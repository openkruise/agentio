// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::gzip::Gzip;
use crate::{
    FilterOutput,
    filters::{BodyEnd, BodyFilter, BodyInterest, BodyResult, Decision},
    parser::{BodyError, BodyEvent, Format, ParserDirection, http::HttpCapture, llm},
};

#[derive(Default)]
pub struct DirectionStream {
    group: Option<Group>,
    bytes_seen: usize,
    gzip: Option<Gzip>,
    count_inflated: bool,
    decoded_bytes: Option<usize>,
}

enum Input {
    Count,
    Llm(llm::Parser),
    Http(HttpCapture),
    Failed(BodyError),
}

struct Group {
    input: Input,
    subscribers: Vec<Box<dyn BodyFilter>>,
}

impl Group {
    fn push(&mut self, bytes: &[u8], size: usize) -> Decision {
        let mut decision = Decision::Continue;
        let mut emit = |event: BodyEvent<'_>| {
            for filter in &mut self.subscribers {
                decision = decision.merge(filter.on_event(&event, size));
            }
        };
        let result = match &mut self.input {
            Input::Llm(parser) => parser.push(bytes, &mut |event| emit(BodyEvent::Llm(event))),
            Input::Http(reader) => {
                reader.push(bytes, size);
                Ok(())
            }
            Input::Count | Input::Failed(_) => Ok(()),
        };
        if let Err(status) = result {
            self.input = Input::Failed(status)
        }
        decision
    }

    fn finish(
        mut self,
        wire_bytes: usize,
        decoded: Option<usize>,
        complete: bool,
        records: &mut FilterOutput,
    ) -> Decision {
        let mut decision = Decision::Continue;
        let result = match self.input {
            Input::Failed(error) => Err(error),
            Input::Llm(parser) => parser
                .finish(complete, &mut |event| {
                    let event = BodyEvent::Llm(event);
                    for filter in &mut self.subscribers {
                        decision = decision.merge(filter.on_event(&event, wire_bytes));
                    }
                })
                .map(BodyResult::Llm),
            _ if !complete => Err(BodyError::Incomplete),
            Input::Count => Ok(BodyResult::Counts),
            Input::Http(reader) => reader
                .finish(decoded.unwrap_or(wire_bytes), true)
                .map(BodyResult::Http),
        };
        let end = BodyEnd {
            bytes_seen: wire_bytes,
            decoded_bytes: decoded,
            result: result.unwrap_or_else(BodyResult::Failed),
        };
        self.subscribers
            .into_iter()
            .fold(decision, |decision, filter| {
                decision.merge(filter.on_end(&end, records))
            })
    }
}

impl DirectionStream {
    pub fn new(
        direction: ParserDirection,
        format: Format,
        media: &str,
        encoding: &str,
        filters: Vec<Box<dyn BodyFilter>>,
    ) -> Self {
        Self::with_limits(direction, format, media, encoding, filters, 0, None)
    }
    pub(crate) fn with_limits(
        direction: ParserDirection,
        format: Format,
        media: &str,
        encoding: &str,
        filters: Vec<Box<dyn BodyFilter>>,
        limit: usize,
        hard_limit: Option<usize>,
    ) -> Self {
        if filters.is_empty() {
            return Self::default();
        }
        let mut interest = BodyInterest::default();
        for filter in &filters {
            let needs = filter.interest();
            interest.decoded_bytes |= needs.decoded_bytes;
            interest.events |= needs.events;
        }
        let gzip = matches!(direction, ParserDirection::Request(_))
            && encoding.trim().eq_ignore_ascii_case("gzip");
        let encoding = if gzip { "" } else { encoding.trim() };
        let input = if interest.events {
            let media = media.parse::<mime::Mime>().ok();
            match format {
                Format::Llm(protocol) => {
                    llm::Parser::new(protocol, direction, media.as_ref(), encoding)
                        .map_or_else(Input::Failed, Input::Llm)
                }
                _ => Input::Http(HttpCapture::new(
                    format,
                    limit,
                    hard_limit,
                    media.as_ref(),
                    encoding,
                )),
            }
        } else {
            Input::Count
        };
        let group = Group {
            input,
            subscribers: filters,
        };
        let mut stream = Self {
            group: Some(group),
            count_inflated: gzip && interest.decoded_bytes,
            ..Default::default()
        };
        if gzip && !stream.counts_bytes_only() {
            stream.gzip = Some(Gzip::new());
            stream.decoded_bytes = Some(0)
        }
        stream
    }
    pub fn is_empty(&self) -> bool {
        self.group.is_none()
    }
    pub fn counts_bytes_only(&self) -> bool {
        !self.count_inflated
            && self.group.iter().all(|g| match &g.input {
                Input::Count | Input::Failed(_) => true,
                Input::Http(reader) => reader.bytes_only(),
                _ => false,
            })
    }
    pub fn count_bytes(&mut self, size: usize) {
        self.bytes_seen += size
    }
    pub fn missing_buffer(&mut self, size: usize) {
        self.count_bytes(size);
        self.gzip = None;
        self.fail(BodyError::CaptureError);
    }
    fn fail(&mut self, e: BodyError) {
        self.count_inflated = false;
        if let Some(g) = &mut self.group {
            match &mut g.input {
                Input::Failed(_) => {}
                Input::Http(d) => d.fail(e),
                _ => g.input = Input::Failed(e),
            }
        }
    }
    pub fn push(&mut self, chunk: &[u8]) -> Decision {
        let mut decision = Decision::Continue;
        self.count_bytes(chunk.len());
        if let Some(mut gzip) = self.gzip.take() {
            let result = gzip.push(chunk, |plain, size| {
                if let Some(g) = &mut self.group {
                    decision = decision.merge(g.push(plain, size));
                }
                !self.counts_bytes_only()
            });
            self.decoded_bytes = Some(gzip.decoded_bytes);
            match result {
                Err(e) => self.fail(e),
                Ok(()) if !self.counts_bytes_only() => self.gzip = Some(gzip),
                Ok(()) => {}
            }
        } else if self.decoded_bytes.is_none()
            && let Some(g) = &mut self.group
        {
            decision = g.push(chunk, self.bytes_seen);
        }
        decision
    }
    pub fn finish(mut self, complete: bool, records: &mut FilterOutput) -> Decision {
        if complete && self.gzip.as_ref().is_some_and(|g| !g.finished()) {
            self.fail(BodyError::InvalidEncoding)
        }
        self.group.map_or(Decision::Continue, |group| {
            group.finish(self.bytes_seen, self.decoded_bytes, complete, records)
        })
    }
}
