// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::gzip::Gzip;
use crate::{
    FilterOutput,
    config::RequestParserConfig,
    filters::{BodyEnd, BodyFilter, BodyResult, Decision},
    parser::{
        BodyEvent, Format,
        body::HttpCapture,
        json_capture::JsonCapture,
        llm::{Fields, sse, stream},
        request::Request,
    },
};

#[derive(Default)]
pub struct DirectionStream {
    group: Option<Group>,
    bytes_seen: usize,
    gzip: Option<Gzip>,
    decoded_bytes: Option<usize>,
}

const RESPONSE_LIMIT: usize = 1 << 20;

#[derive(Clone, Copy)]
pub(crate) enum ParserDirection {
    Request(RequestParserConfig),
    Response,
}

enum Input {
    Request(Request),
    Response(JsonCapture),
    Events(sse::Framer, Box<stream::Stream>),
    Other(HttpCapture),
    Failed(&'static str),
}

impl Input {
    fn llm(
        format: Format,
        protocol: &'static str,
        direction: ParserDirection,
        media: Option<&mime::Mime>,
        encoding: &str,
    ) -> Self {
        if !encoding.is_empty() && !encoding.eq_ignore_ascii_case("identity") {
            return Self::Failed("unsupported_encoding");
        }
        let Some(media) = media else {
            return Self::Failed("unsupported_media_type");
        };
        if media.type_() == mime::APPLICATION
            && (media.subtype() == mime::JSON || media.suffix() == Some(mime::JSON))
        {
            return match direction {
                ParserDirection::Response => Self::Response(JsonCapture::new(RESPONSE_LIMIT)),
                ParserDirection::Request(config) => {
                    Self::Request(Request::new(protocol, config.max_item_size))
                }
            };
        }
        if matches!(direction, ParserDirection::Request(_))
            || media.essence_str() != "text/event-stream"
        {
            return Self::Failed("unsupported_media_type");
        }
        if media
            .get_param("charset")
            .is_some_and(|v| !v.as_str().is_empty() && !v.as_str().eq_ignore_ascii_case("utf-8"))
        {
            return Self::Failed("unsupported_encoding");
        }
        Self::Events(
            sse::Framer::new(format, 64 << 20),
            Box::new(stream::Stream::new(protocol, RESPONSE_LIMIT)),
        )
    }
}

struct Group {
    format: Format,
    input: Input,
    subscribers: Vec<Box<dyn BodyFilter>>,
    event_size: Option<usize>,
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
            Input::Request(reader) => reader.push(bytes, &mut emit),
            Input::Response(reader) => {
                reader.push(bytes, self.format.protocol().unwrap(), true, Fields::ALL);
                Ok(())
            }
            Input::Events(framer, stream) => {
                let result = framer.push(bytes, |frame| {
                    stream.event(frame, &mut |event| emit(BodyEvent::LlmResponse(event)))
                });
                self.event_size = Some(framer.largest_event);
                result
            }
            Input::Other(reader) => {
                reader.push(bytes, size);
                Ok(())
            }
            Input::Failed(_) => Ok(()),
        };
        if let Err(status) = result {
            self.input = Input::Failed(status)
        }
        decision
    }

    fn finish(
        self,
        wire_bytes: usize,
        decoded: Option<usize>,
        complete: bool,
        records: &mut FilterOutput,
    ) -> Decision {
        let source = match self.input {
            _ if !complete => BodyResult::Incomplete,
            Input::Other(reader) => {
                BodyResult::Http(reader.finish(decoded.unwrap_or(wire_bytes), true))
            }
            Input::Request(reader) => BodyResult::Llm(reader.finish().map(|v| (false, v))),
            Input::Response(reader) => BodyResult::Llm(reader.finish(
                self.format.protocol().unwrap(),
                true,
                Fields::ALL,
                RESPONSE_LIMIT,
            )),
            Input::Events(framer, stream) => BodyResult::Sse {
                status: stream.finish(),
                largest_event: framer.largest_event,
            },
            Input::Failed(e) => match self.event_size {
                Some(largest_event) => BodyResult::Sse {
                    status: Err(e),
                    largest_event,
                },
                None => BodyResult::Llm(Err(e)),
            },
        };
        let end = BodyEnd {
            bytes_seen: wire_bytes,
            decoded_bytes: decoded,
            result: source,
        };
        self.subscribers
            .into_iter()
            .fold(Decision::Continue, |decision, filter| {
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
        let media = media.parse::<mime::Mime>().ok();
        let gzip = matches!(direction, ParserDirection::Request(_))
            && encoding.trim().eq_ignore_ascii_case("gzip");
        let encoding = if gzip { "" } else { encoding.trim() };
        let input = match format.protocol() {
            Some(protocol) => Input::llm(format, protocol, direction, media.as_ref(), encoding),
            None => Input::Other(HttpCapture::new(
                format,
                limit,
                hard_limit,
                media.as_ref(),
                encoding,
            )),
        };
        let group = Group {
            format,
            input,
            subscribers: filters,
            event_size: None,
        };
        let mut stream = Self {
            group: Some(group),
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
        self.group.iter().all(|g| match &g.input {
            Input::Failed(_) => true,
            Input::Other(reader) => reader.bytes_only(),
            _ => false,
        })
    }
    pub fn count_bytes(&mut self, size: usize) {
        self.bytes_seen += size
    }
    pub fn missing_buffer(&mut self, size: usize) {
        self.count_bytes(size);
        self.gzip = None;
        self.fail("capture_error");
    }
    fn fail(&mut self, e: &'static str) {
        if let Some(g) = &mut self.group {
            match &mut g.input {
                Input::Failed(_) => {}
                Input::Other(d) => d.fail(e),
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
            self.fail("invalid_encoding")
        }
        self.group.map_or(Decision::Continue, |group| {
            group.finish(self.bytes_seen, self.decoded_bytes, complete, records)
        })
    }
}
