// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::gzip::Gzip;
use crate::{
    AuditRecords,
    filters::audit::capture::Capture,
    parser::{
        Format,
        body::HttpCapture,
        json_capture::JsonCapture,
        llm::{Fields, sse, stream},
        request::{ITEM_LIMIT, Request},
    },
};
use serde_json::Value;

#[derive(Default)]
pub struct DirectionStream {
    groups: Vec<Group>,
    bytes_seen: usize,
    gzip: Option<Gzip>,
    decoded_bytes: Option<usize>,
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
        response: bool,
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
            return if response {
                Self::Response(JsonCapture::new(ITEM_LIMIT))
            } else {
                Self::Request(Request::new(protocol))
            };
        }
        if !response || media.essence_str() != "text/event-stream" {
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
            Box::new(stream::Stream::new(protocol, ITEM_LIMIT)),
        )
    }
}

struct Group {
    format: Format,
    input: Input,
    subscribers: Vec<Capture>,
    event_size: Option<usize>,
}

impl Group {
    fn push(&mut self, bytes: &[u8], size: usize) {
        let result = match &mut self.input {
            Input::Request(reader) => reader.push(bytes, |event, clipped| {
                for audit in &mut self.subscribers {
                    audit.observe(&event, clipped, size);
                }
            }),
            Input::Response(reader) => {
                reader.push(bytes, self.format.protocol().unwrap(), true, Fields::ALL);
                Ok(())
            }
            Input::Events(framer, stream) => {
                let mut result = Ok(());
                let framed = framer.push(bytes, |event| {
                    if result.is_ok() {
                        result = stream.event(event)
                    }
                });
                self.event_size = Some(framer.largest_event);
                result.and(framed)
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
    }

    fn finish(
        self,
        wire_bytes: usize,
        decoded: Option<usize>,
        complete: bool,
        records: &mut AuditRecords,
    ) {
        let size = decoded.unwrap_or(wire_bytes);
        let sources = self.subscribers;
        let is_request = matches!(self.input, Input::Request(_));
        let result: Result<(bool, Value), _> = match self.input {
            Input::Request(reader) => reader.finish().map(|v| (false, v)),
            Input::Response(reader) => reader.finish(
                self.format.protocol().unwrap(),
                true,
                Fields::ALL,
                ITEM_LIMIT,
            ),
            Input::Events(_, stream) => stream.finish(),
            Input::Failed(e) => Err(e),
            Input::Other(reader) => {
                let [audit]: [Capture; 1] = sources.try_into().unwrap_or_else(|_| unreachable!());
                audit.finish(wire_bytes, decoded, reader.finish(size, complete), records);
                return;
            }
        };
        for mut audit in sources {
            let body = if complete {
                audit.project(
                    result.as_ref().map_err(|e| *e),
                    is_request,
                    self.event_size,
                    size,
                )
            } else {
                Err("incomplete")
            };
            audit.finish(wire_bytes, decoded, body, records);
        }
    }
}

impl DirectionStream {
    pub fn new(
        response: bool,
        media: &str,
        encoding: &str,
        audits: impl IntoIterator<Item = Capture>,
    ) -> Self {
        let media = media.parse::<mime::Mime>().ok();
        let gzip = !response && encoding.trim().eq_ignore_ascii_case("gzip");
        let encoding = if gzip { "" } else { encoding.trim() };
        let mut groups = Vec::<Group>::new();
        for audit in audits {
            let format = audit.settings.format;
            if format.protocol().is_some()
                && let Some(g) = groups.iter_mut().find(|g| g.format == format)
            {
                g.subscribers.push(audit);
                continue;
            }
            let input = if let Some(protocol) = format.protocol() {
                Input::llm(format, protocol, response, media.as_ref(), encoding)
            } else {
                Input::Other(audit.http_capture(media.as_ref(), encoding))
            };
            groups.push(Group {
                format,
                input,
                subscribers: vec![audit],
                event_size: None,
            });
        }
        let mut stream = Self {
            groups,
            ..Default::default()
        };
        if gzip && !stream.counts_bytes_only() {
            stream.gzip = Some(Gzip::new());
            stream.decoded_bytes = Some(0)
        }
        stream
    }
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }
    pub fn counts_bytes_only(&self) -> bool {
        self.groups.iter().all(|g| match &g.input {
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
        for g in &mut self.groups {
            match &mut g.input {
                Input::Failed(_) => {}
                Input::Other(d) => d.fail(e),
                _ => g.input = Input::Failed(e),
            }
        }
    }
    pub fn push(&mut self, chunk: &[u8]) {
        self.count_bytes(chunk.len());
        if let Some(mut gzip) = self.gzip.take() {
            let result = gzip.push(chunk, |plain, size| {
                for g in &mut self.groups {
                    g.push(plain, size);
                }
                !self.counts_bytes_only()
            });
            self.decoded_bytes = Some(gzip.decoded_bytes);
            match result {
                Err(e) => self.fail(e),
                Ok(()) if !self.counts_bytes_only() => self.gzip = Some(gzip),
                Ok(()) => {}
            }
        } else if self.decoded_bytes.is_none() {
            for g in &mut self.groups {
                g.push(chunk, self.bytes_seen);
            }
        }
    }
    pub fn finish(mut self, complete: bool, records: &mut AuditRecords) {
        if complete && self.gzip.as_ref().is_some_and(|g| !g.finished()) {
            self.fail("invalid_encoding")
        }
        for group in self.groups {
            group.finish(self.bytes_seen, self.decoded_bytes, complete, records)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::audit::{Direction, capture::AuditContext};
    use serde_json::json;

    #[test]
    fn two_audits_share_one_request_parser_and_match_their_standalone_logs() {
        // Keep the tool definition larger than the other audit's whole log.
        let body = json!({
            "messages":[{"content":"x".repeat(48<<10),"role":"user"},
                        {"content":"latest question","role":"user"}],
            "tools":[{"type":"function","function":{"name":"get_weather",
                "parameters":{"description":"d".repeat(3000)}}}]
        })
        .to_string();
        let question = json!({"fields":{"question":true},"maxSize":2048});
        let tools = json!({"fields":{"tools":true},"maxSize":8192});
        let run = |configs: &[&Value]| {
            let audits = configs.iter().enumerate().map(|(index, config)| {
                let mut dir: Direction = serde_json::from_value((*config).clone()).unwrap();
                dir.format = Format::OpenaiChatCompletions;
                Capture::start(
                    "request",
                    "/v1/chat/completions",
                    "req",
                    dir,
                    AuditContext {
                        chain: "chat",
                        filter_index: index,
                        attributes: &Default::default(),
                    },
                )
            });
            let mut stream = DirectionStream::new(false, "application/json", "", audits);
            assert_eq!(stream.groups.len(), 1);
            assert!(matches!(stream.groups[0].input, Input::Request(_)));
            assert_eq!(stream.groups[0].subscribers.len(), configs.len());
            for chunk in body.as_bytes().chunks(13) {
                stream.push(chunk);
            }
            let mut records = AuditRecords::default();
            stream.finish(true, &mut records);
            records
                .0
                .into_iter()
                .map(|(_, line)| line)
                .collect::<Vec<_>>()
        };
        let a = run(&[&question]).pop().unwrap();
        let b = run(&[&tools]).pop().unwrap();
        assert_eq!(run(&[&question, &tools]), [&a, &b].map(Vec::clone));
        assert_eq!(run(&[&tools, &question]), [&b, &a].map(Vec::clone));
        let disabled_fields = json!({"fields":{},"maxSize":1024});
        assert_eq!(run(&[&disabled_fields, &tools])[1], b);
        assert!(a.len() < 2048 && (2048..8192).contains(&b.len()));
        let a: Value = serde_json::from_slice(&a).unwrap();
        let b: Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(a["llm.question"], "latest question");
        assert!(a.get("gen_ai.tool.definitions").is_none());
        assert!(b.get("llm.question").is_none());
        assert_eq!(b["captureStatus"], "complete");
        assert_eq!(
            b["gen_ai.tool.definitions"][0]["parameters"]["description"]
                .as_str()
                .unwrap()
                .len(),
            3000
        );
    }
}
