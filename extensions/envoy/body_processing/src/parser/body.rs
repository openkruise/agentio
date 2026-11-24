// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{
    BodyError, Format,
    json_capture::JsonCapture,
    llm::{Fields, LlmView},
    multipart::Multipart,
};
use serde_json::Value;

#[derive(Clone)]
pub(crate) enum Content {
    Empty,
    Http(Value),
    Llm(LlmView),
}
#[derive(Clone)]
pub(crate) struct ParsedBody {
    pub truncated: bool,
    pub content: Content,
}

pub(crate) type Decoded = Result<ParsedBody, BodyError>;

enum Body {
    Metadata,
    Json(JsonCapture),
    Multipart(Multipart),
    Text(Vec<u8>),
    Unavailable(BodyError),
}

pub(crate) struct HttpCapture {
    body: Body,
    format: Format,
    limit: usize,
    hard_limit: Option<usize>,
}

impl HttpCapture {
    pub(crate) fn new(
        format: Format,
        limit: usize,
        hard_limit: Option<usize>,
        media: Option<&mime::Mime>,
        encoding: &str,
    ) -> Self {
        let http = format == Format::Http;
        let encoding = encoding.trim();
        let body = if format == Format::Metadata {
            Body::Metadata
        } else if format == Format::UnknownProtocol {
            Body::Unavailable(BodyError::UnknownProtocol)
        } else if !encoding.is_empty() && !encoding.eq_ignore_ascii_case("identity") {
            Body::Unavailable(BodyError::UnsupportedEncoding)
        } else if let Some(m) = media {
            let essence = m.essence_str();
            if format != Format::Text
                && m.type_() == mime::APPLICATION
                && (essence == "application/json" || m.suffix() == Some(mime::JSON))
            {
                Body::Json(JsonCapture::new(limit))
            } else if http && essence == "multipart/form-data" {
                m.get_param("boundary")
                    .and_then(|b| Multipart::new(b.as_str(), limit))
                    .map_or(
                        Body::Unavailable(BodyError::InvalidMultipart),
                        Body::Multipart,
                    )
            } else if (http && m.type_() == mime::TEXT)
                || (format == Format::Text && essence == "text/plain")
            {
                if m.get_param("charset").is_some_and(|v| {
                    !v.as_str().is_empty() && !v.as_str().eq_ignore_ascii_case("utf-8")
                }) {
                    Body::Unavailable(BodyError::UnsupportedEncoding)
                } else {
                    Body::Text(vec![])
                }
            } else {
                Body::Unavailable(BodyError::UnsupportedMediaType)
            }
        } else {
            Body::Unavailable(BodyError::UnsupportedMediaType)
        };
        Self {
            body,
            format,
            limit,
            hard_limit,
        }
    }

    pub(crate) fn bytes_only(&self) -> bool {
        matches!(self.body, Body::Unavailable(_) | Body::Metadata)
    }
    pub(crate) fn fail(&mut self, error: BodyError) {
        self.body = Body::Unavailable(error);
    }

    pub(crate) fn push(&mut self, chunk: &[u8], bytes_seen: usize) {
        if matches!(self.body, Body::Json(_) | Body::Text(_))
            && self.hard_limit.is_some_and(|limit| bytes_seen > limit)
        {
            self.fail(BodyError::TooLarge);
        }
        match &mut self.body {
            Body::Text(buf) => {
                let n = chunk.len().min(self.limit.saturating_sub(buf.len()));
                buf.extend_from_slice(&chunk[..n]);
            }
            Body::Json(c) => c.push(chunk, "json", false, Fields::default()),
            Body::Multipart(c) => {
                if let Err(e) = c.push(chunk) {
                    self.body = Body::Unavailable(e);
                }
            }
            Body::Metadata | Body::Unavailable(_) => {}
        }
    }

    pub(crate) fn finish(self, bytes_seen: usize, complete: bool) -> Decoded {
        let has_body = matches!(
            self.body,
            Body::Json(..) | Body::Multipart(_) | Body::Text(_)
        );
        let (clipped, value) = match self.body {
            _ if !complete => Err(BodyError::Incomplete),
            Body::Unavailable(BodyError::UnsupportedMediaType)
                if bytes_seen == 0 && self.format == Format::Http =>
            {
                Ok((false, Value::Null))
            }
            Body::Metadata => Ok((false, Value::Null)),
            Body::Unavailable(e) => Err(e),
            Body::Json(c) => c
                .finish_fragment()
                .map(|(loss, value)| (loss.document, value)),
            Body::Multipart(c) => c.finish(),
            Body::Text(buf) => {
                let clipped = bytes_seen > buf.len();
                match std::str::from_utf8(&buf) {
                    Ok(text) => Ok((clipped, Value::from(text))),
                    Err(e) if clipped && e.error_len().is_none() => Ok((
                        true,
                        Value::from(std::str::from_utf8(&buf[..e.valid_up_to()]).unwrap()),
                    )),
                    Err(_) => Err(BodyError::InvalidText),
                }
            }
        }?;
        let content = if has_body {
            Content::Http(value)
        } else {
            Content::Empty
        };
        Ok(ParsedBody {
            truncated: clipped,
            content,
        })
    }
}
