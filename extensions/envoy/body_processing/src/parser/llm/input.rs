// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{
    CaptureLoss, Fields, ItemEvent, LlmView, Protocol, json_capture::JsonCapture, request::Request,
    sse, stream,
};
use crate::parser::{BodyError, ParserDirection};

const RESPONSE_LIMIT: usize = 1 << 20;

/// Borrowed for one callback. Model offsets refer to decoded request body bytes.
pub(crate) enum Event<'a> {
    RequestItem {
        item: &'a ItemEvent,
        clipped: bool,
    },
    Response(stream::Event<'a>),
    // Audit reads the validated final model. The wire events retain its byte range.
    #[allow(dead_code)]
    ModelStart(usize),
    #[allow(dead_code)]
    ModelData(&'a [u8]),
    #[allow(dead_code)]
    ModelEnd {
        range: std::ops::Range<usize>,
        value: Option<&'a str>,
    },
}

pub(crate) enum Outcome {
    Document {
        loss: CaptureLoss,
        view: LlmView,
    },
    Sse,
    InterruptedSse {
        reason: BodyError,
        partial: Option<(LlmView, bool)>,
    },
}

pub(crate) enum Parser {
    Request(Request),
    Response {
        protocol: Protocol,
        json: JsonCapture,
    },
    Sse(sse::Framer, Box<stream::Stream>),
}

impl Parser {
    pub(crate) fn new(
        protocol: Protocol,
        direction: ParserDirection,
        media: Option<&mime::Mime>,
        encoding: &str,
    ) -> Result<Self, BodyError> {
        if !encoding.is_empty() && !encoding.eq_ignore_ascii_case("identity") {
            return Err(BodyError::UnsupportedEncoding);
        }
        let media = media.ok_or(BodyError::UnsupportedMediaType)?;
        if media.type_() == mime::APPLICATION
            && (media.subtype() == mime::JSON || media.suffix() == Some(mime::JSON))
        {
            return Ok(match direction {
                ParserDirection::Request(config) => {
                    Self::Request(Request::new(protocol.as_str(), config.max_item_size))
                }
                ParserDirection::Response => Self::Response {
                    protocol,
                    json: JsonCapture::new(RESPONSE_LIMIT),
                },
            });
        }
        if matches!(direction, ParserDirection::Request(_))
            || media.essence_str() != "text/event-stream"
        {
            return Err(BodyError::UnsupportedMediaType);
        }
        if media
            .get_param("charset")
            .is_some_and(|v| !v.as_str().is_empty() && !v.as_str().eq_ignore_ascii_case("utf-8"))
        {
            return Err(BodyError::UnsupportedEncoding);
        }
        Ok(Self::Sse(
            sse::Framer::new(protocol),
            Box::new(stream::Stream::new(protocol.as_str(), RESPONSE_LIMIT)),
        ))
    }

    pub(crate) fn push(
        &mut self,
        bytes: &[u8],
        emit: &mut impl FnMut(Event<'_>),
    ) -> Result<(), BodyError> {
        match self {
            Self::Request(reader) => reader.push(bytes, emit),
            Self::Response { protocol, json } => {
                json.push(bytes, protocol.as_str(), true, Fields::ALL);
                Ok(())
            }
            Self::Sse(framer, stream) => framer.push(bytes, |frame| {
                stream.event(frame, &mut |event| emit(Event::Response(event)))
            }),
        }
    }

    pub(crate) fn finish(self, complete: bool) -> Result<Outcome, BodyError> {
        match self {
            Self::Sse(_, stream) => Ok(match (complete, stream.into_partial()) {
                (true, None) => Outcome::Sse,
                (_, partial) => Outcome::InterruptedSse {
                    reason: if complete {
                        BodyError::IncompleteStream
                    } else {
                        BodyError::Incomplete
                    },
                    partial,
                },
            }),
            _ if !complete => Err(BodyError::Incomplete),
            Self::Request(reader) => Ok(Outcome::Document {
                loss: CaptureLoss::default(),
                view: reader.finish()?,
            }),
            Self::Response { protocol, json } => {
                let (loss, view) =
                    json.finish(protocol.as_str(), true, Fields::ALL, RESPONSE_LIMIT)?;
                Ok(Outcome::Document { loss, view })
            }
        }
    }
}
