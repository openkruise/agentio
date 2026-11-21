// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{Direction, capture::bound_content, projection::response_view};
use crate::parser::{
    body::{Content, ParsedBody},
    encoded_len,
    llm::{
        answer_parts,
        stream::{AnswerStatus, Event},
    },
};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Projection {
    answer: Answer,
    usage: Option<Value>,
    completed: Option<ParsedBody>,
}

#[derive(Default)]
struct Answer {
    parts: BTreeMap<u32, String>,
    encoded_bytes: usize,
    retained_bytes: usize,
    clipped_from: Option<u32>,
}

impl Answer {
    fn append(&mut self, index: u32, text: &str, content_limit: usize, line_limit: usize) {
        if text.is_empty() || self.encoded_bytes + 2 > content_limit {
            return;
        }
        // Adjacent deltas make one JSON string, with a single pair of quotes.
        self.encoded_bytes += encoded_len(text) - 2;
        if self.encoded_bytes + 2 > content_limit {
            self.parts.clear();
            return;
        }
        // Preserve the prefix in output order even if parts arrive interleaved.
        if self.clipped_from.is_some_and(|part| index >= part) {
            return;
        }
        let n = text.floor_char_boundary(text.len().min(line_limit));
        self.parts.entry(index).or_default().push_str(&text[..n]);
        self.retained_bytes += n;
        if n < text.len() {
            self.clipped_from = Some(index);
        }
        while self.retained_bytes > line_limit {
            let mut last = self.parts.last_entry().unwrap();
            let index = *last.key();
            self.clipped_from = Some(self.clipped_from.map_or(index, |old| old.min(index)));
            let s = last.get_mut();
            let keep =
                s.floor_char_boundary(s.len().saturating_sub(self.retained_bytes - line_limit));
            self.retained_bytes -= s.len() - keep;
            if keep == 0 {
                last.remove();
            } else {
                s.truncate(keep);
            }
        }
    }
}

impl Projection {
    pub(super) fn observe(&mut self, event: &Event<'_>, settings: Direction, room: usize) {
        let fields = settings.fields;
        let limit = settings
            .max_content_bytes
            .or(settings.max_capture_bytes)
            .unwrap_or(room);
        match *event {
            Event::TextDelta {
                output: 0,
                part: Some(part),
                text,
                provisional: false,
            } if fields.answer => {
                self.answer
                    .append(part, text, limit, settings.max_log_bytes);
            }
            Event::OutputItem { index, message } if fields.answer => {
                // Responses confirms a complete item, including roles and refusals. Its
                // provisional text deltas were already broadcast to all live filters.
                for text in answer_parts(message) {
                    self.answer
                        .append(index, text, limit, settings.max_log_bytes);
                }
            }
            Event::ReplaceOutput => self.answer = Answer::default(),
            Event::Usage(value) if fields.usage => {
                self.usage = (!value.is_null()).then(|| value.clone())
            }
            Event::Completed {
                view,
                truncated,
                answer,
            } => {
                let mut value = response_view(view, fields, settings.max_log_bytes);
                if let Some(usage) = self.usage.take() {
                    value["usage"] = usage;
                }
                let saved = std::mem::take(&mut self.answer);
                let answer = match (fields.answer, answer) {
                    (true, AnswerStatus::Visible) => Some(saved),
                    (true, AnswerStatus::Empty) => Some(Answer::default()),
                    _ => None,
                };
                let answer_size = answer.as_ref().map_or(0, |a| a.encoded_bytes + 2);
                let content_clipped = bound_content(&mut value, limit.saturating_sub(answer_size))
                    || answer_size > limit;
                let mut clipped = content_clipped || (truncated && fields.output_messages);
                if let Some(answer) = answer
                    && !content_clipped
                {
                    clipped |= answer.clipped_from.is_some();
                    value["answer"] = answer.parts.into_values().collect::<String>().into();
                }
                if clipped {
                    value["truncated"] = true.into();
                }
                self.completed = Some(ParsedBody {
                    truncated: clipped,
                    content: Content::Llm(value),
                });
            }
            _ => {}
        }
    }

    pub(super) fn finish(self) -> ParsedBody {
        self.completed
            .expect("validated SSE stream emitted Completed")
    }
}
