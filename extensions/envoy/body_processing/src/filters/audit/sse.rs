// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::projection::{TextPreview, response_text, response_view};
use crate::parser::{
    body::{Content, ParsedBody},
    llm::{
        Fields, LlmView, answer_parts,
        stream::{AnswerStatus, Event, Output},
    },
};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Projection {
    answer: Answer,
    // Unsealed Responses deltas are useful on disconnect. Authoritative items replace them.
    pending: Option<Box<Answer>>,
    usage: Option<Value>,
}

#[derive(Default)]
struct Answer {
    parts: BTreeMap<(Output, u32), String>,
    retained_bytes: usize,
    // A Responses snapshot can repair one output while others still have gaps.
    clipped_parts: BTreeMap<Output, u32>,
}

impl Answer {
    fn clipped_from(&self) -> Option<(Output, u32)> {
        self.clipped_parts.first_key_value().map(|(&o, &p)| (o, p))
    }

    fn mark_clipped(&mut self, (output, part): (Output, u32)) {
        let first = self.clipped_parts.entry(output).or_insert(part);
        *first = (*first).min(part);
    }

    fn remove_output(&mut self, output: Output) {
        while let Some((&key, _)) = self.parts.range((output, 0)..=(output, u32::MAX)).next() {
            self.retained_bytes -= self.parts.remove(&key).unwrap().len();
        }
        self.clipped_parts.remove(&output);
    }

    fn append(&mut self, index: (Output, u32), text: &str, limit: usize) {
        if text.is_empty() {
            return;
        }
        if let Some(cut) = self.clipped_from()
            && index >= cut
        {
            if index.0 > cut.0 {
                self.mark_clipped(index);
            }
            return;
        }

        // Earlier parts precede later parts in the final answer, even if their deltas
        // arrive out of order. Make room by evicting the end of the latest part first.
        while text.len() > limit - self.retained_bytes {
            let Some(mut last) = self.parts.last_entry() else {
                break;
            };
            if *last.key() <= index {
                break;
            }
            let clipped = *last.key();
            let excess = text.len() - (limit - self.retained_bytes);
            let tail = last.get_mut();
            let keep = tail.floor_char_boundary(tail.len().saturating_sub(excess));
            self.retained_bytes -= tail.len() - keep;
            if keep == 0 {
                last.remove();
            } else {
                tail.truncate(keep);
            }
            self.mark_clipped(clipped);
        }
        let keep = text.floor_char_boundary(text.len().min(limit - self.retained_bytes));
        if keep < text.len() {
            self.mark_clipped(index);
        }
        if keep > 0 {
            self.parts.entry(index).or_default().push_str(&text[..keep]);
            self.retained_bytes += keep;
        }
    }
}

impl Projection {
    pub(super) fn interrupted(
        &mut self,
        view: &LlmView,
        visible: bool,
        fields: Fields,
        limit: usize,
    ) -> ParsedBody {
        let mut result = response_view(view, fields, limit);
        if let Some(usage) = self.usage.take() {
            result.document["usage"] = usage;
        }
        let mut answer = std::mem::take(&mut self.answer);
        if let Some(pending) = self.pending.take() {
            let cut = pending.clipped_from();
            for (index, text) in pending.parts {
                answer.append(index, &text, limit);
            }
            // A later sealed item may fit in the unused bytes at a UTF-8 boundary.
            // Only the prefix before the first gap is part of the observed answer.
            if let Some(cut) = cut {
                answer.parts.retain(|index, _| *index <= cut);
            }
        }
        if !answer.parts.is_empty() {
            if fields.retained_text {
                let mut text = TextPreview::default();
                for part in answer.parts.values() {
                    text.push(part, limit);
                }
                text.publish(&mut result.document);
            }
            if fields.answer && visible {
                let mut parts = answer
                    .parts
                    .into_iter()
                    .filter(|((output, _), _)| output.answer_candidate)
                    .peekable();
                if parts.peek().is_some() {
                    result.document["answer"] =
                        parts.map(|(_, text)| text).collect::<String>().into();
                }
            }
        }
        ParsedBody {
            truncated: false,
            content: Content::Llm(result),
        }
    }

    pub(super) fn observe(
        &mut self,
        event: &Event<'_>,
        fields: Fields,
        limit: usize,
    ) -> Option<ParsedBody> {
        match *event {
            Event::TextDelta {
                output,
                part: Some(part),
                text,
                provisional: false,
            } if (fields.answer && output.answer_candidate) || fields.retained_text => {
                self.answer.append((output, part), text, limit);
            }
            Event::TextDelta {
                output,
                part,
                text,
                provisional: true,
            } if (fields.answer && output.answer_candidate) || fields.retained_text => {
                self.pending.get_or_insert_with(Default::default).append(
                    (output, part.unwrap_or(0)),
                    text,
                    limit,
                );
            }
            Event::OutputItem { output, message }
                if (fields.answer && output.answer_candidate) || fields.retained_text =>
            {
                if let Some(pending) = self.pending.as_mut() {
                    pending.remove_output(output);
                }
                for (part, text) in answer_parts(message).enumerate() {
                    self.answer.append((output, part as u32), text, limit);
                }
            }
            Event::ReplaceOutput => {
                self.answer = Answer::default();
                self.pending = None;
            }
            Event::Usage(value) if fields.usage => {
                self.usage = (!value.is_null()).then(|| value.clone())
            }
            Event::Completed {
                view,
                truncated,
                answer,
            } => {
                self.pending = None;
                let mut result = response_view(view, fields, limit);
                if let Some(usage) = self.usage.take() {
                    result.document["usage"] = usage;
                }
                let saved = std::mem::take(&mut self.answer);
                let mut clipped = truncated && fields.output_messages;
                if fields.retained_text {
                    let text = if truncated && matches!(answer, AnswerStatus::Visible) {
                        let mut text = TextPreview::default();
                        for part in saved.parts.values() {
                            text.push(part, limit);
                        }
                        text.clipped |= saved.clipped_from().is_some();
                        text
                    } else {
                        response_text(&view.document, limit)
                    };
                    clipped |= text.publish(&mut result.document);
                }
                let answer = match (fields.answer, answer) {
                    (true, AnswerStatus::Visible) => Some(saved),
                    (true, AnswerStatus::Empty) => Some(Answer::default()),
                    _ => None,
                };
                if let Some(answer) = answer {
                    clipped |= answer
                        .clipped_from()
                        .is_some_and(|(output, _)| output.answer_candidate);
                    result.document["answer"] = answer
                        .parts
                        .into_iter()
                        .filter(|((output, _), _)| output.answer_candidate)
                        .map(|(_, text)| text)
                        .collect::<String>()
                        .into();
                }
                if clipped {
                    result.document["truncated"] = true.into();
                }
                return Some(ParsedBody {
                    truncated: clipped,
                    content: Content::Llm(result),
                });
            }
            _ => {}
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{Answer, Output};
    use crate::parser::llm::RESPONSES;

    #[test]
    fn earlier_parts_can_displace_a_clipped_later_part() {
        let mut answer = Answer::default();
        let output = Output::new(RESPONSES, 0);
        for (index, text) in [(2, "later"), (2, " text"), (0, "水水"), (1, "好"), (0, "!")] {
            answer.append((output, index), text, 8);
            assert!(answer.retained_bytes <= 8);
        }
        assert_eq!(answer.clipped_from(), Some((output, 1)));
        assert_eq!(answer.parts.into_values().collect::<String>(), "水水!");
    }

    #[test]
    fn interrupted_responses_keep_a_prefix_across_open_and_sealed_items() {
        use super::{Content, Fields, Projection};
        use serde_json::json;
        let view = json!({"format": RESPONSES}).into();
        let first = Output::new(RESPONSES, 0);
        let second = Output::new(RESPONSES, 1);
        let fields = Fields {
            answer: true,
            ..Fields::default()
        };
        for seal_first in [false, true] {
            let mut projection = Projection::default();
            let pending = projection.pending.get_or_insert_with(Default::default);
            pending.append((first, 0), "ab水", 4);
            if seal_first {
                pending.append((second, 0), "x", 4);
                pending.remove_output(first);
                projection.answer.append((first, 0), "A", 4);
                pending.append((second, 0), "y", 4);
            } else {
                projection.answer.append((second, 0), "!", 4);
            }
            let Content::Llm(view) = projection.interrupted(&view, true, fields, 4).content else {
                unreachable!()
            };
            assert_eq!(view.document["answer"], if seal_first { "A" } else { "ab" });
        }
    }
}
