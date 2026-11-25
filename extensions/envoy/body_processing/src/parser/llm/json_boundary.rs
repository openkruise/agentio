// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::response::Result;
use crate::parser::{BodyError, json::string_end};

#[derive(Default)]
pub(super) struct ValueBoundary {
    depth: usize,
    quoted: bool,
    escaped: bool,
    started: bool,
}

impl ValueBoundary {
    // Return the number of bytes in this fragment, leaving its separator for
    // the object/array grammar. The actual JSON value is decoded once.
    pub(super) fn feed(&mut self, input: &[u8]) -> Result<(usize, bool)> {
        let mut i = 0;
        let mut done = false;
        while i < input.len() {
            if self.quoted {
                let Some(end) = string_end(&input[i..], &mut self.escaped) else {
                    i = input.len();
                    break;
                };
                i += end + 1;
                self.quoted = false;
                if self.depth == 0 {
                    done = true;
                    break;
                }
            } else {
                let ch = input[i];
                if self.started
                    && self.depth == 0
                    && (ch.is_ascii_whitespace() || matches!(ch, b',' | b']' | b'}'))
                {
                    done = true;
                    break;
                }
                self.started = true;
                match ch {
                    b'"' => self.quoted = true,
                    b'{' | b'[' => {
                        self.depth += 1;
                        if self.depth > 128 {
                            return Err(BodyError::InvalidJson);
                        }
                    }
                    b'}' | b']' => {
                        self.depth = self.depth.checked_sub(1).ok_or(BodyError::InvalidJson)?;
                        if self.depth == 0 {
                            i += 1;
                            done = true;
                            break;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
        }
        Ok((i, done))
    }
}
