// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::parser::BodyError;
use flate2::{Decompress, FlushDecompress, Status};

// Bound work on the audit copy independently of a filter's retention budget.
pub(super) const MAX_DECODED_BYTES: usize = 64 << 20;

pub(super) struct Gzip {
    inflate: Decompress,
    member_finished: bool,
    pub(super) decoded_bytes: usize,
}

impl Gzip {
    pub(super) fn new() -> Self {
        Self {
            inflate: Decompress::new_gzip(15),
            member_finished: false,
            decoded_bytes: 0,
        }
    }

    // StreamEnd includes verification of the gzip member's CRC and length.
    // RFC 1952 permits more members in the same request, even across callbacks.
    pub(super) fn push(
        &mut self,
        mut input: &[u8],
        mut emit: impl FnMut(&[u8], usize) -> bool,
    ) -> Result<(), BodyError> {
        let mut output = [0u8; 16 * 1024];
        if input.is_empty() {
            return Ok(());
        }
        loop {
            if self.member_finished {
                self.inflate = Decompress::new_gzip(15);
                self.member_finished = false;
            }
            let remaining = MAX_DECODED_BYTES - self.decoded_bytes;
            let capacity = output.len().min(remaining + 1);
            let before_in = self.inflate.total_in();
            let before_out = self.inflate.total_out();
            let status = self
                .inflate
                .decompress(input, &mut output[..capacity], FlushDecompress::None)
                .map_err(|_| BodyError::InvalidEncoding)?;
            let consumed = (self.inflate.total_in() - before_in) as usize;
            let produced = (self.inflate.total_out() - before_out) as usize;
            let accepted = produced.min(remaining);
            self.decoded_bytes += accepted;
            if accepted != 0 && !emit(&output[..accepted], self.decoded_bytes) {
                return Ok(());
            }
            if produced > remaining {
                return Err(BodyError::TooLarge);
            }
            self.member_finished = status == Status::StreamEnd;
            input = &input[consumed..];
            // A full output slice can leave more plaintext inside the inflater.
            // Drain it before waiting for the next Envoy callback.
            if input.is_empty() && (self.member_finished || produced < capacity) {
                return Ok(());
            }
            if consumed == 0 && produced == 0 && !self.member_finished {
                return Err(BodyError::InvalidEncoding);
            }
        }
    }

    pub(super) fn finished(&self) -> bool {
        self.member_finished
    }
}
