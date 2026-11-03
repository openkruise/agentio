// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

// ABI subset from Envoy v1.40.0 source/extensions/dynamic_modules/abi/abi.h.
// Keep the runtime test on the pinned Envoy image when upgrading either side.
use std::ffi::{c_char, c_void};

mod legacy;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Buffer {
    ptr: *const u8,
    len: usize,
}
impl Buffer {
    fn from(s: &str) -> Self {
        Self {
            ptr: s.as_ptr(),
            len: s.len(),
        }
    }
}

#[no_mangle]
pub extern "C" fn envoy_dynamic_module_on_program_init() -> *const c_char {
    c"v0.2.0".as_ptr()
}

#[repr(C)]
struct Timing {
    start_time_unix_ns: i64,
    downstream_connection_begin_ns: i64,
    downstream_handshake_start_ns: i64,
    downstream_handshake_complete_ns: i64,
    last_downstream_header_rx_byte_received_ns: i64,
    last_downstream_rx_byte_received_ns: i64,
    upstream_connect_start_ns: i64,
    upstream_connect_complete_ns: i64,
    upstream_handshake_complete_ns: i64,
    first_upstream_tx_byte_sent_ns: i64,
    last_upstream_tx_byte_sent_ns: i64,
    first_upstream_rx_byte_received_ns: i64,
    first_upstream_rx_body_byte_received_ns: i64,
    last_upstream_rx_byte_received_ns: i64,
    first_downstream_tx_byte_sent_ns: i64,
    last_downstream_tx_byte_sent_ns: i64,
    last_downstream_ack_received_ns: i64,
    request_complete_duration_ns: i64,
    downstream_connection_end_ns: i64,
    has_start_time: bool,
    has_downstream_connection_begin: bool,
    has_downstream_handshake_start: bool,
    has_downstream_handshake_complete: bool,
    has_last_downstream_header_rx_byte_received: bool,
    has_last_downstream_rx_byte_received: bool,
    has_upstream_connect_start: bool,
    has_upstream_connect_complete: bool,
    has_upstream_handshake_complete: bool,
    has_first_upstream_tx_byte_sent: bool,
    has_last_upstream_tx_byte_sent: bool,
    has_first_upstream_rx_byte_received: bool,
    has_first_upstream_rx_body_byte_received: bool,
    has_last_upstream_rx_byte_received: bool,
    has_first_downstream_tx_byte_sent: bool,
    has_last_downstream_tx_byte_sent: bool,
    has_last_downstream_ack_received: bool,
    has_request_complete: bool,
    has_downstream_connection_end: bool,
}

extern "C" {
    fn envoy_dynamic_module_callback_http_get_timing_info(filter: *mut c_void, result: *mut Timing);
    fn envoy_dynamic_module_callback_http_filter_config_define_counter(
        config: *mut c_void,
        name: Buffer,
        labels: *mut Buffer,
        label_count: usize,
        id: *mut usize,
    ) -> i32;
    fn envoy_dynamic_module_callback_http_filter_config_define_histogram(
        config: *mut c_void,
        name: Buffer,
        labels: *mut Buffer,
        label_count: usize,
        id: *mut usize,
    ) -> i32;
    fn envoy_dynamic_module_callback_http_filter_increment_counter(
        filter: *mut c_void,
        id: usize,
        labels: *mut Buffer,
        label_count: usize,
        value: u64,
    ) -> i32;
    fn envoy_dynamic_module_callback_http_filter_record_histogram_value(
        filter: *mut c_void,
        id: usize,
        labels: *mut Buffer,
        label_count: usize,
        value: u64,
    ) -> i32;
    fn envoy_dynamic_module_callback_http_filter_get_attribute_int(
        filter: *mut c_void,
        attribute: i32,
        result: *mut u64,
    ) -> bool;
}

struct Config {
    requests: Option<usize>,
    duration: Option<usize>,
}

#[no_mangle]
pub unsafe extern "C" fn envoy_dynamic_module_on_http_filter_config_new(
    envoy: *mut c_void,
    _name: Buffer,
    value: Buffer,
) -> *mut c_void {
    let value = if value.len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(value.ptr, value.len)
    };
    let Some((requests, duration)) = selection(value) else {
        return std::ptr::null_mut();
    };
    let mut config = Box::new(Config {
        requests: None,
        duration: None,
    });
    let mut labels = [
        Buffer::from("response_code"),
        Buffer::from("response_flags"),
    ];
    if requests {
        let mut id = 0;
        if envoy_dynamic_module_callback_http_filter_config_define_counter(
            envoy,
            Buffer::from("istio_requests_total"),
            labels.as_mut_ptr(),
            labels.len(),
            &mut id,
        ) != 0
        {
            return std::ptr::null_mut();
        }
        config.requests = Some(id);
    }
    if duration {
        let mut id = 0;
        if envoy_dynamic_module_callback_http_filter_config_define_histogram(
            envoy,
            Buffer::from("istio_request_duration_milliseconds"),
            labels.as_mut_ptr(),
            labels.len(),
            &mut id,
        ) != 0
        {
            return std::ptr::null_mut();
        }
        config.duration = Some(id);
    }
    Box::into_raw(config).cast()
}

#[no_mangle]
pub unsafe extern "C" fn envoy_dynamic_module_on_http_filter_config_destroy(config: *mut c_void) {
    drop(Box::from_raw(config.cast::<Config>()));
}

#[no_mangle]
pub extern "C" fn envoy_dynamic_module_on_http_filter_new(
    config: *mut c_void,
    _: *mut c_void,
) -> *mut c_void {
    // Per-stream data is owned by Envoy; the module only needs the immutable metric IDs.
    config
}

#[no_mangle]
pub extern "C" fn envoy_dynamic_module_on_http_filter_destroy(_: *mut c_void) {}

#[no_mangle]
pub unsafe extern "C" fn envoy_dynamic_module_on_http_filter_stream_complete(
    envoy: *mut c_void,
    config: *mut c_void,
) {
    let config = &*config.cast::<Config>();
    // Attribute IDs from the pinned ABI. A stream reset before headers has no response code.
    let mut code = 0;
    envoy_dynamic_module_callback_http_filter_get_attribute_int(envoy, 15, &mut code);
    let mut code_output = [0; 3];
    let code = response_code(code, &mut code_output);
    let mut flags = 0;
    assert!(envoy_dynamic_module_callback_http_filter_get_attribute_int(
        envoy, 17, &mut flags
    ));
    let mut flag_output = [0; 128];
    let flags = response_flags(flags, &mut flag_output);
    let mut labels = [Buffer::from(code), Buffer::from(flags)];
    if let Some(id) = config.requests {
        assert_eq!(
            envoy_dynamic_module_callback_http_filter_increment_counter(
                envoy,
                id,
                labels.as_mut_ptr(),
                labels.len(),
                1
            ),
            0
        );
    }
    if let Some(id) = config.duration {
        let mut timing = std::mem::MaybeUninit::<Timing>::uninit();
        envoy_dynamic_module_callback_http_get_timing_info(envoy, timing.as_mut_ptr());
        let timing = timing.assume_init();
        // StreamInfo requestComplete preserves the original request start, including header receipt.
        if timing.has_request_complete {
            assert_eq!(
                envoy_dynamic_module_callback_http_filter_record_histogram_value(
                    envoy,
                    id,
                    labels.as_mut_ptr(),
                    labels.len(),
                    timing.request_complete_duration_ns as u64 / 1_000_000,
                ),
                0
            );
        }
    }
}

fn response_code(code: u64, output: &mut [u8; 3]) -> &str {
    if !(100..600).contains(&code) {
        return "0";
    }
    *output = [
        b'0' + (code / 100) as u8,
        b'0' + ((code / 10) % 10) as u8,
        b'0' + (code % 10) as u8,
    ];
    std::str::from_utf8(output).unwrap()
}

// The host requires these hooks even when the module does not process payloads or make callouts.
macro_rules! continue_hooks {
    ($($name:ident($($arg:ident: $ty:ty),*));* $(;)?) => {$ (
        #[no_mangle]
        pub extern "C" fn $name($($arg: $ty),*) -> i32 { 0 }
    )*};
}
continue_hooks! {
    envoy_dynamic_module_on_http_filter_request_headers(_envoy: *mut c_void, _module: *mut c_void, _end: bool);
    envoy_dynamic_module_on_http_filter_request_body(_envoy: *mut c_void, _module: *mut c_void, _end: bool);
    envoy_dynamic_module_on_http_filter_request_trailers(_envoy: *mut c_void, _module: *mut c_void);
    envoy_dynamic_module_on_http_filter_response_headers(_envoy: *mut c_void, _module: *mut c_void, _end: bool);
    envoy_dynamic_module_on_http_filter_response_body(_envoy: *mut c_void, _module: *mut c_void, _end: bool);
    envoy_dynamic_module_on_http_filter_response_trailers(_envoy: *mut c_void, _module: *mut c_void);
}
macro_rules! unused_hooks {
    ($($name:ident($($arg:ident: $ty:ty),*));* $(;)?) => {$ (
        #[no_mangle]
        pub extern "C" fn $name($($arg: $ty),*) {}
    )*};
}
unused_hooks! {
    envoy_dynamic_module_on_http_filter_http_callout_done(_envoy: *mut c_void, _module: *mut c_void, _id: u64, _result: i32, _headers: *mut c_void, _header_count: usize, _body: *mut Buffer, _body_count: usize);
    envoy_dynamic_module_on_http_filter_http_stream_headers(_envoy: *mut c_void, _module: *mut c_void, _id: u64, _headers: *mut c_void, _header_count: usize, _end: bool);
    envoy_dynamic_module_on_http_filter_http_stream_data(_envoy: *mut c_void, _module: *mut c_void, _id: u64, _data: *const Buffer, _count: usize, _end: bool);
    envoy_dynamic_module_on_http_filter_http_stream_trailers(_envoy: *mut c_void, _module: *mut c_void, _id: u64, _headers: *mut c_void, _header_count: usize);
    envoy_dynamic_module_on_http_filter_http_stream_complete(_envoy: *mut c_void, _module: *mut c_void, _id: u64);
    envoy_dynamic_module_on_http_filter_http_stream_reset(_envoy: *mut c_void, _module: *mut c_void, _id: u64, _reason: i32);
    envoy_dynamic_module_on_http_filter_scheduled(_envoy: *mut c_void, _module: *mut c_void, _id: u64);
    envoy_dynamic_module_on_http_filter_downstream_above_write_buffer_high_watermark(_envoy: *mut c_void, _module: *mut c_void);
    envoy_dynamic_module_on_http_filter_downstream_below_write_buffer_low_watermark(_envoy: *mut c_void, _module: *mut c_void);
}

// CoreResponseFlag and ResponseFlagUtils abbreviations in the pinned Envoy.
const RESPONSE_FLAGS: [&str; 30] = [
    "LH", "UH", "UT", "LR", "UR", "UF", "UC", "UO", "NR", "DI", "FI", "RL", "UAEX", "RLSE", "DC",
    "URX", "SI", "IH", "DPE", "UMSDR", "RFCF", "NFCF", "DT", "UPE", "NC", "OM", "DF", "DO", "DR",
    "UDO",
];

// The ABI bitmask loses flag insertion order; combinations use core-flag enum order.
fn response_flags(bits: u64, output: &mut [u8; 128]) -> &str {
    if bits == 0 {
        return "-";
    }
    let mut len = 0;
    for (bit, flag) in RESPONSE_FLAGS.iter().enumerate() {
        if bits & (1 << bit) == 0 {
            continue;
        }
        if len != 0 {
            output[len] = b',';
            len += 1;
        }
        output[len..len + flag.len()].copy_from_slice(flag.as_bytes());
        len += flag.len();
    }
    std::str::from_utf8(&output[..len]).unwrap()
}

fn selection(value: &[u8]) -> Option<(bool, bool)> {
    match value {
        b"" => Some((true, true)),
        b"requests" => Some((true, false)),
        b"duration" => Some((false, true)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_combinations_use_envoy_abbreviations() {
        let mut output = [0; 128];
        assert_eq!(response_flags(0, &mut output), "-");
        assert_eq!(response_flags(1 << 14, &mut output), "DC");
        assert_eq!(response_flags((1 << 5) | (1 << 15), &mut output), "UF,URX");
        assert_eq!(response_flags((1 << 26) | (1 << 29), &mut output), "DF,UDO");
        assert_eq!(
            response_flags((1 << 30) - 1, &mut output),
            RESPONSE_FLAGS.join(",")
        );
    }

    #[test]
    fn status_codes_preserve_valid_codes_and_missing_response() {
        let mut output = [0; 3];
        for code in 100..600 {
            assert_eq!(response_code(code, &mut output), code.to_string());
        }
        for code in [0, 99, 600, u64::MAX] {
            assert_eq!(response_code(code, &mut output), "0");
        }
    }

    #[test]
    fn timing_layout_matches_pinned_abi() {
        assert_eq!(std::mem::size_of::<Timing>(), 176);
        assert_eq!(
            std::mem::offset_of!(Timing, request_complete_duration_ns),
            136
        );
        assert_eq!(std::mem::offset_of!(Timing, has_request_complete), 169);
    }

    #[test]
    fn metric_selection_rejects_unknown_values() {
        assert_eq!(selection(b""), Some((true, true)));
        assert_eq!(selection(b"requests"), Some((true, false)));
        assert_eq!(selection(b"duration"), Some((false, true)));
        assert_eq!(selection(b"tcp"), None);
    }
}
