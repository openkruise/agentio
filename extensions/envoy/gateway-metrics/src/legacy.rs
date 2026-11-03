// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

// Kept for gateways still receiving the previous native access-logger configuration.
use super::{c_void, Buffer};

#[repr(C)]
struct Timing {
    start_time_unix_ns: i64,
    request_complete_duration_ns: i64,
    first_upstream_tx_byte_sent_ns: i64,
    last_upstream_tx_byte_sent_ns: i64,
    first_upstream_rx_byte_received_ns: i64,
    last_upstream_rx_byte_received_ns: i64,
    first_downstream_tx_byte_sent_ns: i64,
    last_downstream_tx_byte_sent_ns: i64,
}

extern "C" {
    fn envoy_dynamic_module_callback_access_logger_config_define_counter(
        config: *mut c_void,
        name: Buffer,
        id: *mut usize,
    ) -> i32;
    fn envoy_dynamic_module_callback_access_logger_config_define_histogram(
        config: *mut c_void,
        name: Buffer,
        id: *mut usize,
    ) -> i32;
    fn envoy_dynamic_module_callback_access_logger_increment_counter(
        config: *mut c_void,
        id: usize,
        value: u64,
    ) -> i32;
    fn envoy_dynamic_module_callback_access_logger_record_histogram_value(
        config: *mut c_void,
        id: usize,
        value: u64,
    ) -> i32;
    fn envoy_dynamic_module_callback_access_logger_get_response_code(logger: *mut c_void) -> u32;
    fn envoy_dynamic_module_callback_access_logger_get_timing_info(
        logger: *mut c_void,
        timing: *mut Timing,
    );
}

struct Config {
    envoy: *mut c_void,
    counters: [usize; 600],
    duration: usize,
    requests_enabled: bool,
    duration_enabled: bool,
}

#[no_mangle]
pub unsafe extern "C" fn envoy_dynamic_module_on_access_logger_config_new(
    envoy: *mut c_void,
    _name: Buffer,
    selection: Buffer,
) -> *mut c_void {
    let selection = if selection.len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(selection.ptr, selection.len)
    };
    let (requests_enabled, duration_enabled) = match selection {
        b"" => (true, true),
        b"requests" => (true, false),
        b"duration" => (false, true),
        _ => return std::ptr::null_mut(),
    };
    let mut config = Box::new(Config {
        envoy,
        counters: [0; 600],
        duration: 0,
        requests_enabled,
        duration_enabled,
    });
    // Register during initialization as required by the host ABI. Requests only
    // update existing metrics, without allocation or a module-level lock.
    for code in std::iter::once(0)
        .chain(100..600)
        .filter(|_| requests_enabled)
    {
        let name = format!("istio_requests_total.response_code.{code}");
        if envoy_dynamic_module_callback_access_logger_config_define_counter(
            envoy,
            Buffer::from(&name),
            &mut config.counters[code],
        ) != 0
        {
            return std::ptr::null_mut();
        }
    }
    if duration_enabled
        && envoy_dynamic_module_callback_access_logger_config_define_histogram(
            envoy,
            Buffer::from("istio_request_duration_milliseconds"),
            &mut config.duration,
        ) != 0
    {
        return std::ptr::null_mut();
    }
    Box::into_raw(config).cast()
}

#[no_mangle]
pub unsafe extern "C" fn envoy_dynamic_module_on_access_logger_config_destroy(config: *mut c_void) {
    drop(Box::from_raw(config.cast::<Config>()));
}

#[no_mangle]
pub extern "C" fn envoy_dynamic_module_on_access_logger_new(
    config: *mut c_void,
    _: *mut c_void,
) -> *mut c_void {
    config
}

#[no_mangle]
pub extern "C" fn envoy_dynamic_module_on_access_logger_destroy(_: *mut c_void) {}

#[no_mangle]
pub unsafe extern "C" fn envoy_dynamic_module_on_access_logger_log(
    logger: *mut c_void,
    config: *mut c_void,
    log_type: i32,
) {
    // DownstreamEnd only: tunnel establishment and periodic logs are not requests.
    if log_type != 6 {
        return;
    }
    let config = &*config.cast::<Config>();
    let code = envoy_dynamic_module_callback_access_logger_get_response_code(logger) as usize;
    let code = if (100..600).contains(&code) { code } else { 0 };
    let mut timing = std::mem::MaybeUninit::<Timing>::uninit();
    envoy_dynamic_module_callback_access_logger_get_timing_info(logger, timing.as_mut_ptr());
    let timing = timing.assume_init();
    if config.requests_enabled {
        assert_eq!(
            envoy_dynamic_module_callback_access_logger_increment_counter(
                config.envoy,
                config.counters[code],
                1
            ),
            0
        );
    }
    // requestComplete also covers requests aborted before the final response byte.
    if config.duration_enabled && timing.request_complete_duration_ns >= 0 {
        assert_eq!(
            envoy_dynamic_module_callback_access_logger_record_histogram_value(
                config.envoy,
                config.duration,
                timing.request_complete_duration_ns as u64 / 1_000_000,
            ),
            0
        );
    }
}
