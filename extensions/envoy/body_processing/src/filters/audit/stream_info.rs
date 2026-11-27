// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{Attributes, RequestHeader};
use chrono::{
    DateTime, Utc,
    format::{Item, StrftimeItems},
};
use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyHttpFilter, TimingInfo, abi::envoy_dynamic_module_type_attribute_id as Attribute,
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub(crate) struct Completion {
    pub(super) fields: BTreeMap<String, (Field, usize)>,
}

pub(super) enum Field {
    StartTime(Vec<Item<'static>>),
    Duration(Duration),
    Header(RequestHeader),
    TraceId,
    SpanId,
    Flags,
    ResponseCodeDetails,
    ResponseCode,
}

pub(super) enum Duration {
    Total,
    Request,
    Response,
}

impl Field {
    pub(super) fn parse(name: &str, argument: Option<&str>) -> Result<Option<Self>, String> {
        let field = match (name, argument) {
            ("START_TIME", format) => {
                let format = format.unwrap_or("%Y-%m-%dT%H:%M:%S%.3fZ");
                let items: Vec<_> = StrftimeItems::new(format).map(Item::to_owned).collect();
                DateTime::<Utc>::UNIX_EPOCH
                    .format_with_items(items.iter())
                    .write_to(&mut String::new())
                    .map_err(|_| "invalid START_TIME format")?;
                Self::StartTime(items)
            }
            ("RESP", Some(args)) => Self::Header(RequestHeader::parse(args)?),
            ("DURATION", None) => Self::Duration(Duration::Total),
            ("REQUEST_DURATION", None) => Self::Duration(Duration::Request),
            ("RESPONSE_DURATION", None) => Self::Duration(Duration::Response),
            ("RESPONSE_CODE", None) => Self::ResponseCode,
            ("RESPONSE_CODE_DETAILS", None) => Self::ResponseCodeDetails,
            ("TRACE_ID", None) => Self::TraceId,
            ("SPAN_ID", None) => Self::SpanId,
            ("RESPONSE_FLAGS", None) => Self::Flags,
            _ => return Ok(None),
        };
        Ok(Some(field))
    }

    pub(super) fn numeric(&self) -> bool {
        matches!(self, Self::ResponseCode | Self::Duration(_))
    }

    fn value(
        &self,
        envoy: &impl EnvoyHttpFilter,
        timing: &mut Option<TimingInfo>,
    ) -> Option<Value> {
        let text = match self {
            Self::StartTime(format) => {
                let timestamp = timing
                    .get_or_insert_with(|| envoy.get_timing_info())
                    .start_time_unix_ns?;
                let date = DateTime::<Utc>::from_timestamp(
                    timestamp.div_euclid(1_000_000_000),
                    timestamp.rem_euclid(1_000_000_000) as u32,
                )?;
                date.format_with_items(format.iter()).to_string()
            }
            Self::Duration(duration) => {
                let timing = timing.get_or_insert_with(|| envoy.get_timing_info());
                let ns = match duration {
                    Duration::Total => timing.request_complete_duration_ns,
                    Duration::Request => timing.last_downstream_rx_byte_received_ns,
                    Duration::Response => timing.first_upstream_rx_byte_received_ns,
                }?;
                return Some((ns / 1_000_000).into());
            }
            Self::Header(header) => {
                let value = header.get(|key| envoy.get_response_header_value(key))?;
                String::from_utf8_lossy(value.as_slice()).into_owned()
            }
            Self::TraceId => envoy
                .get_active_span()?
                .get_trace_id()
                .filter(|id| !id.is_empty())?,
            Self::SpanId => envoy
                .get_active_span()?
                .get_span_id()
                .filter(|id| !id.is_empty())?,
            Self::Flags => flags(envoy.get_attribute_int(Attribute::ResponseFlags)? as u64),
            Self::ResponseCodeDetails => {
                let value = envoy.get_attribute_string(Attribute::ResponseCodeDetails)?;
                let text = String::from_utf8_lossy(value.as_slice());
                text.replace([' ', '\t', '\n', '\r', '\x0b', '\x0c'], "_")
            }
            Self::ResponseCode => {
                return envoy
                    .get_attribute_int(Attribute::ResponseCode)
                    .map(Value::from);
            }
        };
        Some(Value::String(text))
    }
}

impl Completion {
    pub(crate) fn capture(&self, envoy: &impl EnvoyHttpFilter, row: &mut Map<String, Value>) {
        let mut timing = None;
        let mut attrs = Attributes::default();
        for (alias, (field, limit)) in &self.fields {
            if let Some(value) = field.value(envoy, &mut timing) {
                if let Value::String(value) = value {
                    attrs.insert(alias, &value, *limit);
                } else {
                    attrs.values.insert(alias.clone(), value);
                }
            }
        }
        row.append(&mut attrs.values);
    }
}

fn flags(mask: u64) -> String {
    // Envoy 1.40.2 CoreResponseFlag order, exposed by the SDK as a bitmask.
    const NAMES: [&str; 30] = [
        "LH", "UH", "UT", "LR", "UR", "UF", "UC", "UO", "NR", "DI", "FI", "RL", "UAEX", "RLSE",
        "DC", "URX", "SI", "IH", "DPE", "UMSDR", "RFCF", "NFCF", "DT", "UPE", "NC", "OM", "DF",
        "DO", "DR", "UDO",
    ];
    if mask == 0 {
        return "-".into();
    }
    NAMES
        .iter()
        .enumerate()
        .filter_map(|(i, name)| (mask & (1 << i) != 0).then_some(*name))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::audit::Audit;

    #[test]
    fn stream_fields_compile_without_body_parsers() {
        for expression in [
            "%START_TIME%",
            "%START_TIME(%s.%9f)%",
            "%START_TIME(%Y/%m/%dT%H:%M:%S%z)%",
            "%DURATION%",
            "%REQUEST_DURATION%",
            "%RESPONSE_DURATION%",
            "%RESP(X-ID?X-OTHER):4%",
            "%TRACE_ID%",
            "%SPAN_ID%",
            "%RESPONSE_FLAGS%",
            "%RESPONSE_CODE_DETAILS%",
            "%RESPONSE_CODE%",
        ] {
            let audit =
                Audit::compile(BTreeMap::from([("field".into(), expression.into())])).unwrap();
            assert!(
                audit.request.is_none() && audit.response.is_none(),
                "{expression}"
            );
            assert_eq!(audit.completion.fields.len(), 1, "{expression}");
        }
        for expression in [
            "%DURATION(ms)%",
            "%DURATION:4%",
            "%REQUEST_DURATION:1%",
            "%RESPONSE_DURATION:1%",
            "%RESPONSE_CODE:1%",
            "%START_TIME(%Q)%",
            "%START_TIME(%)%",
            "%START_TIME(%#z)%",
            "%RESP%",
            "%RESP(white space)%",
            "%ENVIRONMENT()%",
        ] {
            assert!(
                Audit::compile(BTreeMap::from([("field".into(), expression.into())])).is_err(),
                "{expression}"
            );
        }
    }

    #[test]
    fn deferred_operators_are_not_accepted() {
        for expression in [
            "%RESPONSE_TX_DURATION%",
            "%UPSTREAM_REQUEST_ATTEMPT_COUNT%",
            "%UPSTREAM_HOST%",
            "%UPSTREAM_CLUSTER%",
            "%PROTOCOL%",
            "%UPSTREAM_PROTOCOL%",
            "%DOWNSTREAM_REMOTE_ADDRESS%",
            "%TRAILER(X-ID)%",
            "%ROUTE_NAME%",
            "%CONNECTION_TERMINATION_DETAILS%",
            "%UPSTREAM_TRANSPORT_FAILURE_REASON%",
            "%BYTES_RECEIVED%",
            "%BYTES_SENT%",
            "%REQUEST_HEADER(X-ID)%",
            "%RESPONSE_HEADER(X-ID)%",
            "%RESPONSE_TRAILER(X-ID)%",
        ] {
            assert!(
                Audit::compile(BTreeMap::from([("field".into(), expression.into())])).is_err(),
                "{expression}"
            );
        }
    }
}
