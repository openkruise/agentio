// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

//! Cross-language wire corpus: responses marshaled by the real Go compiler
//! (tests/query_fixtures.go) must decode and resolve identically here.

use super::*;
use super::query_tests::QueryFixture;
use crate::wire::agentio::sandbox::GetSandboxResponse;
use base64::Engine as _;
use prost::Message;
use serde::Deserialize;
use tonic::Code;

#[derive(Deserialize)]
struct Expect {
    outcome: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    uid: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    profile: bool,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    response: String,
    expect: Expect,
}

#[tokio::test]
async fn wire_corpus_matches_go_compiler_outcomes() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/query_fixtures.json");
    let cases: Vec<Case> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert!(!cases.is_empty());
    let f = QueryFixture::new().await;
    let c = f.client();
    for case in &cases {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&case.response)
            .unwrap();
        let response = GetSandboxResponse::decode(bytes.as_slice()).unwrap();
        assert_eq!(response.version, case.expect.version, "{}: version", case.name);
        f.put_raw(&case.name, response);
        let result = c.demand(ResourceKind::Sandbox, &case.name, None).await;
        match case.expect.outcome.as_str() {
            "value" => {
                let value = result.unwrap();
                let View::Sandbox(s) = value.as_ref() else {
                    panic!("{}: expected Sandbox view", case.name);
                };
                assert_eq!(s.uid, case.expect.uid, "{}: uid", case.name);
                assert_eq!(s.profile.is_some(), case.expect.profile, "{}: profile", case.name);
            }
            "not_found" => assert!(
                matches!(result.unwrap_err(), DemandError::NotFound),
                "{}: expected NotFound",
                case.name
            ),
            "error" => {
                let expected = match case.expect.code.as_str() {
                    "DataLoss" => Code::DataLoss,
                    other => panic!("{}: unmapped code {other}", case.name),
                };
                assert!(
                    matches!(result.unwrap_err(), DemandError::Query(code) if code == expected),
                    "{}: expected {expected:?}",
                    case.name
                );
            }
            other => panic!("{}: unknown outcome {other}", case.name),
        }
    }
}