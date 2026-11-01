// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use x509_parser::{
    certificate::X509Certificate,
    error::{PEMError, X509Error},
    nom,
    pem::parse_x509_pem,
    prelude::FromDer,
};

const WORKLOAD_IDENTITY_OID: &str = "1.3.6.1.4.1.57874.5.1";

// Match the control plane: leave only RFC 3986 unreserved UID bytes unescaped.
const INSTANCE_UID_ESCAPE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid certificate URL encoding")]
    UrlEncoding,
    #[error("invalid certificate PEM: {0}")]
    Pem(#[source] nom::Err<PEMError>),
    #[error("expected CERTIFICATE PEM block")]
    PemType,
    #[error("invalid certificate DER: {0}")]
    Der(#[source] nom::Err<X509Error>),
    #[error("invalid workload identity extension: {0}")]
    Claim(#[from] serde_json::Error),
    #[error("workload identity registry and uid are required")]
    MissingIdentityFields,
}

#[derive(Deserialize)]
struct WorkloadIdentity {
    registry: String,
    uid: String,
}

/// Envoy has already authenticated TLS. Only parse its captured certificate;
/// CONNECT headers cannot supply or override these claims.
pub fn certificate_instance(encoded: &str) -> Result<Option<String>, Error> {
    if encoded.is_empty() {
        return Ok(None);
    }

    // PathUnescape semantics: '+' is literal and incomplete escapes are errors.
    let bytes = encoded.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'%'
            && (index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit())
        {
            return Err(Error::UrlEncoding);
        }
    }
    let decoded = percent_encoding::percent_decode_str(encoded).collect::<Vec<_>>();
    let (_, pem) = parse_x509_pem(&decoded).map_err(Error::Pem)?;
    if pem.label != "CERTIFICATE" {
        return Err(Error::PemType);
    }
    let (_, certificate) = X509Certificate::from_der(&pem.contents).map_err(Error::Der)?;
    for extension in certificate.extensions() {
        if extension.oid.to_id_string() == WORKLOAD_IDENTITY_OID {
            let identity: WorkloadIdentity = serde_json::from_slice(extension.value)?;
            if identity.registry.is_empty() || identity.uid.is_empty() {
                return Err(Error::MissingIdentityFields);
            }
            return Ok(Some(format!(
                "workload-instance/{}/{}",
                identity.registry,
                percent_encoding::utf8_percent_encode(&identity.uid, INSTANCE_UID_ESCAPE)
            )));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, CustomExtension, KeyPair};

    fn certificate(claim: Option<&[u8]>) -> String {
        let mut params = CertificateParams::default();
        if let Some(claim) = claim {
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 4, 1, 57874, 5, 1],
                    claim.to_vec(),
                ));
        }
        params
            .self_signed(&KeyPair::generate().unwrap())
            .unwrap()
            .pem()
    }

    #[test]
    fn absent_identity_allows_legacy_lookup() {
        assert_eq!(certificate_instance("").unwrap(), None);
        assert_eq!(certificate_instance(&certificate(None)).unwrap(), None);
    }

    #[test]
    fn workload_alias_matches_control_plane() {
        for (claim, expected) in [
            (
                r#"{"registry":"kubernetes/demo","uid":"pod-123"}"#,
                "workload-instance/kubernetes/demo/pod-123",
            ),
            (
                r#"{"registry":"runtime","uid":"a/b% c-._~"}"#,
                "workload-instance/runtime/a%2Fb%25%20c-._~",
            ),
        ] {
            assert_eq!(
                certificate_instance(&certificate(Some(claim.as_bytes()))).unwrap(),
                Some(expected.to_string())
            );
        }
    }

    #[test]
    fn runtime_identity_accepts_pem_and_url_encoding() {
        let pem = certificate(Some(
            r#"{"registry":"运行时","uid":"sandbox+42:/","role":"sandbox-attester","future":true}"#
                .as_bytes(),
        ));
        let expected = Some("workload-instance/运行时/sandbox%2B42%3A%2F".to_string());
        assert_eq!(certificate_instance(&pem).unwrap(), expected);
        let encoded =
            percent_encoding::utf8_percent_encode(&pem, percent_encoding::NON_ALPHANUMERIC)
                .to_string();
        assert_eq!(certificate_instance(&encoded).unwrap(), expected);
        // '+' in PEM is literal, not form-url-encoded whitespace.
        assert_eq!(
            certificate_instance(&encoded.replace("%2B", "+")).unwrap(),
            expected
        );
    }

    #[test]
    fn certificate_errors_retain_their_category_and_source() {
        for encoded in ["%", "%A", "%XX"] {
            assert!(matches!(
                certificate_instance(encoded),
                Err(Error::UrlEncoding)
            ));
        }
        let pem_error = certificate_instance("not a certificate").unwrap_err();
        assert!(matches!(pem_error, Error::Pem(_)));
        assert!(std::error::Error::source(&pem_error).is_some());

        let pem = certificate(None);
        assert!(matches!(
            certificate_instance(&pem.replace("CERTIFICATE", "PRIVATE KEY")),
            Err(Error::PemType)
        ));
        let der_error =
            certificate_instance("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n")
                .unwrap_err();
        assert!(matches!(der_error, Error::Der(_)));
        assert!(std::error::Error::source(&der_error).is_some());
    }

    #[test]
    fn invalid_claim_is_distinct_from_absent_identity() {
        for claim in [
            b"{".as_slice(),
            br#"{"registry":"r"}"#,
            br#"{"registry":"r","uid":42}"#,
        ] {
            let error = certificate_instance(&certificate(Some(claim))).unwrap_err();
            assert!(matches!(error, Error::Claim(_)));
            assert!(std::error::Error::source(&error).is_some());
        }
        for claim in [
            br#"{"registry":"","uid":"u"}"#.as_slice(),
            br#"{"registry":"r","uid":""}"#,
        ] {
            assert!(matches!(
                certificate_instance(&certificate(Some(claim))),
                Err(Error::MissingIdentityFields)
            ));
        }
    }
}
