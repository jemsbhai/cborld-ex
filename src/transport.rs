//! Transport adapters for CBOR-LD-ex (§10, FORMAL_MODEL.md).
//!
//! Provides thin wrappers for MQTT and CoAP transport plus protocol-specific
//! metadata derivation (topic, QoS, content-format).
//!
//! **§10.1 Transport-Agnostic Payload Principle:**
//! For any CBOR-LD-ex message M, the payload carried over MQTT and the payload
//! carried over CoAP MUST be byte-identical:
//!
//! ```text
//! mqtt_payload(M) == coap_payload(M) == encode(doc, annotation, registry)
//! ```
//!
//! The transport layer adds protocol-specific routing metadata but MUST NOT
//! alter, wrap, or re-encode the CBOR-LD-ex payload.
//!
//! ## MQTT (§10.2)
//!
//! - Payload: raw CBOR-LD-ex codec output (no MQTT-specific framing)
//! - Topic: derived from doc metadata + compliance status
//! - QoS: derived from projected probability P(ω) = b + a·u
//!
//! ## CoAP (§10.3)
//!
//! - Payload: raw CBOR-LD-ex codec output (identical to MQTT)
//! - Content-Format: 60000 (experimental range, matches CBOR tag)
//! - 802.15.4 frame fit: max payload 111 bytes (127 MTU − 16 CoAP overhead)

use crate::annotation::Annotation;
use crate::codec::{self, CodecError, ContextRegistry};
use crate::header::{ComplianceStatus, Header, PrecisionMode};
use crate::opinion::dequantize_binomial;

use ciborium::Value;

// =====================================================================
// Constants
// =====================================================================

/// CoAP Content-Format ID for CBOR-LD-ex (experimental range).
/// Matches the CBOR tag number (60000) for self-documentation.
pub const COAP_CONTENT_FORMAT_CBOR_LD_EX: u64 = 60000;

/// 802.15.4 MAC layer MTU in bytes.
pub const MTU_802154: usize = 127;

/// Approximate CoAP overhead for a minimal NON message in bytes.
pub const COAP_OVERHEAD: usize = 16;

/// Maximum CBOR-LD-ex payload that fits in a single 802.15.4 frame.
pub const MAX_SINGLE_FRAME_PAYLOAD: usize = MTU_802154 - COAP_OVERHEAD;

// =====================================================================
// MQTT Transport (§10.2)
// =====================================================================

/// Encode a CBOR-LD-ex message as an MQTT payload.
///
/// The payload is the standard CBOR-LD-ex codec output — no
/// MQTT-specific framing. MQTT carries the raw CBOR bytes as the
/// PUBLISH payload.
pub fn to_mqtt_payload(
    doc: &[(Value, Value)],
    annotation: &Annotation,
    registry: Option<&ContextRegistry>,
) -> Result<Vec<u8>, CodecError> {
    codec::encode(doc, annotation, registry)
}

/// Decode an MQTT payload to a CBOR-LD-ex message.
pub fn from_mqtt_payload(
    payload: &[u8],
    registry: Option<&ContextRegistry>,
) -> Result<(Vec<(Value, Value)>, Annotation), CodecError> {
    codec::decode(payload, registry)
}

/// Derive an MQTT topic from document metadata and annotation.
///
/// Pattern: `{prefix}/{@type_local}/{@id_fragment}/{compliance_status}`
///
/// The compliance status in the topic enables topic-based filtering
/// at the MQTT broker level — subscribers can filter by compliance
/// state without payload inspection.
pub fn derive_topic(doc: &[(Value, Value)], annotation: &Annotation, prefix: &str) -> String {
    // Extract @type
    let type_str = doc
        .iter()
        .find(|(k, _)| matches!(k, Value::Text(s) if s == "@type"))
        .and_then(|(_, v)| match v {
            Value::Text(s) => Some(local_name(s)),
            _ => None,
        })
        .unwrap_or("unknown");

    // Extract @id
    let id_str = doc
        .iter()
        .find(|(k, _)| matches!(k, Value::Text(s) if s == "@id"))
        .and_then(|(_, v)| match v {
            Value::Text(s) => Some(local_name(s)),
            _ => None,
        })
        .unwrap_or("unknown");

    // Compliance status
    let status = match &annotation.header {
        Header::Tier1(h) => h.compliance_status,
        Header::Tier2(h) => h.compliance_status,
        Header::Tier3(h) => h.compliance_status,
    };
    let status_str = match status {
        ComplianceStatus::Compliant => "compliant",
        ComplianceStatus::NonCompliant => "non_compliant",
        ComplianceStatus::Insufficient => "insufficient",
    };

    let type_seg = sanitize_topic_segment(type_str);
    let id_seg = sanitize_topic_segment(id_str);

    format!("{}/{}/{}/{}", prefix, type_seg, id_seg, status_str)
}

/// Derive MQTT QoS level from the annotation's opinion.
///
/// Uses the projected probability P(ω) = b + a·u:
///   - P(ω) ≥ 0.9  → QoS 2 (exactly once)
///   - 0.5 ≤ P(ω) < 0.9 → QoS 1 (at least once)
///   - P(ω) < 0.5  → QoS 0 (at most once)
///
/// If no opinion is present, defaults to QoS 1.
pub fn derive_qos(annotation: &Annotation) -> u8 {
    let has_opinion = match &annotation.header {
        Header::Tier1(h) => h.has_opinion,
        Header::Tier2(h) => h.has_opinion,
        Header::Tier3(h) => h.has_opinion,
    };

    if !has_opinion || annotation.opinion.is_none() {
        return 1; // Default
    }

    let q = annotation.opinion.as_ref().unwrap();

    let precision = match &annotation.header {
        Header::Tier1(h) => h.precision_mode,
        Header::Tier2(h) => h.precision_mode,
        Header::Tier3(h) => h.precision_mode,
    };

    let precision_bits = match precision {
        PrecisionMode::Bits8 => 8,
        PrecisionMode::Bits16 => 16,
        PrecisionMode::Bits32 => 32,
        PrecisionMode::Reserved => return 1,
    };

    let (b, _d, u, a) =
        dequantize_binomial(q, precision_bits).expect("valid quantized opinion should dequantize");

    let projected = b + a * u;

    if projected >= 0.9 {
        2
    } else if projected >= 0.5 {
        1
    } else {
        0
    }
}

// =====================================================================
// CoAP Transport (§10.3)
// =====================================================================

/// Encode a CBOR-LD-ex message as a CoAP payload.
///
/// Identical to MQTT — the payload is the CBOR-LD-ex codec output.
/// CoAP-specific metadata (Content-Format option, Uri-Path) is set
/// by the CoAP client library, not embedded in the payload.
pub fn to_coap_payload(
    doc: &[(Value, Value)],
    annotation: &Annotation,
    registry: Option<&ContextRegistry>,
) -> Result<Vec<u8>, CodecError> {
    codec::encode(doc, annotation, registry)
}

/// Decode a CoAP payload to a CBOR-LD-ex message.
pub fn from_coap_payload(
    payload: &[u8],
    registry: Option<&ContextRegistry>,
) -> Result<(Vec<(Value, Value)>, Annotation), CodecError> {
    codec::decode(payload, registry)
}

// =====================================================================
// Frame fit (§10.3)
// =====================================================================

/// Check whether a payload fits in a single 802.15.4 frame
/// after accounting for CoAP overhead.
pub fn fits_single_frame(payload: &[u8]) -> bool {
    payload.len() <= MAX_SINGLE_FRAME_PAYLOAD
}

// =====================================================================
// Internal helpers
// =====================================================================

/// Extract the local/fragment part of an IRI or URN.
///
/// - `http://example.org/ns#Foo` → `Foo`
/// - `http://example.org/ns/Foo` → `Foo`
/// - `urn:sensor:temp-042` → `temp-042`
fn local_name(iri: &str) -> &str {
    if let Some(pos) = iri.rfind('#') {
        &iri[pos + 1..]
    } else if let Some(pos) = iri.rfind('/') {
        &iri[pos + 1..]
    } else if let Some(pos) = iri.rfind(':') {
        &iri[pos + 1..]
    } else {
        iri
    }
}

/// Remove MQTT-illegal characters from a topic segment.
///
/// MQTT topic names must not contain `#`, `+`, or null bytes.
/// Segments must not start with `$` (reserved for broker system topics).
fn sanitize_topic_segment(segment: &str) -> String {
    let mut s = String::with_capacity(segment.len());
    for c in segment.chars() {
        match c {
            '#' | '+' | '\0' => s.push('_'),
            _ => s.push(c),
        }
    }
    // Strip leading '$' (reserved for broker system topics)
    let trimmed = s.trim_start_matches('$');
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed.to_string()
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::*;
    use crate::opinion::QuantizedBinomial;

    // =============================================================
    // Helpers
    // =============================================================

    fn sample_doc() -> Vec<(Value, Value)> {
        vec![
            (
                Value::Text("@type".into()),
                Value::Text("TemperatureReading".into()),
            ),
            (
                Value::Text("@id".into()),
                Value::Text("urn:sensor:temp-042".into()),
            ),
            (Value::Text("value".into()), Value::Float(22.5)),
            (Value::Text("unit".into()), Value::Text("Celsius".into())),
        ]
    }

    fn sample_annotation_compliant() -> Annotation {
        Annotation {
            header: Header::Tier1(Tier1Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: true,
                precision_mode: PrecisionMode::Bits8,
            }),
            opinion: Some(QuantizedBinomial {
                belief: 217,
                disbelief: 13,
                uncertainty: 25,
                base_rate: 128,
            }),
            extensions: None,
        }
    }

    fn sample_annotation_no_opinion() -> Annotation {
        Annotation {
            header: Header::Tier1(Tier1Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: false,
                precision_mode: PrecisionMode::Bits8,
            }),
            opinion: None,
            extensions: None,
        }
    }

    // =============================================================
    // 1. MQTT payload roundtrip
    // =============================================================

    #[test]
    fn test_mqtt_payload_roundtrip() {
        let doc = sample_doc();
        let ann = sample_annotation_compliant();

        let payload = to_mqtt_payload(&doc, &ann, None).unwrap();
        let (decoded_doc, decoded_ann) = from_mqtt_payload(&payload, None).unwrap();

        assert_eq!(decoded_doc, doc);
        assert_eq!(decoded_ann, ann);
    }

    // =============================================================
    // 2. CoAP payload roundtrip
    // =============================================================

    #[test]
    fn test_coap_payload_roundtrip() {
        let doc = sample_doc();
        let ann = sample_annotation_compliant();

        let payload = to_coap_payload(&doc, &ann, None).unwrap();
        let (decoded_doc, decoded_ann) = from_coap_payload(&payload, None).unwrap();

        assert_eq!(decoded_doc, doc);
        assert_eq!(decoded_ann, ann);
    }

    // =============================================================
    // 3. §10.1 Transport-agnostic payload identity
    // =============================================================

    #[test]
    fn test_transport_agnostic_identity() {
        let doc = sample_doc();
        let ann = sample_annotation_compliant();

        let mqtt = to_mqtt_payload(&doc, &ann, None).unwrap();
        let coap = to_coap_payload(&doc, &ann, None).unwrap();

        assert_eq!(
            mqtt, coap,
            "§10.1 violation: MQTT and CoAP payloads must be byte-identical"
        );
    }

    // =============================================================
    // 4. derive_topic — basic case
    // =============================================================

    #[test]
    fn test_derive_topic_basic() {
        let doc = sample_doc();
        let ann = sample_annotation_compliant();

        let topic = derive_topic(&doc, &ann, "cbor-ld-ex");
        assert_eq!(topic, "cbor-ld-ex/TemperatureReading/temp-042/compliant");
    }

    // =============================================================
    // 5. derive_topic — all compliance statuses
    // =============================================================

    #[test]
    fn test_derive_topic_all_compliance_statuses() {
        let doc = sample_doc();

        let cases = [
            (ComplianceStatus::Compliant, "compliant"),
            (ComplianceStatus::NonCompliant, "non_compliant"),
            (ComplianceStatus::Insufficient, "insufficient"),
        ];

        for (status, expected_suffix) in cases {
            let ann = Annotation {
                header: Header::Tier1(Tier1Header {
                    compliance_status: status,
                    delegation_flag: false,
                    has_opinion: false,
                    precision_mode: PrecisionMode::Bits8,
                }),
                opinion: None,
                extensions: None,
            };

            let topic = derive_topic(&doc, &ann, "cbor-ld-ex");
            assert!(
                topic.ends_with(expected_suffix),
                "Expected topic to end with '{}', got '{}'",
                expected_suffix,
                topic
            );
        }
    }

    // =============================================================
    // 6. derive_topic — sanitizes MQTT-illegal characters
    // =============================================================

    #[test]
    fn test_derive_topic_sanitizes_mqtt_chars() {
        // '#' in an IRI is consumed by local_name as a fragment separator
        // (correct JSON-LD behavior). To test sanitization of '#' and '+',
        // they must appear within the local name portion — i.e. after the
        // last IRI delimiter.
        //
        // Use a plain string (no IRI structure) so local_name returns it
        // whole, and both '#' and '+' reach sanitize_topic_segment.
        let doc = vec![
            (
                Value::Text("@type".into()),
                Value::Text("Sensor+Reading".into()),
            ),
            (
                Value::Text("@id".into()),
                Value::Text("urn:sensor:node#1+2".into()),
            ),
        ];
        let ann = sample_annotation_no_opinion();

        let topic = derive_topic(&doc, &ann, "cbor-ld-ex");
        // '+' in @type local name must be replaced with '_'
        assert!(
            !topic.contains('+'),
            "Topic must not contain '+': {}",
            topic
        );
        assert!(
            topic.contains("Sensor_Reading"),
            "Expected sanitized @type segment, got: {}",
            topic
        );
        // For @id "urn:sensor:node#1+2", local_name splits on '#' → "1+2",
        // then sanitize replaces '+' → "1_2"
        assert!(
            topic.contains("1_2"),
            "Expected sanitized @id segment, got: {}",
            topic
        );
    }

    // =============================================================
    // 7. derive_topic — IRI fragment extraction
    // =============================================================

    #[test]
    fn test_derive_topic_iri_fragment() {
        let doc = vec![
            (
                Value::Text("@type".into()),
                Value::Text("http://example.org/ns#TemperatureReading".into()),
            ),
            (
                Value::Text("@id".into()),
                Value::Text("http://example.org/sensors#temp-042".into()),
            ),
        ];
        let ann = sample_annotation_no_opinion();

        let topic = derive_topic(&doc, &ann, "pfx");
        assert_eq!(topic, "pfx/TemperatureReading/temp-042/compliant");
    }

    // =============================================================
    // 8. derive_topic — URN local name
    // =============================================================

    #[test]
    fn test_derive_topic_urn() {
        let doc = vec![
            (
                Value::Text("@type".into()),
                Value::Text("urn:iot:type:TempReading".into()),
            ),
            (
                Value::Text("@id".into()),
                Value::Text("urn:sensor:temp-042".into()),
            ),
        ];
        let ann = sample_annotation_no_opinion();

        let topic = derive_topic(&doc, &ann, "cbor-ld-ex");
        assert_eq!(topic, "cbor-ld-ex/TempReading/temp-042/compliant");
    }

    // =============================================================
    // 9. derive_topic — custom prefix
    // =============================================================

    #[test]
    fn test_derive_topic_custom_prefix() {
        let doc = sample_doc();
        let ann = sample_annotation_no_opinion();

        let topic = derive_topic(&doc, &ann, "iot/v2");
        assert!(topic.starts_with("iot/v2/"));
    }

    // =============================================================
    // 10. derive_qos — high confidence → QoS 2
    // =============================================================

    #[test]
    fn test_derive_qos_high_confidence() {
        // b=230/255≈0.902, d=5/255≈0.020, u=20/255≈0.078, a=128/255≈0.502
        // P(ω) = 0.902 + 0.502 × 0.078 ≈ 0.941 ≥ 0.9 → QoS 2
        let ann = Annotation {
            header: Header::Tier1(Tier1Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: true,
                precision_mode: PrecisionMode::Bits8,
            }),
            opinion: Some(QuantizedBinomial {
                belief: 230,
                disbelief: 5,
                uncertainty: 20,
                base_rate: 128,
            }),
            extensions: None,
        };

        assert_eq!(derive_qos(&ann), 2);
    }

    // =============================================================
    // 11. derive_qos — normal confidence → QoS 1
    // =============================================================

    #[test]
    fn test_derive_qos_normal_confidence() {
        // b=153/255≈0.600, d=26/255≈0.102, u=76/255≈0.298, a=128/255≈0.502
        // P(ω) = 0.600 + 0.502 × 0.298 ≈ 0.750 → QoS 1
        let ann = Annotation {
            header: Header::Tier1(Tier1Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: true,
                precision_mode: PrecisionMode::Bits8,
            }),
            opinion: Some(QuantizedBinomial {
                belief: 153,
                disbelief: 26,
                uncertainty: 76,
                base_rate: 128,
            }),
            extensions: None,
        };

        assert_eq!(derive_qos(&ann), 1);
    }

    // =============================================================
    // 12. derive_qos — low confidence → QoS 0
    // =============================================================

    #[test]
    fn test_derive_qos_low_confidence() {
        // b=26/255≈0.102, d=77/255≈0.302, u=152/255≈0.596, a=128/255≈0.502
        // P(ω) = 0.102 + 0.502 × 0.596 ≈ 0.401 < 0.5 → QoS 0
        let ann = Annotation {
            header: Header::Tier1(Tier1Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: true,
                precision_mode: PrecisionMode::Bits8,
            }),
            opinion: Some(QuantizedBinomial {
                belief: 26,
                disbelief: 77,
                uncertainty: 152,
                base_rate: 128,
            }),
            extensions: None,
        };

        assert_eq!(derive_qos(&ann), 0);
    }

    // =============================================================
    // 13. derive_qos — no opinion → QoS 1 default
    // =============================================================

    #[test]
    fn test_derive_qos_no_opinion() {
        let ann = sample_annotation_no_opinion();
        assert_eq!(derive_qos(&ann), 1);
    }

    // =============================================================
    // 14. Tier 1 message fits single 802.15.4 frame
    // =============================================================

    #[test]
    fn test_tier1_fits_single_frame() {
        let doc = sample_doc();
        let ann = sample_annotation_compliant();

        let payload = to_mqtt_payload(&doc, &ann, None).unwrap();
        assert!(
            fits_single_frame(&payload),
            "Tier 1 payload ({} bytes) should fit in single 802.15.4 frame (max {} bytes)",
            payload.len(),
            MAX_SINGLE_FRAME_PAYLOAD
        );
    }

    // =============================================================
    // 15. CoAP Content-Format constant
    // =============================================================

    #[test]
    fn test_coap_content_format_constant() {
        assert_eq!(COAP_CONTENT_FORMAT_CBOR_LD_EX, 60000);
    }
}
