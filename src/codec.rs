//! Full CBOR-LD-ex codec — encode/decode pipeline.
//!
//! Ties headers, opinions, annotations, and CBOR together:
//!   encode: JSON-LD doc + Annotation → CBOR bytes
//!   decode: CBOR bytes → JSON-LD doc + Annotation
//!
//! Wire format (§5.3):
//!   CBOR map = {
//!     ...data fields (context-compressed to integer keys/values)...,
//!     ANNOTATION_TERM_ID: Tag(60000, annotation_bytes)
//!   }

use std::collections::BTreeMap;

use ciborium::Value;

use crate::annotation::{
    Annotation, AnnotationError, CBOR_TAG_CBORLD_EX,
    encode_annotation, decode_annotation,
};

/// Wire-level integer key for the annotation block in the CBOR map.
/// Matches the CBOR tag number for self-documentation: 60000.
/// CBOR encoding cost: 3 bytes. Compare to "@annotation" string: 12 bytes.
pub const ANNOTATION_TERM_ID: u64 = CBOR_TAG_CBORLD_EX;

/// Error type for codec operations.
#[derive(Debug)]
pub enum CodecError {
    Annotation(AnnotationError),
    /// CBOR serialization/deserialization failure.
    Cbor(String),
    /// Top-level CBOR value is not a map.
    NotAMap,
    /// No annotation found at the expected term ID.
    MissingAnnotation,
    /// Annotation tag number mismatch.
    WrongTag { expected: u64, got: u64 },
    /// Duplicate integer codes in registry.
    DuplicateCodes,
    /// Code collision between key_map and value_map.
    CodeCollision,
    /// Reserved annotation term ID used in registry.
    ReservedCodeUsed,
}

impl From<AnnotationError> for CodecError {
    fn from(e: AnnotationError) -> Self {
        Self::Annotation(e)
    }
}

// =====================================================================
// Context Registry
// =====================================================================

/// Registry for compressing JSON-LD keys AND values to integer codes.
///
/// Maps known JSON-LD string keys to small integers (term compression)
/// and known string values to integers (value compression).
pub struct ContextRegistry {
    key_to_int: BTreeMap<String, i64>,
    int_to_key: BTreeMap<i64, String>,
    val_to_int: BTreeMap<String, i64>,
    int_to_val: BTreeMap<i64, String>,
}

impl ContextRegistry {
    /// Create a new registry from key and value maps.
    ///
    /// Validates: no duplicate codes within maps, no collisions across maps,
    /// no collision with the reserved ANNOTATION_TERM_ID.
    pub fn new(
        key_map: BTreeMap<String, i64>,
        value_map: BTreeMap<String, i64>,
    ) -> Result<Self, CodecError> {
        // Validate no collisions across maps
        let key_codes: std::collections::BTreeSet<i64> = key_map.values().copied().collect();
        let val_codes: std::collections::BTreeSet<i64> = value_map.values().copied().collect();

        if key_codes.len() != key_map.len() {
            return Err(CodecError::DuplicateCodes);
        }
        if val_codes.len() != value_map.len() {
            return Err(CodecError::DuplicateCodes);
        }

        let overlap: Vec<_> = key_codes.intersection(&val_codes).collect();
        if !overlap.is_empty() {
            return Err(CodecError::CodeCollision);
        }

        // Validate no collision with reserved annotation term ID
        let ann_id = ANNOTATION_TERM_ID as i64;
        if key_codes.contains(&ann_id) || val_codes.contains(&ann_id) {
            return Err(CodecError::ReservedCodeUsed);
        }

        let int_to_key: BTreeMap<i64, String> = key_map.iter().map(|(k, v)| (*v, k.clone())).collect();
        let int_to_val: BTreeMap<i64, String> = value_map.iter().map(|(k, v)| (*v, k.clone())).collect();

        Ok(Self {
            key_to_int: key_map,
            int_to_key,
            val_to_int: value_map,
            int_to_val,
        })
    }

    /// Compress a CBOR Value map: replace known string keys/values with integers.
    pub fn compress(&self, doc: &[(Value, Value)]) -> Vec<(Value, Value)> {
        doc.iter().map(|(k, v)| {
            let ck = if let Value::Text(s) = k {
                if let Some(&code) = self.key_to_int.get(s.as_str()) {
                    Value::Integer(code.into())
                } else {
                    k.clone()
                }
            } else {
                k.clone()
            };

            let cv = if let Value::Text(s) = v {
                if let Some(&code) = self.val_to_int.get(s.as_str()) {
                    Value::Integer(code.into())
                } else {
                    v.clone()
                }
            } else {
                v.clone()
            };

            (ck, cv)
        }).collect()
    }

    /// Decompress a CBOR Value map: replace integer keys/values with strings.
    pub fn decompress(&self, doc: &[(Value, Value)]) -> Vec<(Value, Value)> {
        doc.iter().map(|(k, v)| {
            let dk = if let Value::Integer(i) = k {
                let code: i128 = (*i).into();
                if let Some(s) = self.int_to_key.get(&(code as i64)) {
                    Value::Text(s.clone())
                } else {
                    k.clone()
                }
            } else {
                k.clone()
            };

            let dv = if let Value::Integer(i) = v {
                let code: i128 = (*i).into();
                if let Some(s) = self.int_to_val.get(&(code as i64)) {
                    Value::Text(s.clone())
                } else {
                    v.clone()
                }
            } else {
                v.clone()
            };

            (dk, dv)
        }).collect()
    }
}

// =====================================================================
// Encode
// =====================================================================

/// Encode a document + annotation to CBOR-LD-ex bytes.
///
/// The document is a list of (key, value) pairs (CBOR map entries).
/// The annotation is encoded, tagged with Tag(60000), and inserted
/// at key ANNOTATION_TERM_ID.
pub fn encode(
    doc: &[(Value, Value)],
    annotation: &Annotation,
    registry: Option<&ContextRegistry>,
) -> Result<Vec<u8>, CodecError> {
    // Compress document if registry provided
    let data_entries = if let Some(reg) = registry {
        reg.compress(doc)
    } else {
        doc.to_vec()
    };

    // Encode annotation to bytes
    let (ann_buf, ann_len) = encode_annotation(annotation)?;
    let ann_bytes = Value::Bytes(ann_buf[..ann_len].to_vec());
    let ann_tagged = Value::Tag(CBOR_TAG_CBORLD_EX, Box::new(ann_bytes));

    // Build CBOR map: data entries + annotation
    let mut entries = data_entries;
    entries.push((
        Value::Integer((ANNOTATION_TERM_ID as i64).into()),
        ann_tagged,
    ));

    let cbor_map = Value::Map(entries);

    let mut buf = Vec::new();
    ciborium::into_writer(&cbor_map, &mut buf)
        .map_err(|e| CodecError::Cbor(format!("{e}")))?;

    Ok(buf)
}

// =====================================================================
// Decode
// =====================================================================

/// Decode CBOR-LD-ex bytes to a document + annotation.
pub fn decode(
    data: &[u8],
    registry: Option<&ContextRegistry>,
) -> Result<(Vec<(Value, Value)>, Annotation), CodecError> {
    let cbor_val: Value = ciborium::from_reader(data)
        .map_err(|e| CodecError::Cbor(format!("{e}")))?;

    let entries = match cbor_val {
        Value::Map(entries) => entries,
        _ => return Err(CodecError::NotAMap),
    };

    // Find and extract annotation entry
    let ann_key = Value::Integer((ANNOTATION_TERM_ID as i64).into());
    let mut doc_entries = Vec::new();
    let mut ann_value: Option<Value> = None;

    for (k, v) in entries {
        if k == ann_key {
            ann_value = Some(v);
        } else {
            doc_entries.push((k, v));
        }
    }

    let ann_tagged = ann_value.ok_or(CodecError::MissingAnnotation)?;

    // Extract annotation bytes from Tag(60000, bytes)
    let ann_bytes = match ann_tagged {
        Value::Tag(tag_num, inner) => {
            if tag_num != CBOR_TAG_CBORLD_EX {
                return Err(CodecError::WrongTag {
                    expected: CBOR_TAG_CBORLD_EX,
                    got: tag_num,
                });
            }
            match *inner {
                Value::Bytes(b) => b,
                _ => return Err(CodecError::Cbor("Tag content is not bytes".into())),
            }
        }
        _ => return Err(CodecError::Cbor("Annotation is not tagged".into())),
    };

    let annotation = decode_annotation(&ann_bytes)?;

    // Decompress document if registry provided
    let doc = if let Some(reg) = registry {
        reg.decompress(&doc_entries)
    } else {
        doc_entries
    };

    Ok((doc, annotation))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::*;
    use crate::opinion::QuantizedBinomial;

    // =================================================================
    // Helper: build a simple test document
    // =================================================================

    fn sample_doc() -> Vec<(Value, Value)> {
        vec![
            (Value::Text("@type".into()), Value::Text("TemperatureReading".into())),
            (Value::Text("value".into()), Value::Float(22.5)),
            (Value::Text("unit".into()), Value::Text("Celsius".into())),
        ]
    }

    fn sample_annotation() -> Annotation {
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
        }
    }

    fn sample_registry() -> ContextRegistry {
        let mut key_map = BTreeMap::new();
        key_map.insert("@type".into(), 1);
        key_map.insert("value".into(), 2);
        key_map.insert("unit".into(), 3);

        let mut val_map = BTreeMap::new();
        val_map.insert("TemperatureReading".into(), 100);
        val_map.insert("Celsius".into(), 101);

        ContextRegistry::new(key_map, val_map).unwrap()
    }

    // =================================================================
    // ContextRegistry creation
    // =================================================================

    #[test]
    fn test_registry_creation_valid() {
        let reg = sample_registry();
        // Should not panic
        let _ = reg;
    }

    #[test]
    fn test_registry_empty_maps() {
        let reg = ContextRegistry::new(BTreeMap::new(), BTreeMap::new());
        assert!(reg.is_ok());
    }

    #[test]
    fn test_registry_code_collision_across_maps() {
        let mut key_map = BTreeMap::new();
        key_map.insert("@type".into(), 1);

        let mut val_map = BTreeMap::new();
        val_map.insert("SomeValue".into(), 1); // collision with key_map

        assert!(matches!(
            ContextRegistry::new(key_map, val_map),
            Err(CodecError::CodeCollision)
        ));
    }

    #[test]
    fn test_registry_reserved_annotation_term_id() {
        let mut key_map = BTreeMap::new();
        key_map.insert("@annotation".into(), ANNOTATION_TERM_ID as i64);

        assert!(matches!(
            ContextRegistry::new(key_map, BTreeMap::new()),
            Err(CodecError::ReservedCodeUsed)
        ));
    }

    // =================================================================
    // ContextRegistry compress/decompress
    // =================================================================

    #[test]
    fn test_compress_replaces_known_keys_and_values() {
        let reg = sample_registry();
        let doc = sample_doc();
        let compressed = reg.compress(&doc);

        // "@type" → 1, "TemperatureReading" → 100
        assert_eq!(compressed[0].0, Value::Integer(1.into()));
        assert_eq!(compressed[0].1, Value::Integer(100.into()));

        // "value" → 2, 22.5 stays as float (not in value_map)
        assert_eq!(compressed[1].0, Value::Integer(2.into()));
        assert_eq!(compressed[1].1, Value::Float(22.5));

        // "unit" → 3, "Celsius" → 101
        assert_eq!(compressed[2].0, Value::Integer(3.into()));
        assert_eq!(compressed[2].1, Value::Integer(101.into()));
    }

    #[test]
    fn test_decompress_recovers_original() {
        let reg = sample_registry();
        let doc = sample_doc();
        let compressed = reg.compress(&doc);
        let decompressed = reg.decompress(&compressed);

        assert_eq!(decompressed, doc);
    }

    #[test]
    fn test_compress_unknown_keys_pass_through() {
        let reg = sample_registry();
        let doc = vec![
            (Value::Text("unknownKey".into()), Value::Text("unknownVal".into())),
        ];
        let compressed = reg.compress(&doc);
        // Unknown keys/values pass through unchanged
        assert_eq!(compressed[0].0, Value::Text("unknownKey".into()));
        assert_eq!(compressed[0].1, Value::Text("unknownVal".into()));
    }

    // =================================================================
    // Encode — no registry
    // =================================================================

    #[test]
    fn test_encode_without_registry() {
        let doc = sample_doc();
        let ann = sample_annotation();
        let bytes = encode(&doc, &ann, None).unwrap();
        // Should produce valid CBOR
        assert!(!bytes.is_empty());
    }

    // =================================================================
    // Encode/Decode roundtrip — no registry
    // =================================================================

    #[test]
    fn test_roundtrip_no_registry() {
        let doc = sample_doc();
        let ann = sample_annotation();
        let bytes = encode(&doc, &ann, None).unwrap();
        let (decoded_doc, decoded_ann) = decode(&bytes, None).unwrap();
        assert_eq!(decoded_doc, doc);
        assert_eq!(decoded_ann, ann);
    }

    // =================================================================
    // Encode/Decode roundtrip — with registry
    // =================================================================

    #[test]
    fn test_roundtrip_with_registry() {
        let doc = sample_doc();
        let ann = sample_annotation();
        let reg = sample_registry();
        let bytes = encode(&doc, &ann, Some(&reg)).unwrap();
        let (decoded_doc, decoded_ann) = decode(&bytes, Some(&reg)).unwrap();
        assert_eq!(decoded_doc, doc);
        assert_eq!(decoded_ann, ann);
    }

    // =================================================================
    // Compression produces smaller output
    // =================================================================

    #[test]
    fn test_compressed_smaller_than_uncompressed() {
        let doc = sample_doc();
        let ann = sample_annotation();
        let reg = sample_registry();

        let uncompressed = encode(&doc, &ann, None).unwrap();
        let compressed = encode(&doc, &ann, Some(&reg)).unwrap();

        assert!(
            compressed.len() < uncompressed.len(),
            "Compressed {} should be < uncompressed {}",
            compressed.len(), uncompressed.len()
        );
    }

    // =================================================================
    // Annotation tag is Tag(60000)
    // =================================================================

    #[test]
    fn test_annotation_uses_correct_tag() {
        let doc = sample_doc();
        let ann = sample_annotation();
        let bytes = encode(&doc, &ann, None).unwrap();

        // Decode the raw CBOR and inspect the tag
        let raw: Value = ciborium::from_reader(&bytes[..]).unwrap();
        if let Value::Map(entries) = raw {
            let ann_entry = entries.iter().find(|(k, _)| {
                matches!(k, Value::Integer(i) if i128::from(*i) == ANNOTATION_TERM_ID as i128)
            });
            assert!(ann_entry.is_some(), "Annotation key not found");
            let (_, v) = ann_entry.unwrap();
            if let Value::Tag(tag_num, _) = v {
                assert_eq!(*tag_num, CBOR_TAG_CBORLD_EX);
            } else {
                panic!("Annotation value is not a CBOR tag");
            }
        } else {
            panic!("Top-level is not a map");
        }
    }

    // =================================================================
    // Decode error cases
    // =================================================================

    #[test]
    fn test_decode_not_a_map() {
        // Encode a CBOR integer, not a map
        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Integer(42.into()), &mut bytes).unwrap();
        assert!(matches!(decode(&bytes, None), Err(CodecError::NotAMap)));
    }

    #[test]
    fn test_decode_missing_annotation() {
        // Encode a CBOR map with no annotation key
        let map = Value::Map(vec![
            (Value::Text("key".into()), Value::Text("val".into())),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&map, &mut bytes).unwrap();
        assert!(matches!(decode(&bytes, None), Err(CodecError::MissingAnnotation)));
    }

    // =================================================================
    // Roundtrips with different header tiers
    // =================================================================

    #[test]
    fn test_roundtrip_tier2() {
        let doc = sample_doc();
        let ann = Annotation {
            header: Header::Tier2(Tier2Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: true,
                precision_mode: PrecisionMode::Bits8,
                operator_id: OperatorId::CumulativeFusion,
                reasoning_context: 3,
                context_version: 1,
                has_multinomial: false,
                sub_tier_depth: 0,
                source_count: 5,
            }),
            opinion: Some(QuantizedBinomial {
                belief: 217, disbelief: 13, uncertainty: 25, base_rate: 128,
            }),
        };
        let bytes = encode(&doc, &ann, None).unwrap();
        let (decoded_doc, decoded_ann) = decode(&bytes, None).unwrap();
        assert_eq!(decoded_doc, doc);
        assert_eq!(decoded_ann, ann);
    }

    #[test]
    fn test_roundtrip_tier3_no_opinion() {
        let doc = sample_doc();
        let ann = Annotation {
            header: Header::Tier3(Tier3Header {
                compliance_status: ComplianceStatus::Insufficient,
                delegation_flag: true,
                has_opinion: false,
                precision_mode: PrecisionMode::Bits8,
                operator_id: OperatorId::ErasurePropagation,
                reasoning_context: 0,
                has_extended_context: false,
                has_provenance_chain: false,
                has_multinomial: false,
                has_trust_info: false,
                sub_tier_depth: 0,
            }),
            opinion: None,
        };
        let bytes = encode(&doc, &ann, None).unwrap();
        let (decoded_doc, decoded_ann) = decode(&bytes, None).unwrap();
        assert_eq!(decoded_doc, doc);
        assert_eq!(decoded_ann, ann);
    }

    #[test]
    fn test_roundtrip_16bit_opinion() {
        let doc = sample_doc();
        let ann = Annotation {
            header: Header::Tier1(Tier1Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: true,
                precision_mode: PrecisionMode::Bits16,
            }),
            opinion: Some(QuantizedBinomial {
                belief: 55705, disbelief: 3277, uncertainty: 6553, base_rate: 32768,
            }),
        };
        let bytes = encode(&doc, &ann, None).unwrap();
        let (_, decoded_ann) = decode(&bytes, None).unwrap();
        assert_eq!(decoded_ann, ann);
    }

    // =================================================================
    // Empty document
    // =================================================================

    #[test]
    fn test_roundtrip_empty_doc() {
        let doc: Vec<(Value, Value)> = vec![];
        let ann = sample_annotation();
        let bytes = encode(&doc, &ann, None).unwrap();
        let (decoded_doc, decoded_ann) = decode(&bytes, None).unwrap();
        assert!(decoded_doc.is_empty());
        assert_eq!(decoded_ann, ann);
    }

    // =================================================================
    // Various value types in document
    // =================================================================

    #[test]
    fn test_roundtrip_mixed_value_types() {
        let doc = vec![
            (Value::Text("int".into()), Value::Integer(42.into())),
            (Value::Text("float".into()), Value::Float(3.14)),
            (Value::Text("bool".into()), Value::Bool(true)),
            (Value::Text("null".into()), Value::Null),
            (Value::Text("str".into()), Value::Text("hello".into())),
        ];
        let ann = sample_annotation();
        let bytes = encode(&doc, &ann, None).unwrap();
        let (decoded_doc, decoded_ann) = decode(&bytes, None).unwrap();
        assert_eq!(decoded_doc, doc);
        assert_eq!(decoded_ann, ann);
    }
}
