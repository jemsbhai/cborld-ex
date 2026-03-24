//! Annotation assembly and CBOR tag wrapping for CBOR-LD-ex.
//!
//! Combines headers (§5) and opinion payloads (§4) into complete
//! annotation blocks, and wraps them in CBOR Tag(60000) per §5.3.
//!
//! Wire structure:
//!
//! ```text
//! [header bytes][opinion bytes][extension bytes]
//! ```
//!
//! Extensions are detected by remaining bytes after header + opinion.
//! Zero cost when absent.

use crate::header::{
    Header, HeaderError, PrecisionMode,
    encode_header, decode_header, header_size,
};
use crate::opinion::{
    OpinionError, QuantizedBinomial,
    encode_opinion_bytes, decode_opinion_bytes, opinion_wire_size,
};

// When the `alloc` feature is enabled (implied by `std`), annotations
// can carry temporal extensions (half-life, decay, triggers).
// This import is only available when temporal.rs is compiled.
#[cfg(feature = "alloc")]
use crate::temporal::{ExtensionBlock, TemporalError, encode_extensions, decode_extensions};

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

/// CBOR tag number for CBOR-LD-ex annotations (§5.3).
pub const CBOR_TAG_CBORLD_EX: u64 = 60000;

/// Error type for annotation operations.
#[derive(Debug, Clone, PartialEq)]
pub enum AnnotationError {
    Header(HeaderError),
    Opinion(OpinionError),
    /// has_opinion is true but no opinion payload provided.
    MissingOpinion,
    /// has_opinion is false but opinion payload was provided.
    UnexpectedOpinion,
    /// Temporal extension encoding/decoding error.
    #[cfg(feature = "alloc")]
    Temporal(TemporalError),
}

impl From<HeaderError> for AnnotationError {
    fn from(e: HeaderError) -> Self {
        Self::Header(e)
    }
}

impl From<OpinionError> for AnnotationError {
    fn from(e: OpinionError) -> Self {
        Self::Opinion(e)
    }
}

#[cfg(feature = "alloc")]
impl From<TemporalError> for AnnotationError {
    fn from(e: TemporalError) -> Self {
        Self::Temporal(e)
    }
}

/// A complete CBOR-LD-ex annotation: header + optional opinion + optional extensions.
///
/// Corresponds to Definition 6 (Annotation algebraic type) at the wire level.
///
/// Wire structure: header bytes ‖ opinion bytes ‖ extension bytes
/// Extensions are only available when the `alloc` feature is enabled.
/// On bare `no_std`, annotations carry header + opinion only — sufficient
/// for Tier 1 constrained devices. Edge/cloud devices decode extensions too.
#[derive(Debug, Clone, PartialEq)]
pub struct Annotation {
    pub header: Header,
    pub opinion: Option<QuantizedBinomial>,
    /// Temporal and trigger extensions (§7). Requires `alloc` feature.
    ///
    /// When present, encoded as a bit-packed block appended after the
    /// opinion payload. Decoded by checking for remaining bytes after
    /// header + opinion.
    #[cfg(feature = "alloc")]
    pub extensions: Option<ExtensionBlock>,
}

impl Annotation {
    /// Create an annotation without extensions.
    ///
    /// Works identically across all feature flag configurations.
    /// This is the primary constructor for Tier 1 constrained devices.
    pub fn new(header: Header, opinion: Option<QuantizedBinomial>) -> Self {
        Self {
            header,
            opinion,
            #[cfg(feature = "alloc")]
            extensions: None,
        }
    }

    /// Create an annotation with temporal/trigger extensions.
    ///
    /// Requires the `alloc` feature (or `std`, which implies `alloc`).
    #[cfg(feature = "alloc")]
    pub fn with_extensions(
        header: Header,
        opinion: Option<QuantizedBinomial>,
        extensions: Option<ExtensionBlock>,
    ) -> Self {
        Self { header, opinion, extensions }
    }
}

/// Map PrecisionMode to the integer precision value.
fn precision_value(pm: PrecisionMode) -> u8 {
    match pm {
        PrecisionMode::Bits8 => 8,
        PrecisionMode::Bits16 => 16,
        PrecisionMode::Bits32 => 32,
        PrecisionMode::Reserved => 8, // fallback; shouldn't encode with Reserved
    }
}

/// Extract the has_opinion flag from any header tier.
fn has_opinion(header: &Header) -> bool {
    match header {
        Header::Tier1(h) => h.has_opinion,
        Header::Tier2(h) => h.has_opinion,
        Header::Tier3(h) => h.has_opinion,
    }
}

/// Extract the precision_mode from any header tier.
fn precision_mode(header: &Header) -> PrecisionMode {
    match header {
        Header::Tier1(h) => h.precision_mode,
        Header::Tier2(h) => h.precision_mode,
        Header::Tier3(h) => h.precision_mode,
    }
}

/// Encode the core annotation to bytes: header + opinion.
///
/// Returns a fixed 16-byte stack buffer and the number of significant bytes.
/// Maximum core payload: 4 (Tier 2/3 header) + 12 (32-bit opinion) = 16 bytes.
/// Zero heap allocation. This is the hot path for constrained Tier 1 devices.
///
/// Extensions (temporal, triggers) are encoded separately via
/// `encode_annotation_full` (requires `alloc` feature).
pub fn encode_annotation(ann: &Annotation) -> Result<([u8; 16], usize), AnnotationError> {
    let ho = has_opinion(&ann.header);

    // Validate consistency between header flag and opinion presence
    if ho && ann.opinion.is_none() {
        return Err(AnnotationError::MissingOpinion);
    }
    if !ho && ann.opinion.is_some() {
        return Err(AnnotationError::UnexpectedOpinion);
    }

    let mut buf = [0u8; 16];
    let header_bytes = encode_header(&ann.header);
    let hsize = header_size(&ann.header);
    buf[..hsize].copy_from_slice(&header_bytes[..hsize]);

    let mut offset = hsize;

    if ho {
        let op = ann.opinion.as_ref().unwrap();
        let prec = precision_value(precision_mode(&ann.header));
        // Wire format: transmit (b̂, d̂, â) only. û is derived by decoder.
        let op_buf = encode_opinion_bytes(op.belief, op.disbelief, op.base_rate, prec)?;
        let op_size = opinion_wire_size(prec)?;
        buf[offset..offset + op_size].copy_from_slice(&op_buf[..op_size]);
        offset += op_size;
    }

    Ok((buf, offset))
}

/// Decode the core annotation from bytes: header + opinion.
///
/// Reads the header (dispatching on origin_tier), then reads the
/// opinion payload if has_opinion is set. Extensions are NOT decoded
/// here — use `decode_annotation_full` for that (requires `alloc`).
pub fn decode_annotation(data: &[u8]) -> Result<Annotation, AnnotationError> {
    let hdr = decode_header(data)?;
    let hsize = header_size(&hdr);

    let opinion = if has_opinion(&hdr) {
        let prec = precision_value(precision_mode(&hdr));
        let op_size = opinion_wire_size(prec)?;
        if data.len() < hsize + op_size {
            return Err(AnnotationError::Opinion(OpinionError::InsufficientData {
                expected: op_size,
                got: data.len() - hsize,
            }));
        }
        Some(decode_opinion_bytes(&data[hsize..hsize + op_size], prec)?)
    } else {
        None
    };

    Ok(Annotation::new(hdr, opinion))
}

// =====================================================================
// Full encode/decode — alloc-gated, includes temporal extensions
//
// These functions extend the core encode/decode with extension blocks.
// Wire format: [core bytes][extension bytes] — no framing, no length
// prefix, no wasted bytes. The extension block is self-describing
// (bit-packed flags tell the decoder what follows).
//
// The core prefix is byte-identical to encode_annotation output.
// Callers without extensions should prefer the core path to avoid
// the Vec<u8> heap allocation.
// =====================================================================

/// Encode a complete annotation to bytes: header + opinion + extensions.
///
/// Returns a `Vec<u8>` containing the exact wire bytes — no padding,
/// no framing. The first N bytes are identical to `encode_annotation`
/// output (the core prefix invariant).
///
/// Requires the `alloc` feature (or `std`, which implies `alloc`).
#[cfg(feature = "alloc")]
pub fn encode_annotation_full(ann: &Annotation) -> Result<Vec<u8>, AnnotationError> {
    let (core_buf, core_len) = encode_annotation(ann)?;
    let mut out = Vec::from(&core_buf[..core_len]);

    if let Some(ref ext) = ann.extensions {
        let ext_bytes = encode_extensions(ext)?;
        out.extend_from_slice(&ext_bytes);
    }

    Ok(out)
}

/// Decode a complete annotation from bytes: header + opinion + extensions.
///
/// Reads the core annotation (header + opinion), then decodes any
/// remaining bytes as temporal/trigger extensions. If no bytes remain
/// after the core, extensions is `None` (backward compatible with
/// annotations that predate the extensions field).
///
/// Requires the `alloc` feature (or `std`, which implies `alloc`).
#[cfg(feature = "alloc")]
pub fn decode_annotation_full(data: &[u8]) -> Result<Annotation, AnnotationError> {
    let hdr = decode_header(data)?;
    let hsize = header_size(&hdr);

    let mut consumed = hsize;

    let opinion = if has_opinion(&hdr) {
        let prec = precision_value(precision_mode(&hdr));
        let op_size = opinion_wire_size(prec)?;
        if data.len() < consumed + op_size {
            return Err(AnnotationError::Opinion(OpinionError::InsufficientData {
                expected: op_size,
                got: data.len() - consumed,
            }));
        }
        let op = decode_opinion_bytes(&data[consumed..consumed + op_size], prec)?;
        consumed += op_size;
        Some(op)
    } else {
        None
    };

    let extensions = if data.len() > consumed {
        Some(decode_extensions(&data[consumed..])?)
    } else {
        None
    };

    Ok(Annotation { header: hdr, opinion, extensions })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{
        ComplianceStatus, OperatorId, Tier1Header, Tier2Header, Tier3Header,
    };

    // =================================================================
    // Tier 1 annotation encode — header only (no opinion)
    // =================================================================

    #[test]
    fn test_tier1_no_opinion_encode() {
        let ann = Annotation {
            header: Header::Tier1(Tier1Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: false,
                precision_mode: PrecisionMode::Bits8,
            }),
            opinion: None,
        extensions: None,
        };
        let (buf, len) = encode_annotation(&ann).unwrap();
        assert_eq!(len, 1); // header only
        assert_eq!(buf[0], 0x00); // [00][0][00][0][00]
    }

    // =================================================================
    // Tier 1 annotation encode — header + 8-bit opinion
    // =================================================================

    #[test]
    fn test_tier1_with_opinion_8bit_encode() {
        // Formal model example: compliant, 85% belief
        let ann = Annotation {
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
        };
        let (buf, len) = encode_annotation(&ann).unwrap();
        // 1 byte header + 3 bytes opinion = 4 bytes total
        assert_eq!(len, 4);
        assert_eq!(buf[0], 0x04); // [00][0][00][1][00]
        assert_eq!(buf[1], 217);  // b̂
        assert_eq!(buf[2], 13);   // d̂
        assert_eq!(buf[3], 128);  // â (NOT û — û is derived)
    }

    // =================================================================
    // Tier 1 annotation encode — header + 16-bit opinion
    // =================================================================

    #[test]
    fn test_tier1_with_opinion_16bit_encode() {
        let ann = Annotation {
            header: Header::Tier1(Tier1Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: true,
                precision_mode: PrecisionMode::Bits16,
            }),
            opinion: Some(QuantizedBinomial {
                belief: 55705,
                disbelief: 3277,
                uncertainty: 6553,
                base_rate: 32768,
            }),
        extensions: None,
        };
        let (buf, len) = encode_annotation(&ann).unwrap();
        // 1 byte header + 6 bytes opinion = 7 bytes
        assert_eq!(len, 7);
        assert_eq!(buf[0], 0x05); // [00][0][00][1][01] (precision=16bit)
    }

    // =================================================================
    // Tier 2 annotation encode
    // =================================================================

    #[test]
    fn test_tier2_with_opinion_encode() {
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
                belief: 217,
                disbelief: 13,
                uncertainty: 25,
                base_rate: 128,
            }),
        extensions: None,
        };
        let (buf, len) = encode_annotation(&ann).unwrap();
        // 4 byte header + 3 bytes opinion = 7 bytes
        assert_eq!(len, 7);
        assert_eq!(&buf[..4], &[0x0C, 0x13, 0x10, 0x05]); // header
        assert_eq!(buf[4], 217); // b̂
        assert_eq!(buf[5], 13);  // d̂
        assert_eq!(buf[6], 128); // â
    }

    // =================================================================
    // Tier 3 annotation encode
    // =================================================================

    #[test]
    fn test_tier3_no_opinion_encode() {
        let ann = Annotation {
            header: Header::Tier3(Tier3Header {
                compliance_status: ComplianceStatus::NonCompliant,
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
        extensions: None,
        };
        let (_buf, len) = encode_annotation(&ann).unwrap();
        // 4 byte header, no opinion
        assert_eq!(len, 4);
    }

    // =================================================================
    // Decode roundtrips
    // =================================================================

    #[test]
    fn test_tier1_roundtrip_no_opinion() {
        let original = Annotation {
            header: Header::Tier1(Tier1Header {
                compliance_status: ComplianceStatus::Insufficient,
                delegation_flag: true,
                has_opinion: false,
                precision_mode: PrecisionMode::Bits32,
            }),
            opinion: None,
        extensions: None,
        };
        let (buf, len) = encode_annotation(&original).unwrap();
        let decoded = decode_annotation(&buf[..len]).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_tier1_roundtrip_with_opinion_8bit() {
        let original = Annotation {
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
        };
        let (buf, len) = encode_annotation(&original).unwrap();
        let decoded = decode_annotation(&buf[..len]).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_tier1_roundtrip_with_opinion_16bit() {
        let original = Annotation {
            header: Header::Tier1(Tier1Header {
                compliance_status: ComplianceStatus::NonCompliant,
                delegation_flag: true,
                has_opinion: true,
                precision_mode: PrecisionMode::Bits16,
            }),
            opinion: Some(QuantizedBinomial {
                belief: 55705,
                disbelief: 3277,
                uncertainty: 6553,
                base_rate: 32768,
            }),
        extensions: None,
        };
        let (buf, len) = encode_annotation(&original).unwrap();
        let decoded = decode_annotation(&buf[..len]).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_tier2_roundtrip_with_opinion() {
        let original = Annotation {
            header: Header::Tier2(Tier2Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: true,
                precision_mode: PrecisionMode::Bits8,
                operator_id: OperatorId::ConsentAssessment,
                reasoning_context: 7,
                context_version: 10,
                has_multinomial: true,
                sub_tier_depth: 3,
                source_count: 42,
            }),
            opinion: Some(QuantizedBinomial {
                belief: 200,
                disbelief: 30,
                uncertainty: 25,
                base_rate: 100,
            }),
        extensions: None,
        };
        let (buf, len) = encode_annotation(&original).unwrap();
        let decoded = decode_annotation(&buf[..len]).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_tier3_roundtrip_with_opinion() {
        let original = Annotation {
            header: Header::Tier3(Tier3Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: true,
                precision_mode: PrecisionMode::Bits8,
                operator_id: OperatorId::Deduction,
                reasoning_context: 5,
                has_extended_context: true,
                has_provenance_chain: false,
                has_multinomial: false,
                has_trust_info: true,
                sub_tier_depth: 9,
            }),
            opinion: Some(QuantizedBinomial {
                belief: 150,
                disbelief: 50,
                uncertainty: 55,
                base_rate: 128,
            }),
        extensions: None,
        };
        let (buf, len) = encode_annotation(&original).unwrap();
        let decoded = decode_annotation(&buf[..len]).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_tier3_roundtrip_no_opinion() {
        let original = Annotation {
            header: Header::Tier3(Tier3Header {
                compliance_status: ComplianceStatus::Insufficient,
                delegation_flag: true,
                has_opinion: false,
                precision_mode: PrecisionMode::Bits8,
                operator_id: OperatorId::WithdrawalOverride,
                reasoning_context: 15,
                has_extended_context: true,
                has_provenance_chain: true,
                has_multinomial: true,
                has_trust_info: true,
                sub_tier_depth: 15,
            }),
            opinion: None,
        extensions: None,
        };
        let (buf, len) = encode_annotation(&original).unwrap();
        let decoded = decode_annotation(&buf[..len]).unwrap();
        assert_eq!(decoded, original);
    }

    // =================================================================
    // Error cases
    // =================================================================

    #[test]
    fn test_encode_missing_opinion_error() {
        // has_opinion=true but opinion is None
        let ann = Annotation {
            header: Header::Tier1(Tier1Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: true,
                precision_mode: PrecisionMode::Bits8,
            }),
            opinion: None,
        extensions: None,
        };
        assert_eq!(
            encode_annotation(&ann),
            Err(AnnotationError::MissingOpinion)
        );
    }

    #[test]
    fn test_encode_unexpected_opinion_error() {
        // has_opinion=false but opinion is Some
        let ann = Annotation {
            header: Header::Tier1(Tier1Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: false,
                precision_mode: PrecisionMode::Bits8,
            }),
            opinion: Some(QuantizedBinomial {
                belief: 100, disbelief: 50, uncertainty: 105, base_rate: 128,
            }),
        extensions: None,
        };
        assert_eq!(
            encode_annotation(&ann),
            Err(AnnotationError::UnexpectedOpinion)
        );
    }

    #[test]
    fn test_decode_empty_data() {
        assert!(decode_annotation(&[]).is_err());
    }

    #[test]
    fn test_decode_truncated_opinion() {
        // Valid Tier 1 header with has_opinion=true, but only 2 bytes
        // (needs 1 header + 3 opinion = 4)
        let data = [0x04, 0xD9]; // header ok, opinion truncated
        assert!(decode_annotation(&data).is_err());
    }

    // =================================================================
    // Wire size verification
    // =================================================================

    #[test]
    fn test_annotation_sizes() {
        // Tier 1, no opinion: 1 byte
        let ann = Annotation {
            header: Header::Tier1(Tier1Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: false,
                precision_mode: PrecisionMode::Bits8,
            }),
            opinion: None,
        extensions: None,
        };
        let (_, len) = encode_annotation(&ann).unwrap();
        assert_eq!(len, 1);

        // Tier 1, 8-bit opinion: 4 bytes
        let ann = Annotation {
            header: Header::Tier1(Tier1Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: true,
                precision_mode: PrecisionMode::Bits8,
            }),
            opinion: Some(QuantizedBinomial {
                belief: 200, disbelief: 30, uncertainty: 25, base_rate: 128,
            }),
        extensions: None,
        };
        let (_, len) = encode_annotation(&ann).unwrap();
        assert_eq!(len, 4);

        // Tier 2, 8-bit opinion: 7 bytes
        let ann = Annotation {
            header: Header::Tier2(Tier2Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: true,
                precision_mode: PrecisionMode::Bits8,
                operator_id: OperatorId::None,
                reasoning_context: 0,
                context_version: 0,
                has_multinomial: false,
                sub_tier_depth: 0,
                source_count: 0,
            }),
            opinion: Some(QuantizedBinomial {
                belief: 200, disbelief: 30, uncertainty: 25, base_rate: 128,
            }),
        extensions: None,
        };
        let (_, len) = encode_annotation(&ann).unwrap();
        assert_eq!(len, 7);

        // Tier 2, 16-bit opinion: 10 bytes
        let ann = Annotation {
            header: Header::Tier2(Tier2Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: true,
                precision_mode: PrecisionMode::Bits16,
                operator_id: OperatorId::None,
                reasoning_context: 0,
                context_version: 0,
                has_multinomial: false,
                sub_tier_depth: 0,
                source_count: 0,
            }),
            opinion: Some(QuantizedBinomial {
                belief: 50000, disbelief: 10000, uncertainty: 5535, base_rate: 32768,
            }),
        extensions: None,
        };
        let (_, len) = encode_annotation(&ann).unwrap();
        assert_eq!(len, 10);
    }

    // =================================================================
    // Python interop — byte-exact full annotation encoding
    // =================================================================

    #[test]
    fn test_python_interop_tier1_formal_model() {
        // Python: encode_annotation(Annotation(
        //   header=Tier1Header(COMPLIANT, False, True, BITS_8),
        //   opinion=(217, 13, 25, 128)))
        // → b'\x04\xd9\x0d\x80'
        let ann = Annotation {
            header: Header::Tier1(Tier1Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: true,
                precision_mode: PrecisionMode::Bits8,
            }),
            opinion: Some(QuantizedBinomial {
                belief: 217, disbelief: 13, uncertainty: 25, base_rate: 128,
            }),
        extensions: None,
        };
        let (buf, len) = encode_annotation(&ann).unwrap();
        assert_eq!(&buf[..len], &[0x04, 0xD9, 0x0D, 0x80]);
    }

    #[test]
    fn test_python_interop_tier2_fusion() {
        // Python: encode_annotation(Annotation(
        //   header=Tier2Header(COMPLIANT, False, True, BITS_8,
        //     CUMULATIVE_FUSION, 3, 1, False, 0, 5),
        //   opinion=(217, 13, 25, 128)))
        // → b'\x0c\x13\x10\x05\xd9\x0d\x80'
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
        extensions: None,
        };
        let (buf, len) = encode_annotation(&ann).unwrap();
        assert_eq!(&buf[..len], &[0x0C, 0x13, 0x10, 0x05, 0xD9, 0x0D, 0x80]);
    }

    // =================================================================
    // Exhaustive Tier 1 annotation roundtrip
    //
    // Every valid Tier 1 header × a fixed opinion must roundtrip.
    // =================================================================

    #[test]
    fn test_exhaustive_tier1_annotation_roundtrip() {
        let statuses = [
            ComplianceStatus::Compliant,
            ComplianceStatus::NonCompliant,
            ComplianceStatus::Insufficient,
        ];
        let precisions = [
            PrecisionMode::Bits8,
            PrecisionMode::Bits16,
        ];

        let opinions_8bit = QuantizedBinomial {
            belief: 200, disbelief: 30, uncertainty: 25, base_rate: 128,
        };
        let opinions_16bit = QuantizedBinomial {
            belief: 50000, disbelief: 10000, uncertainty: 5535, base_rate: 32768,
        };

        for &cs in &statuses {
            for &df in &[false, true] {
                // Without opinion
                let ann = Annotation {
                    header: Header::Tier1(Tier1Header {
                        compliance_status: cs,
                        delegation_flag: df,
                        has_opinion: false,
                        precision_mode: PrecisionMode::Bits8,
                    }),
                    opinion: None,
                extensions: None,
                };
                let (buf, len) = encode_annotation(&ann).unwrap();
                let decoded = decode_annotation(&buf[..len]).unwrap();
                assert_eq!(decoded, ann);

                // With opinion at each precision
                for &pm in &precisions {
                    let op = match pm {
                        PrecisionMode::Bits8 => opinions_8bit,
                        PrecisionMode::Bits16 => opinions_16bit,
                        _ => unreachable!(),
                    };
                    let ann = Annotation {
                        header: Header::Tier1(Tier1Header {
                            compliance_status: cs,
                            delegation_flag: df,
                            has_opinion: true,
                            precision_mode: pm,
                        }),
                        opinion: Some(op),
                    extensions: None,
                    };
                    let (buf, len) = encode_annotation(&ann).unwrap();
                    let decoded = decode_annotation(&buf[..len]).unwrap();
                    assert_eq!(decoded, ann,
                        "Roundtrip failed: cs={cs:?} df={df} pm={pm:?}");
                }
            }
        }
    }

    // =================================================================
    // encode_annotation_full / decode_annotation_full (alloc-gated)
    //
    // These tests verify the full encode/decode pipeline including
    // temporal extensions. Wire format:
    //   [core bytes (header+opinion)][extension bytes (bit-packed)]
    // No framing. No length prefix. No wasted bytes.
    // =================================================================

    use crate::temporal::{
        ExtensionBlock, TemporalBlock, Trigger,
        DECAY_EXPONENTIAL, DECAY_LINEAR, DECAY_STEP,
        TRIGGER_EXPIRY, TRIGGER_REVIEW_DUE, TRIGGER_WITHDRAWAL,
    };

    // -----------------------------------------------------------------
    // Property 1: Core prefix invariant
    // First N bytes of encode_annotation_full output MUST be identical
    // to encode_annotation output. The full encoder must not alter
    // the core wire format.
    // -----------------------------------------------------------------

    #[test]
    fn test_full_encode_core_prefix_matches_core_encode() {
        let ann = Annotation::with_extensions(
            Header::Tier1(Tier1Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: true,
                precision_mode: PrecisionMode::Bits8,
            }),
            Some(QuantizedBinomial {
                belief: 217, disbelief: 13, uncertainty: 25, base_rate: 128,
            }),
            Some(ExtensionBlock {
                temporal: Some(TemporalBlock {
                    decay_fn: DECAY_EXPONENTIAL,
                    half_life_encoded: 120,
                }),
                triggers: None,
            }),
        );

        let (core_buf, core_len) = encode_annotation(&ann).unwrap();
        let full_bytes = encode_annotation_full(&ann).unwrap();

        // First core_len bytes must be identical
        assert_eq!(
            &full_bytes[..core_len], &core_buf[..core_len],
            "Core prefix mismatch: full encoder altered the core wire format"
        );
        // Full output must be strictly longer (extensions present)
        assert!(
            full_bytes.len() > core_len,
            "Full output should be longer than core when extensions present"
        );
    }

    // -----------------------------------------------------------------
    // Property 2: No-extensions equivalence
    // encode_annotation_full with extensions: None produces identical
    // bytes to encode_annotation.
    // -----------------------------------------------------------------

    #[test]
    fn test_full_encode_no_extensions_equals_core() {
        let ann = Annotation::new(
            Header::Tier1(Tier1Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: true,
                precision_mode: PrecisionMode::Bits8,
            }),
            Some(QuantizedBinomial {
                belief: 217, disbelief: 13, uncertainty: 25, base_rate: 128,
            }),
        );

        let (core_buf, core_len) = encode_annotation(&ann).unwrap();
        let full_bytes = encode_annotation_full(&ann).unwrap();

        assert_eq!(
            full_bytes, &core_buf[..core_len],
            "No-extensions full encode must be byte-identical to core encode"
        );
    }

    // -----------------------------------------------------------------
    // Property 3: Roundtrip with temporal only
    // -----------------------------------------------------------------

    #[test]
    fn test_full_roundtrip_temporal_only() {
        let original = Annotation::with_extensions(
            Header::Tier1(Tier1Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: true,
                precision_mode: PrecisionMode::Bits8,
            }),
            Some(QuantizedBinomial {
                belief: 217, disbelief: 13, uncertainty: 25, base_rate: 128,
            }),
            Some(ExtensionBlock {
                temporal: Some(TemporalBlock {
                    decay_fn: DECAY_EXPONENTIAL,
                    half_life_encoded: 120,
                }),
                triggers: None,
            }),
        );

        let bytes = encode_annotation_full(&original).unwrap();
        let decoded = decode_annotation_full(&bytes).unwrap();
        assert_eq!(decoded, original);
    }

    // -----------------------------------------------------------------
    // Property 4: Roundtrip with triggers only
    // -----------------------------------------------------------------

    #[test]
    fn test_full_roundtrip_triggers_only() {
        let original = Annotation::with_extensions(
            Header::Tier2(Tier2Header {
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
            Some(QuantizedBinomial {
                belief: 200, disbelief: 30, uncertainty: 25, base_rate: 128,
            }),
            Some(ExtensionBlock {
                temporal: None,
                triggers: Some(vec![
                    Trigger { trigger_type: TRIGGER_EXPIRY, parameter: 200 },
                    Trigger { trigger_type: TRIGGER_WITHDRAWAL, parameter: 0 },
                ]),
            }),
        );

        let bytes = encode_annotation_full(&original).unwrap();
        let decoded = decode_annotation_full(&bytes).unwrap();
        assert_eq!(decoded, original);
    }

    // -----------------------------------------------------------------
    // Property 5: Roundtrip with temporal + triggers combined
    // -----------------------------------------------------------------

    #[test]
    fn test_full_roundtrip_temporal_and_triggers() {
        let original = Annotation::with_extensions(
            Header::Tier1(Tier1Header {
                compliance_status: ComplianceStatus::NonCompliant,
                delegation_flag: true,
                has_opinion: true,
                precision_mode: PrecisionMode::Bits8,
            }),
            Some(QuantizedBinomial {
                belief: 150, disbelief: 50, uncertainty: 55, base_rate: 128,
            }),
            Some(ExtensionBlock {
                temporal: Some(TemporalBlock {
                    decay_fn: DECAY_STEP,
                    half_life_encoded: 200,
                }),
                triggers: Some(vec![
                    Trigger { trigger_type: TRIGGER_EXPIRY, parameter: 128 },
                    Trigger { trigger_type: TRIGGER_REVIEW_DUE, parameter: 64 },
                ]),
            }),
        );

        let bytes = encode_annotation_full(&original).unwrap();
        let decoded = decode_annotation_full(&bytes).unwrap();
        assert_eq!(decoded, original);
    }

    // -----------------------------------------------------------------
    // Property 6: Backward compatibility
    // decode_annotation_full on core-only bytes (no extension bytes)
    // must produce extensions: None.
    // -----------------------------------------------------------------

    #[test]
    fn test_full_decode_core_only_bytes_gives_no_extensions() {
        let ann = Annotation::new(
            Header::Tier1(Tier1Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: true,
                precision_mode: PrecisionMode::Bits8,
            }),
            Some(QuantizedBinomial {
                belief: 217, disbelief: 13, uncertainty: 25, base_rate: 128,
            }),
        );

        // Encode with core encoder (no extensions on wire)
        let (core_buf, core_len) = encode_annotation(&ann).unwrap();

        // Decode with full decoder
        let decoded = decode_annotation_full(&core_buf[..core_len]).unwrap();

        assert_eq!(decoded.header, ann.header);
        assert_eq!(decoded.opinion, ann.opinion);
        assert_eq!(decoded.extensions, None,
            "Decoding core-only bytes must produce extensions: None");
    }

    // -----------------------------------------------------------------
    // Property 7: Exact wire sizes — every bit accounted for
    // -----------------------------------------------------------------

    #[test]
    fn test_full_wire_size_tier1_8bit_temporal_only() {
        // Core: 1 (header) + 3 (opinion) = 4 bytes
        // Extension: 1(ht) + 1(htr) + 2(decay_fn) + 8(half_life) = 12 bits → 2 bytes
        // Total: 6 bytes
        let ann = Annotation::with_extensions(
            Header::Tier1(Tier1Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: true,
                precision_mode: PrecisionMode::Bits8,
            }),
            Some(QuantizedBinomial {
                belief: 217, disbelief: 13, uncertainty: 25, base_rate: 128,
            }),
            Some(ExtensionBlock {
                temporal: Some(TemporalBlock {
                    decay_fn: DECAY_EXPONENTIAL,
                    half_life_encoded: 120,
                }),
                triggers: None,
            }),
        );

        let bytes = encode_annotation_full(&ann).unwrap();
        assert_eq!(bytes.len(), 6,
            "Tier1 + 8bit opinion + temporal = 4 core + 2 ext = 6 bytes");
    }

    #[test]
    fn test_full_wire_size_no_opinion_temporal_only() {
        // Core: 1 (header, no opinion) = 1 byte
        // Extension: 12 bits → 2 bytes
        // Total: 3 bytes
        let ann = Annotation::with_extensions(
            Header::Tier1(Tier1Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: false,
                precision_mode: PrecisionMode::Bits8,
            }),
            None,
            Some(ExtensionBlock {
                temporal: Some(TemporalBlock {
                    decay_fn: DECAY_LINEAR,
                    half_life_encoded: 255,
                }),
                triggers: None,
            }),
        );

        let bytes = encode_annotation_full(&ann).unwrap();
        assert_eq!(bytes.len(), 3,
            "Tier1 header-only + temporal = 1 core + 2 ext = 3 bytes");
    }

    #[test]
    fn test_full_wire_size_tier1_8bit_temporal_plus_triggers() {
        // Core: 4 bytes (Tier1 + 8-bit opinion)
        // Extension:
        //   1(ht) + 1(htr) + 2(decay) + 8(hl) = 12 bits temporal
        //   3(count) + [2(type)+8(param)] + [2(type)] = 15 bits triggers
        //   12 + 15 = 27 bits → 4 bytes (ceil(27/8) = 4, padded with 5 zero bits)
        // Total: 4 + 4 = 8 bytes
        let ann = Annotation::with_extensions(
            Header::Tier1(Tier1Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: true,
                precision_mode: PrecisionMode::Bits8,
            }),
            Some(QuantizedBinomial {
                belief: 217, disbelief: 13, uncertainty: 25, base_rate: 128,
            }),
            Some(ExtensionBlock {
                temporal: Some(TemporalBlock {
                    decay_fn: DECAY_EXPONENTIAL,
                    half_life_encoded: 120,
                }),
                triggers: Some(vec![
                    Trigger { trigger_type: TRIGGER_EXPIRY, parameter: 200 },
                    Trigger { trigger_type: TRIGGER_WITHDRAWAL, parameter: 0 },
                ]),
            }),
        );

        let bytes = encode_annotation_full(&ann).unwrap();
        assert_eq!(bytes.len(), 8,
            "Tier1 + 8bit opinion + temporal + 2 triggers = 4 + 4 = 8 bytes");
    }

    // -----------------------------------------------------------------
    // Roundtrip across all decay functions
    // -----------------------------------------------------------------

    #[test]
    fn test_full_roundtrip_all_decay_fns() {
        for df in [DECAY_EXPONENTIAL, DECAY_LINEAR, DECAY_STEP] {
            let original = Annotation::with_extensions(
                Header::Tier1(Tier1Header {
                    compliance_status: ComplianceStatus::Compliant,
                    delegation_flag: false,
                    has_opinion: true,
                    precision_mode: PrecisionMode::Bits8,
                }),
                Some(QuantizedBinomial {
                    belief: 200, disbelief: 30, uncertainty: 25, base_rate: 128,
                }),
                Some(ExtensionBlock {
                    temporal: Some(TemporalBlock {
                        decay_fn: df,
                        half_life_encoded: 100,
                    }),
                    triggers: None,
                }),
            );

            let bytes = encode_annotation_full(&original).unwrap();
            let decoded = decode_annotation_full(&bytes).unwrap();
            assert_eq!(decoded, original,
                "Full roundtrip failed for decay_fn={df}");
        }
    }

    // -----------------------------------------------------------------
    // Roundtrip: Tier 2 with 16-bit opinion + extensions
    // Verify extensions work with all header tiers and precisions
    // -----------------------------------------------------------------

    #[test]
    fn test_full_roundtrip_tier2_16bit_with_extensions() {
        let original = Annotation::with_extensions(
            Header::Tier2(Tier2Header {
                compliance_status: ComplianceStatus::Compliant,
                delegation_flag: false,
                has_opinion: true,
                precision_mode: PrecisionMode::Bits16,
                operator_id: OperatorId::TemporalDecay,
                reasoning_context: 5,
                context_version: 2,
                has_multinomial: false,
                sub_tier_depth: 0,
                source_count: 3,
            }),
            Some(QuantizedBinomial {
                belief: 55705, disbelief: 3277, uncertainty: 6553, base_rate: 32768,
            }),
            Some(ExtensionBlock {
                temporal: Some(TemporalBlock {
                    decay_fn: DECAY_EXPONENTIAL,
                    half_life_encoded: 120,
                }),
                triggers: Some(vec![
                    Trigger { trigger_type: TRIGGER_REVIEW_DUE, parameter: 90 },
                ]),
            }),
        );

        let (core_buf, core_len) = encode_annotation(&original).unwrap();
        assert_eq!(core_len, 10, "Tier2 + 16-bit opinion = 4 + 6 = 10 bytes core");

        let full_bytes = encode_annotation_full(&original).unwrap();
        assert_eq!(&full_bytes[..core_len], &core_buf[..core_len],
            "Core prefix must be preserved");

        let decoded = decode_annotation_full(&full_bytes).unwrap();
        assert_eq!(decoded, original);
    }
}
