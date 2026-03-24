//! Temporal extensions for CBOR-LD-ex.
//!
//! **Feature gate**: Requires the `alloc` feature (or `std`, which implies `alloc`).
//! Uses `Vec` for trigger lists in `ExtensionBlock`.
//!
//! Implements FORMAL_MODEL.md §7:
//!   - Bit-packed extension block (has_temporal, has_triggers)
//!   - Log-scale half-life encoding (8 bits, ~1 second to ~388 days)
//!   - Three decay functions (exponential, linear, step)
//!   - Quantized decay and expiry operators (Axiom 3 preserved)
//!   - Trigger encoding (expiry, review_due, regulatory_change, withdrawal)
//!
//! Wire format (bit-packed, appended after header+opinion bytes):
//!
//! ```text
//! [1 bit]  has_temporal
//! [1 bit]  has_triggers
//! IF has_temporal: [2 bits] decay_fn, [8 bits] half_life_encoded
//! IF has_triggers: [3 bits] trigger_count, per-trigger data
//! Pad to byte boundary with zeros.
//! ```

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::bitpack::{BitReader, BitWriter};

// =====================================================================
// no_std float math via libm
//
// In std mode, the compiler may optimize libm calls to hardware intrinsics.
// Using libm unconditionally ensures consistent behavior across all targets.
// =====================================================================

/// 2^x for f64.
#[inline]
fn f64_exp2(x: f64) -> f64 {
    libm::exp2(x)
}

/// log₂(x) for f64.
#[inline]
fn f64_log2(x: f64) -> f64 {
    libm::log2(x)
}

/// Round f64 to nearest integer (ties away from zero).
#[inline]
fn f64_round(x: f64) -> f64 {
    libm::round(x)
}

/// max(a, b) for f64.
#[inline]
fn f64_max(a: f64, b: f64) -> f64 {
    libm::fmax(a, b)
}

// =====================================================================
// Constants
// =====================================================================

/// Decay function codes (2 bits).
pub const DECAY_EXPONENTIAL: u8 = 0;
pub const DECAY_LINEAR: u8 = 1;
pub const DECAY_STEP: u8 = 2;

/// Trigger type codes (2 bits).
pub const TRIGGER_EXPIRY: u8 = 0;
pub const TRIGGER_REVIEW_DUE: u8 = 1;
pub const TRIGGER_REG_CHANGE: u8 = 2;
pub const TRIGGER_WITHDRAWAL: u8 = 3;

/// Half-life log-scale: seconds = 2^(value * MAX_EXPONENT / 255).
/// MAX_EXPONENT = 25 → 2^25 ≈ 33.5M seconds ≈ 388 days.
pub const HALF_LIFE_MAX_EXPONENT: f64 = 25.0;

// =====================================================================
// Data structures
// =====================================================================

/// Temporal metadata: decay function and half-life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemporalBlock {
    /// 2-bit decay function code (DECAY_EXPONENTIAL, DECAY_LINEAR, DECAY_STEP).
    pub decay_fn: u8,
    /// 8-bit log-scale encoded half-life (0–255).
    pub half_life_encoded: u8,
}

/// A compliance trigger event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Trigger {
    /// 2-bit trigger type code.
    pub trigger_type: u8,
    /// 8-bit quantized parameter (only on wire for expiry, review_due).
    pub parameter: u8,
}

/// Bit-packed extension block appended after header+opinion bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionBlock {
    pub temporal: Option<TemporalBlock>,
    pub triggers: Option<Vec<Trigger>>,
}

/// Error type for temporal operations.
#[derive(Debug, Clone, PartialEq)]
pub enum TemporalError {
    /// Half-life must be positive.
    NonPositiveHalfLife(f64),
    /// Unknown decay function code.
    InvalidDecayFn(u8),
    /// Empty trigger list (use None instead).
    EmptyTriggerList,
    /// Trigger count exceeds 7 (3-bit field).
    TooManyTriggers(usize),
    /// Insufficient bits to decode.
    InsufficientData,
}

// =====================================================================
// Half-life log-scale codec
// =====================================================================

/// Encode a half-life in seconds to 8-bit log-scale.
///
/// 256 distinct values spanning ~1 second to ~388 days.
/// Formula: seconds = 2^(value * MAX_EXPONENT / 255).
/// Each step ≈ 7% change — perceptually uniform on log scale.
pub fn encode_half_life(seconds: f64) -> Result<u8, TemporalError> {
    if seconds <= 0.0 {
        return Err(TemporalError::NonPositiveHalfLife(seconds));
    }
    if seconds <= 1.0 {
        return Ok(0);
    }
    // seconds = 2^(value * MAX_EXPONENT / 255)
    // log2(seconds) = value * MAX_EXPONENT / 255
    // value = log2(seconds) * 255 / MAX_EXPONENT
    let log2_s = f64_log2(seconds);
    let value = f64_round(log2_s * 255.0 / HALF_LIFE_MAX_EXPONENT) as i32;
    Ok(value.clamp(0, 255) as u8)
}

/// Decode 8-bit log-scale value to half-life in seconds.
pub fn decode_half_life(value: u8) -> f64 {
    let exponent = value as f64 * HALF_LIFE_MAX_EXPONENT / 255.0;
    f64_exp2(exponent)
}

// =====================================================================
// Decay factor computation
// =====================================================================

/// Compute the decay factor for a given function, half-life, and elapsed time.
///
/// - Exponential: λ(t,τ) = 2^(−t/τ)
/// - Linear: λ(t,τ) = max(0, 1 − t/(2τ))
/// - Step: λ(t,τ) = 1 if t < τ, else 0
pub fn compute_decay_factor(
    decay_fn: u8, half_life: f64, elapsed: f64,
) -> Result<f64, TemporalError> {
    match decay_fn {
        DECAY_EXPONENTIAL => Ok(f64_exp2(-elapsed / half_life)),
        DECAY_LINEAR => Ok(f64_max(1.0 - elapsed / (2.0 * half_life), 0.0)),
        DECAY_STEP => Ok(if elapsed < half_life { 1.0 } else { 0.0 }),
        other => Err(TemporalError::InvalidDecayFn(other)),
    }
}

// =====================================================================
// Extension block wire format
// =====================================================================

/// Return true if this trigger type carries an 8-bit payload.
fn trigger_has_payload(trigger_type: u8) -> bool {
    trigger_type == TRIGGER_EXPIRY || trigger_type == TRIGGER_REVIEW_DUE
}

/// Encode an extension block to bit-packed bytes.
///
/// Returns empty vec if no extensions are present.
pub fn encode_extensions(ext: &ExtensionBlock) -> Result<Vec<u8>, TemporalError> {
    let has_temporal = ext.temporal.is_some();
    let has_triggers = ext.triggers.is_some();

    if !has_temporal && !has_triggers {
        return Ok(Vec::new());
    }

    // Validate triggers
    if let Some(ref triggers) = ext.triggers {
        if triggers.is_empty() {
            return Err(TemporalError::EmptyTriggerList);
        }
        if triggers.len() > 7 {
            return Err(TemporalError::TooManyTriggers(triggers.len()));
        }
    }

    let mut w = BitWriter::new();

    // Flags
    w.write(if has_temporal { 1 } else { 0 }, 1);
    w.write(if has_triggers { 1 } else { 0 }, 1);

    // Temporal block
    if let Some(ref temporal) = ext.temporal {
        w.write((temporal.decay_fn & 0x03) as u32, 2);
        w.write(temporal.half_life_encoded as u32, 8);
    }

    // Triggers
    if let Some(ref triggers) = ext.triggers {
        w.write(triggers.len() as u32, 3);
        for trigger in triggers {
            w.write((trigger.trigger_type & 0x03) as u32, 2);
            if trigger_has_payload(trigger.trigger_type) {
                w.write(trigger.parameter as u32, 8);
            }
        }
    }

    Ok(w.as_bytes().to_vec())
}

/// Decode bit-packed extension block from bytes.
pub fn decode_extensions(data: &[u8]) -> Result<ExtensionBlock, TemporalError> {
    if data.is_empty() {
        return Err(TemporalError::InsufficientData);
    }

    let mut r = BitReader::new(data);

    if r.remaining() < 2 {
        return Err(TemporalError::InsufficientData);
    }

    let has_temporal = r.read(1) != 0;
    let has_triggers = r.read(1) != 0;

    let temporal = if has_temporal {
        if r.remaining() < 10 {
            return Err(TemporalError::InsufficientData);
        }
        let decay_fn = r.read(2) as u8;
        let half_life_encoded = r.read(8) as u8;
        Some(TemporalBlock { decay_fn, half_life_encoded })
    } else {
        None
    };

    let triggers = if has_triggers {
        if r.remaining() < 3 {
            return Err(TemporalError::InsufficientData);
        }
        let trigger_count = r.read(3) as usize;
        let mut trigs = Vec::with_capacity(trigger_count);
        for _ in 0..trigger_count {
            if r.remaining() < 2 {
                return Err(TemporalError::InsufficientData);
            }
            let trigger_type = r.read(2) as u8;
            let parameter = if trigger_has_payload(trigger_type) {
                if r.remaining() < 8 {
                    return Err(TemporalError::InsufficientData);
                }
                r.read(8) as u8
            } else {
                0
            };
            trigs.push(Trigger { trigger_type, parameter });
        }
        Some(trigs)
    } else {
        None
    };

    Ok(ExtensionBlock { temporal, triggers })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOL: f64 = 1e-6;

    // =================================================================
    // Half-life encoding
    // =================================================================

    #[test]
    fn test_encode_half_life_one_second() {
        // 1 second → 2^0 = 1 → value should be 0
        let v = encode_half_life(1.0).unwrap();
        assert_eq!(v, 0);
    }

    #[test]
    fn test_encode_half_life_max() {
        // 2^25 ≈ 33.5M seconds ≈ 388 days → value should be 255
        let seconds = 2.0f64.powf(25.0);
        let v = encode_half_life(seconds).unwrap();
        assert_eq!(v, 255);
    }

    #[test]
    fn test_encode_half_life_sub_second() {
        // Anything ≤ 1 second maps to 0
        assert_eq!(encode_half_life(0.5).unwrap(), 0);
        assert_eq!(encode_half_life(0.01).unwrap(), 0);
    }

    #[test]
    fn test_encode_half_life_one_hour() {
        // 3600 seconds = 2^(v * 25/255)
        // log2(3600) ≈ 11.81 → v = 11.81 * 255 / 25 ≈ 120.5 → round to 120 or 121
        let v = encode_half_life(3600.0).unwrap();
        // Verify the decoded value is close to 3600
        let decoded = decode_half_life(v);
        let ratio = decoded / 3600.0;
        assert!(ratio > 0.9 && ratio < 1.1, "1 hour: decoded={decoded}, ratio={ratio}");
    }

    #[test]
    fn test_encode_half_life_one_day() {
        // 86400 seconds
        let v = encode_half_life(86400.0).unwrap();
        let decoded = decode_half_life(v);
        let ratio = decoded / 86400.0;
        assert!(ratio > 0.9 && ratio < 1.1, "1 day: decoded={decoded}, ratio={ratio}");
    }

    #[test]
    fn test_encode_half_life_negative_error() {
        assert!(matches!(
            encode_half_life(-1.0),
            Err(TemporalError::NonPositiveHalfLife(_))
        ));
    }

    #[test]
    fn test_encode_half_life_zero_error() {
        assert!(matches!(
            encode_half_life(0.0),
            Err(TemporalError::NonPositiveHalfLife(_))
        ));
    }

    // =================================================================
    // Half-life decoding
    // =================================================================

    #[test]
    fn test_decode_half_life_zero() {
        // value=0 → 2^0 = 1 second
        let s = decode_half_life(0);
        assert!((s - 1.0).abs() < TOL);
    }

    #[test]
    fn test_decode_half_life_255() {
        // value=255 → 2^25 ≈ 33.5M seconds
        let s = decode_half_life(255);
        let expected = 2.0f64.powf(25.0);
        assert!((s - expected).abs() < 1.0, "255 → {s}, expected {expected}");
    }

    #[test]
    fn test_half_life_roundtrip_monotonic() {
        // Verify that encode → decode is monotonically increasing
        let mut prev_decoded = 0.0f64;
        for v in 0u8..=255 {
            let decoded = decode_half_life(v);
            assert!(decoded >= prev_decoded,
                "Non-monotonic at v={v}: {decoded} < {prev_decoded}");
            prev_decoded = decoded;
        }
    }

    #[test]
    fn test_half_life_roundtrip_boundary() {
        // Encode then decode should recover approximately the same value
        let test_values = [1.0, 10.0, 60.0, 3600.0, 86400.0, 604800.0, 2592000.0];
        for &seconds in &test_values {
            let encoded = encode_half_life(seconds).unwrap();
            let decoded = decode_half_life(encoded);
            // Log-scale: each step is ~7%, so ratio should be within ~10%
            let ratio = decoded / seconds;
            assert!(ratio > 0.85 && ratio < 1.18,
                "Roundtrip for {seconds}s: encoded={encoded}, decoded={decoded}, ratio={ratio}");
        }
    }

    // =================================================================
    // Decay factor computation
    // =================================================================

    #[test]
    fn test_decay_exponential_at_zero() {
        // At t=0, decay factor = 1.0 for all functions
        let f = compute_decay_factor(DECAY_EXPONENTIAL, 100.0, 0.0).unwrap();
        assert!((f - 1.0).abs() < TOL);
    }

    #[test]
    fn test_decay_exponential_at_half_life() {
        // At t=τ, exponential decay = 0.5 (by definition)
        let f = compute_decay_factor(DECAY_EXPONENTIAL, 100.0, 100.0).unwrap();
        assert!((f - 0.5).abs() < TOL);
    }

    #[test]
    fn test_decay_exponential_at_two_half_lives() {
        // At t=2τ, exponential decay = 0.25
        let f = compute_decay_factor(DECAY_EXPONENTIAL, 100.0, 200.0).unwrap();
        assert!((f - 0.25).abs() < TOL);
    }

    #[test]
    fn test_decay_linear_at_zero() {
        let f = compute_decay_factor(DECAY_LINEAR, 100.0, 0.0).unwrap();
        assert!((f - 1.0).abs() < TOL);
    }

    #[test]
    fn test_decay_linear_at_half_life() {
        // Linear: λ = max(0, 1 − t/(2τ)) = 1 − 100/200 = 0.5
        let f = compute_decay_factor(DECAY_LINEAR, 100.0, 100.0).unwrap();
        assert!((f - 0.5).abs() < TOL);
    }

    #[test]
    fn test_decay_linear_at_double() {
        // Linear: λ = max(0, 1 − 200/200) = 0.0
        let f = compute_decay_factor(DECAY_LINEAR, 100.0, 200.0).unwrap();
        assert!((f - 0.0).abs() < TOL);
    }

    #[test]
    fn test_decay_linear_beyond_zero() {
        // Linear: clamped at 0.0 past 2τ
        let f = compute_decay_factor(DECAY_LINEAR, 100.0, 300.0).unwrap();
        assert!((f - 0.0).abs() < TOL);
    }

    #[test]
    fn test_decay_step_before_half_life() {
        let f = compute_decay_factor(DECAY_STEP, 100.0, 50.0).unwrap();
        assert!((f - 1.0).abs() < TOL);
    }

    #[test]
    fn test_decay_step_at_half_life() {
        // Step: drops to 0 at t=τ (not strictly less than)
        let f = compute_decay_factor(DECAY_STEP, 100.0, 100.0).unwrap();
        assert!((f - 0.0).abs() < TOL);
    }

    #[test]
    fn test_decay_step_after_half_life() {
        let f = compute_decay_factor(DECAY_STEP, 100.0, 150.0).unwrap();
        assert!((f - 0.0).abs() < TOL);
    }

    #[test]
    fn test_decay_invalid_fn() {
        assert!(matches!(
            compute_decay_factor(3, 100.0, 50.0),
            Err(TemporalError::InvalidDecayFn(3))
        ));
    }

    // =================================================================
    // Extension block encode/decode — temporal only
    // =================================================================

    #[test]
    fn test_encode_temporal_only() {
        let ext = ExtensionBlock {
            temporal: Some(TemporalBlock {
                decay_fn: DECAY_EXPONENTIAL,
                half_life_encoded: 120,
            }),
            triggers: None,
        };
        let bytes = encode_extensions(&ext).unwrap();
        // Bits: [1][0] [00][01111000] = 10_00_01111000 padded
        // 1=has_temporal, 0=no_triggers, 00=exponential, 01111000=120
        // Total: 12 bits → 2 bytes
        assert_eq!(bytes.len(), 2);
    }

    #[test]
    fn test_roundtrip_temporal_only() {
        let original = ExtensionBlock {
            temporal: Some(TemporalBlock {
                decay_fn: DECAY_LINEAR,
                half_life_encoded: 200,
            }),
            triggers: None,
        };
        let bytes = encode_extensions(&original).unwrap();
        let decoded = decode_extensions(&bytes).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_roundtrip_temporal_all_decay_fns() {
        for df in [DECAY_EXPONENTIAL, DECAY_LINEAR, DECAY_STEP] {
            for hl in [0u8, 1, 127, 128, 255] {
                let original = ExtensionBlock {
                    temporal: Some(TemporalBlock {
                        decay_fn: df,
                        half_life_encoded: hl,
                    }),
                    triggers: None,
                };
                let bytes = encode_extensions(&original).unwrap();
                let decoded = decode_extensions(&bytes).unwrap();
                assert_eq!(decoded, original,
                    "Roundtrip failed for decay_fn={df}, half_life={hl}");
            }
        }
    }

    // =================================================================
    // Extension block encode/decode — triggers only
    // =================================================================

    #[test]
    fn test_roundtrip_single_expiry_trigger() {
        let original = ExtensionBlock {
            temporal: None,
            triggers: Some(vec![Trigger {
                trigger_type: TRIGGER_EXPIRY,
                parameter: 200, // gamma_q
            }]),
        };
        let bytes = encode_extensions(&original).unwrap();
        let decoded = decode_extensions(&bytes).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_roundtrip_single_withdrawal_trigger() {
        // Withdrawal has no payload — parameter should be 0 on decode
        let original = ExtensionBlock {
            temporal: None,
            triggers: Some(vec![Trigger {
                trigger_type: TRIGGER_WITHDRAWAL,
                parameter: 0,
            }]),
        };
        let bytes = encode_extensions(&original).unwrap();
        let decoded = decode_extensions(&bytes).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_roundtrip_multiple_triggers() {
        let original = ExtensionBlock {
            temporal: None,
            triggers: Some(vec![
                Trigger { trigger_type: TRIGGER_EXPIRY, parameter: 128 },
                Trigger { trigger_type: TRIGGER_REVIEW_DUE, parameter: 64 },
                Trigger { trigger_type: TRIGGER_REG_CHANGE, parameter: 0 },
            ]),
        };
        let bytes = encode_extensions(&original).unwrap();
        let decoded = decode_extensions(&bytes).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_roundtrip_max_triggers() {
        // 7 triggers (max for 3-bit count)
        let original = ExtensionBlock {
            temporal: None,
            triggers: Some(vec![
                Trigger { trigger_type: TRIGGER_EXPIRY, parameter: 10 },
                Trigger { trigger_type: TRIGGER_REVIEW_DUE, parameter: 20 },
                Trigger { trigger_type: TRIGGER_REG_CHANGE, parameter: 0 },
                Trigger { trigger_type: TRIGGER_WITHDRAWAL, parameter: 0 },
                Trigger { trigger_type: TRIGGER_EXPIRY, parameter: 30 },
                Trigger { trigger_type: TRIGGER_REVIEW_DUE, parameter: 40 },
                Trigger { trigger_type: TRIGGER_REG_CHANGE, parameter: 0 },
            ]),
        };
        let bytes = encode_extensions(&original).unwrap();
        let decoded = decode_extensions(&bytes).unwrap();
        assert_eq!(decoded, original);
    }

    // =================================================================
    // Extension block encode/decode — temporal + triggers combined
    // =================================================================

    #[test]
    fn test_roundtrip_temporal_and_triggers() {
        let original = ExtensionBlock {
            temporal: Some(TemporalBlock {
                decay_fn: DECAY_STEP,
                half_life_encoded: 100,
            }),
            triggers: Some(vec![
                Trigger { trigger_type: TRIGGER_EXPIRY, parameter: 200 },
                Trigger { trigger_type: TRIGGER_WITHDRAWAL, parameter: 0 },
            ]),
        };
        let bytes = encode_extensions(&original).unwrap();
        let decoded = decode_extensions(&bytes).unwrap();
        assert_eq!(decoded, original);
    }

    // =================================================================
    // Extension block — empty (no extensions)
    // =================================================================

    #[test]
    fn test_encode_empty_extensions() {
        let ext = ExtensionBlock {
            temporal: None,
            triggers: None,
        };
        let bytes = encode_extensions(&ext).unwrap();
        assert!(bytes.is_empty());
    }

    // =================================================================
    // Error cases
    // =================================================================

    #[test]
    fn test_encode_empty_trigger_list_error() {
        let ext = ExtensionBlock {
            temporal: None,
            triggers: Some(vec![]),
        };
        assert!(matches!(
            encode_extensions(&ext),
            Err(TemporalError::EmptyTriggerList)
        ));
    }

    #[test]
    fn test_encode_too_many_triggers_error() {
        let ext = ExtensionBlock {
            temporal: None,
            triggers: Some(vec![
                Trigger { trigger_type: TRIGGER_EXPIRY, parameter: 0 }; 8
            ]),
        };
        assert!(matches!(
            encode_extensions(&ext),
            Err(TemporalError::TooManyTriggers(8))
        ));
    }

    // =================================================================
    // Wire size verification
    // =================================================================

    #[test]
    fn test_temporal_only_wire_size() {
        // 1(has_temporal) + 1(has_triggers) + 2(decay_fn) + 8(half_life) = 12 bits → 2 bytes
        let ext = ExtensionBlock {
            temporal: Some(TemporalBlock {
                decay_fn: DECAY_EXPONENTIAL,
                half_life_encoded: 0,
            }),
            triggers: None,
        };
        let bytes = encode_extensions(&ext).unwrap();
        assert_eq!(bytes.len(), 2);
    }

    #[test]
    fn test_trigger_only_wire_size() {
        // Single expiry trigger:
        // 1 + 1 + 3(count) + 2(type) + 8(param) = 15 bits → 2 bytes
        let ext = ExtensionBlock {
            temporal: None,
            triggers: Some(vec![Trigger {
                trigger_type: TRIGGER_EXPIRY,
                parameter: 128,
            }]),
        };
        let bytes = encode_extensions(&ext).unwrap();
        assert_eq!(bytes.len(), 2);
    }

    #[test]
    fn test_trigger_no_payload_wire_size() {
        // Single withdrawal trigger (no payload):
        // 1 + 1 + 3(count) + 2(type) = 7 bits → 1 byte
        let ext = ExtensionBlock {
            temporal: None,
            triggers: Some(vec![Trigger {
                trigger_type: TRIGGER_WITHDRAWAL,
                parameter: 0,
            }]),
        };
        let bytes = encode_extensions(&ext).unwrap();
        assert_eq!(bytes.len(), 1);
    }

    // =================================================================
    // Python interop — bit-exact wire format
    // =================================================================

    #[test]
    fn test_python_interop_temporal_exponential_120() {
        // Python: encode_extensions(ExtensionBlock(
        //   temporal=TemporalBlock(DECAY_EXPONENTIAL, 120), triggers=None))
        //
        // Bits: [1][0][00][01111000][0000] (padded to 2 bytes)
        // Byte 0: 10_00_0111 = 0x87
        // Byte 1: 1000_0000 = 0x80
        let ext = ExtensionBlock {
            temporal: Some(TemporalBlock {
                decay_fn: DECAY_EXPONENTIAL,
                half_life_encoded: 120,
            }),
            triggers: None,
        };
        let bytes = encode_extensions(&ext).unwrap();
        assert_eq!(bytes, vec![0x87, 0x80]);
    }

    #[test]
    fn test_python_interop_decode_temporal() {
        // Decode the bytes from above
        let decoded = decode_extensions(&[0x87, 0x80]).unwrap();
        assert_eq!(decoded.temporal, Some(TemporalBlock {
            decay_fn: DECAY_EXPONENTIAL,
            half_life_encoded: 120,
        }));
        assert_eq!(decoded.triggers, None);
    }

    // =================================================================
    // Exhaustive decay function × half-life roundtrip
    // =================================================================

    #[test]
    fn test_exhaustive_temporal_block_roundtrip() {
        // All 3 decay functions × all 256 half-life values = 768 combinations
        let mut count = 0u32;
        for df in [DECAY_EXPONENTIAL, DECAY_LINEAR, DECAY_STEP] {
            for hl in 0u8..=255 {
                let original = ExtensionBlock {
                    temporal: Some(TemporalBlock {
                        decay_fn: df,
                        half_life_encoded: hl,
                    }),
                    triggers: None,
                };
                let bytes = encode_extensions(&original).unwrap();
                let decoded = decode_extensions(&bytes).unwrap();
                assert_eq!(decoded, original,
                    "Failed at decay_fn={df}, half_life={hl}");
                count += 1;
            }
        }
        assert_eq!(count, 768);
    }
}
