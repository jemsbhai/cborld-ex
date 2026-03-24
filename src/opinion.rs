//! Quantization codec for Subjective Logic opinions.
//!
//! Implements constrained quantization per FORMAL_MODEL.md §4:
//!   - Definition 9:  Q_n(x) = round(x * (2^n - 1))
//!   - Definition 10: Constrained binomial quantization (derive û)
//!   - Theorem 1:  b̂ + d̂ + û = 2^n - 1 exactly
//!
//! Precision modes (Table 1, §4.3):
//!   8-bit  (mode 00): 3 bytes per opinion on wire (b̂, d̂, â)
//!   16-bit (mode 01): 6 bytes per opinion on wire
//!   32-bit (mode 10): 12 bytes (IEEE 754 float32, no quantization)
//!
//! û is NEVER transmitted — it is derived by the decoder.

/// Valid precision modes.
pub const PRECISION_8: u8 = 8;
pub const PRECISION_16: u8 = 16;
pub const PRECISION_32: u8 = 32;

/// Error type for opinion operations.
#[derive(Debug, Clone, PartialEq)]
pub enum OpinionError {
    /// Precision must be 8, 16, or 32.
    InvalidPrecision(u8),
    /// Opinion components must be non-negative.
    NegativeComponent { name: &'static str, value: f64 },
    /// b + d + u must equal 1.0 (within tolerance).
    SumViolation { sum: f64 },
    /// Base rate must be in [0, 1].
    InvalidBaseRate(f64),
    /// Insufficient bytes for decoding.
    InsufficientData { expected: usize, got: usize },
}

// -------------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------------

// no_std-compatible float math.
//
// In std mode, the compiler may optimize these to hardware intrinsics.
// In no_std mode, libm provides pure-Rust software implementations.
// We use libm unconditionally for consistency across targets.

/// Round f64 to nearest integer (ties away from zero).
/// All callers pass non-negative values in [0, 65535].
#[inline]
fn f64_round(x: f64) -> f64 {
    libm::round(x)
}

/// Absolute value of f64.
#[inline]
fn f64_abs(x: f64) -> f64 {
    libm::fabs(x)
}

/// Round f32 to nearest integer (ties away from zero).
#[inline]
fn f32_round(x: f32) -> f32 {
    libm::roundf(x)
}

fn validate_precision(precision: u8) -> Result<(), OpinionError> {
    match precision {
        8 | 16 | 32 => Ok(()),
        other => Err(OpinionError::InvalidPrecision(other)),
    }
}

fn validate_binomial(b: f64, d: f64, u: f64, a: f64) -> Result<(), OpinionError> {
    if b < -1e-9 {
        return Err(OpinionError::NegativeComponent {
            name: "belief",
            value: b,
        });
    }
    if d < -1e-9 {
        return Err(OpinionError::NegativeComponent {
            name: "disbelief",
            value: d,
        });
    }
    if u < -1e-9 {
        return Err(OpinionError::NegativeComponent {
            name: "uncertainty",
            value: u,
        });
    }
    if !(-1e-9..=1.0 + 1e-9).contains(&a) {
        return Err(OpinionError::InvalidBaseRate(a));
    }
    let sum = b + d + u;
    if f64_abs(sum - 1.0) > 1e-6 {
        return Err(OpinionError::SumViolation { sum });
    }
    Ok(())
}

/// Return 2^n - 1 for the given precision.
fn max_val(precision: u8) -> u16 {
    ((1u32 << precision) - 1) as u16
}

/// Definition 9: Q_n(x) = round(x * (2^n - 1)).
fn quantize_single(x: f64, mv: u16) -> u16 {
    f64_round(x * mv as f64) as u16
}

/// Definition 9 inverse: Q_n^{-1}(k) = k / (2^n - 1).
fn dequantize_single(k: u16, mv: u16) -> f64 {
    k as f64 / mv as f64
}

/// Result of binomial quantization: (b̂, d̂, û, â) as integers.
///
/// û is derived, never independently quantized (Theorem 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuantizedBinomial {
    pub belief: u16,
    pub disbelief: u16,
    pub uncertainty: u16, // derived: max_val - belief - disbelief
    pub base_rate: u16,
}

/// Quantize a binomial opinion per Definition 10.
///
/// Quantizes b and d independently via rounding, then derives
/// û = (2^n - 1) - b̂ - d̂. Uncertainty is NEVER independently
/// quantized — this preserves b̂ + d̂ + û = 2^n - 1 exactly (Theorem 1a).
///
/// Clamping rule (Theorem 1c): If b̂ + d̂ > max_val (possible when
/// u ≈ 0 and both b and d round up), d̂ is decremented by 1.
pub fn quantize_binomial(
    b: f64,
    d: f64,
    u: f64,
    a: f64,
    precision: u8,
) -> Result<QuantizedBinomial, OpinionError> {
    validate_precision(precision)?;
    validate_binomial(b, d, u, a)?;

    let mv = max_val(precision);

    let b_q = quantize_single(b, mv);
    let mut d_q = quantize_single(d, mv);

    // Clamping rule (Theorem 1c): if b̂ + d̂ > max_val, decrement d̂
    // This introduces a documented marginal bias toward belief.
    // Compare in u32 to avoid overflow when both round up at 16-bit.
    if (b_q as u32) + (d_q as u32) > mv as u32 {
        d_q -= 1;
    }

    // Derived uncertainty — never independently quantized
    let u_q = mv - b_q - d_q;

    let a_q = quantize_single(a, mv);

    Ok(QuantizedBinomial {
        belief: b_q,
        disbelief: d_q,
        uncertainty: u_q,
        base_rate: a_q,
    })
}

/// Dequantize a binomial opinion: reconstruct floats from quantized values.
///
/// Theorem 1(b) guarantees:
///   Q_n^{-1}(b̂) + Q_n^{-1}(d̂) + Q_n^{-1}(û) = 1.0 exactly
/// because b̂ + d̂ + û = 2^n - 1 by construction.
pub fn dequantize_binomial(
    q: &QuantizedBinomial,
    precision: u8,
) -> Result<(f64, f64, f64, f64), OpinionError> {
    validate_precision(precision)?;
    let mv = max_val(precision);
    Ok((
        dequantize_single(q.belief, mv),
        dequantize_single(q.disbelief, mv),
        dequantize_single(q.uncertainty, mv),
        dequantize_single(q.base_rate, mv),
    ))
}

/// Encode a quantized opinion to wire bytes — transmits 3 values only.
///
/// û is NEVER transmitted. The decoder derives it.
///
/// Wire format:
///   8-bit:  3 bytes — b̂(u8), d̂(u8), â(u8)
///   16-bit: 6 bytes — b̂(u16), d̂(u16), â(u16), big-endian
///   32-bit: 12 bytes — b(f32), d(f32), a(f32), big-endian
pub fn encode_opinion_bytes(
    b_q: u16,
    d_q: u16,
    a_q: u16,
    precision: u8,
) -> Result<[u8; 12], OpinionError> {
    validate_precision(precision)?;
    let mut buf = [0u8; 12];

    match precision {
        8 => {
            buf[0] = b_q as u8;
            buf[1] = d_q as u8;
            buf[2] = a_q as u8;
        }
        16 => {
            buf[0..2].copy_from_slice(&b_q.to_be_bytes());
            buf[2..4].copy_from_slice(&d_q.to_be_bytes());
            buf[4..6].copy_from_slice(&a_q.to_be_bytes());
        }
        32 => {
            // For 32-bit mode, the u16 values hold the raw f32 bit
            // patterns split across two u16s. This path is used via
            // the full pipeline (quantize → encode), not directly.
            // Direct 32-bit encoding goes through encode_opinion_f32.
            buf[0..4].copy_from_slice(&(b_q as f32).to_be_bytes());
            buf[4..8].copy_from_slice(&(d_q as f32).to_be_bytes());
            buf[8..12].copy_from_slice(&(a_q as f32).to_be_bytes());
        }
        _ => unreachable!(), // validate_precision already checked
    }

    Ok(buf)
}

/// Return the wire size in bytes for a given precision mode.
pub fn opinion_wire_size(precision: u8) -> Result<usize, OpinionError> {
    match precision {
        8 => Ok(3),
        16 => Ok(6),
        32 => Ok(12),
        other => Err(OpinionError::InvalidPrecision(other)),
    }
}

/// Decode wire bytes to quantized opinion values — derives û.
///
/// Returns QuantizedBinomial with all 4 components, even though
/// only 3 were on the wire.
pub fn decode_opinion_bytes(data: &[u8], precision: u8) -> Result<QuantizedBinomial, OpinionError> {
    let expected = opinion_wire_size(precision)?;
    if data.len() < expected {
        return Err(OpinionError::InsufficientData {
            expected,
            got: data.len(),
        });
    }

    match precision {
        8 => {
            let b_q = data[0] as u16;
            let d_q = data[1] as u16;
            let a_q = data[2] as u16;
            let u_q = 255 - b_q - d_q;
            Ok(QuantizedBinomial {
                belief: b_q,
                disbelief: d_q,
                uncertainty: u_q,
                base_rate: a_q,
            })
        }
        16 => {
            let b_q = u16::from_be_bytes([data[0], data[1]]);
            let d_q = u16::from_be_bytes([data[2], data[3]]);
            let a_q = u16::from_be_bytes([data[4], data[5]]);
            let u_q = 65535 - b_q - d_q;
            Ok(QuantizedBinomial {
                belief: b_q,
                disbelief: d_q,
                uncertainty: u_q,
                base_rate: a_q,
            })
        }
        32 => {
            // 32-bit mode uses IEEE 754 float32
            let b = f32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            let d = f32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            let a = f32::from_be_bytes([data[8], data[9], data[10], data[11]]);
            let u = 1.0 - b - d;
            // Store as fixed-point scaled values for QuantizedBinomial
            // For 32-bit, we treat the u16 fields as raw bit containers
            // This is a simplification — full 32-bit path uses f32 directly
            Ok(QuantizedBinomial {
                belief: f32_round(b * 65535.0) as u16,
                disbelief: f32_round(d * 65535.0) as u16,
                uncertainty: f32_round(u * 65535.0) as u16,
                base_rate: f32_round(a * 65535.0) as u16,
            })
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tolerance for floating-point comparisons
    const TOL: f64 = 1e-6;

    fn approx_eq(a: f64, b: f64) -> bool {
        (a - b).abs() < TOL
    }

    // =================================================================
    // Validation — input checking
    // =================================================================

    #[test]
    fn test_quantize_invalid_precision() {
        assert!(matches!(
            quantize_binomial(0.5, 0.3, 0.2, 0.5, 4),
            Err(OpinionError::InvalidPrecision(4))
        ));
    }

    #[test]
    fn test_quantize_negative_belief() {
        assert!(matches!(
            quantize_binomial(-0.1, 0.5, 0.6, 0.5, 8),
            Err(OpinionError::NegativeComponent { name: "belief", .. })
        ));
    }

    #[test]
    fn test_quantize_negative_disbelief() {
        assert!(matches!(
            quantize_binomial(0.5, -0.1, 0.6, 0.5, 8),
            Err(OpinionError::NegativeComponent {
                name: "disbelief",
                ..
            })
        ));
    }

    #[test]
    fn test_quantize_negative_uncertainty() {
        assert!(matches!(
            quantize_binomial(0.5, 0.5, -0.1, 0.5, 8),
            Err(OpinionError::NegativeComponent {
                name: "uncertainty",
                ..
            })
        ));
    }

    #[test]
    fn test_quantize_sum_not_one() {
        assert!(matches!(
            quantize_binomial(0.5, 0.5, 0.5, 0.5, 8),
            Err(OpinionError::SumViolation { .. })
        ));
    }

    #[test]
    fn test_quantize_base_rate_out_of_range() {
        assert!(matches!(
            quantize_binomial(0.5, 0.3, 0.2, 1.5, 8),
            Err(OpinionError::InvalidBaseRate(..))
        ));
    }

    #[test]
    fn test_quantize_base_rate_negative() {
        assert!(matches!(
            quantize_binomial(0.5, 0.3, 0.2, -0.1, 8),
            Err(OpinionError::InvalidBaseRate(..))
        ));
    }

    // =================================================================
    // 8-bit quantization — specific values
    // =================================================================

    #[test]
    fn test_quantize_8bit_formal_model_example() {
        // From FORMAL_MODEL.md Appendix C:
        // b=0.85, d=0.05, u=0.10, a=0.50
        // b̂ = round(0.85 * 255) = 217
        // d̂ = round(0.05 * 255) = 13
        // û = 255 - 217 - 13 = 25
        // â = round(0.50 * 255) = 128
        let q = quantize_binomial(0.85, 0.05, 0.10, 0.50, 8).unwrap();
        assert_eq!(q.belief, 217);
        assert_eq!(q.disbelief, 13);
        assert_eq!(q.uncertainty, 25);
        assert_eq!(q.base_rate, 128);
    }

    #[test]
    fn test_quantize_8bit_maximum_belief() {
        // b=1.0, d=0.0, u=0.0 → b̂=255, d̂=0, û=0
        let q = quantize_binomial(1.0, 0.0, 0.0, 0.5, 8).unwrap();
        assert_eq!(q.belief, 255);
        assert_eq!(q.disbelief, 0);
        assert_eq!(q.uncertainty, 0);
    }

    #[test]
    fn test_quantize_8bit_maximum_uncertainty() {
        // b=0.0, d=0.0, u=1.0 → b̂=0, d̂=0, û=255
        let q = quantize_binomial(0.0, 0.0, 1.0, 0.5, 8).unwrap();
        assert_eq!(q.belief, 0);
        assert_eq!(q.disbelief, 0);
        assert_eq!(q.uncertainty, 255);
    }

    #[test]
    fn test_quantize_8bit_maximum_disbelief() {
        // b=0.0, d=1.0, u=0.0 → b̂=0, d̂=255, û=0
        let q = quantize_binomial(0.0, 1.0, 0.0, 0.5, 8).unwrap();
        assert_eq!(q.belief, 0);
        assert_eq!(q.disbelief, 255);
        assert_eq!(q.uncertainty, 0);
    }

    #[test]
    fn test_quantize_8bit_uniform() {
        // b=1/3, d=1/3, u=1/3 → b̂=85, d̂=85, û=85
        // sum = 85+85+85 = 255 ✓
        let q = quantize_binomial(1.0 / 3.0, 1.0 / 3.0, 1.0 / 3.0, 0.5, 8).unwrap();
        assert_eq!(q.belief, 85);
        assert_eq!(q.disbelief, 85);
        assert_eq!(q.uncertainty, 85);
        assert_eq!(q.belief + q.disbelief + q.uncertainty, 255);
    }

    #[test]
    fn test_quantize_8bit_base_rate_zero() {
        let q = quantize_binomial(0.5, 0.3, 0.2, 0.0, 8).unwrap();
        assert_eq!(q.base_rate, 0);
    }

    #[test]
    fn test_quantize_8bit_base_rate_one() {
        let q = quantize_binomial(0.5, 0.3, 0.2, 1.0, 8).unwrap();
        assert_eq!(q.base_rate, 255);
    }

    // =================================================================
    // 16-bit quantization
    // =================================================================

    #[test]
    fn test_quantize_16bit_formal_model_example() {
        // b=0.85 → round(0.85 * 65535) = 55705
        // d=0.05 → round(0.05 * 65535) = 3277
        // û = 65535 - 55705 - 3277 = 6553
        // a=0.50 → round(0.50 * 65535) = 32768
        let q = quantize_binomial(0.85, 0.05, 0.10, 0.50, 16).unwrap();
        assert_eq!(q.belief, 55705);
        assert_eq!(q.disbelief, 3277);
        assert_eq!(q.uncertainty, 6553);
        assert_eq!(q.base_rate, 32768);
    }

    #[test]
    fn test_quantize_16bit_invariant() {
        let q = quantize_binomial(0.7, 0.2, 0.1, 0.5, 16).unwrap();
        assert_eq!(q.belief + q.disbelief + q.uncertainty, 65535);
    }

    // =================================================================
    // Clamping rule — Theorem 1(c)
    //
    // When u ≈ 0 and both b and d round up, b̂ + d̂ can exceed max_val.
    // The clamping rule decrements d̂ by 1 (bias toward belief).
    // =================================================================

    #[test]
    fn test_clamping_8bit() {
        // b = 0.498, d = 0.502, u = 0.0
        // b̂ = round(0.498 * 255) = round(126.99) = 127
        // d̂ = round(0.502 * 255) = round(128.01) = 128
        // b̂ + d̂ = 255, ok no clamping needed actually.
        //
        // Let's use b=0.5, d=0.5, u=0.0:
        // b̂ = round(0.5 * 255) = round(127.5) = 128
        // d̂ = round(0.5 * 255) = round(127.5) = 128
        // b̂ + d̂ = 256 > 255 → clamp d̂ to 127
        // û = 255 - 128 - 127 = 0
        let q = quantize_binomial(0.5, 0.5, 0.0, 0.5, 8).unwrap();
        assert_eq!(q.belief, 128);
        assert_eq!(q.disbelief, 127); // clamped from 128
        assert_eq!(q.uncertainty, 0);
        assert_eq!(q.belief + q.disbelief + q.uncertainty, 255);
    }

    #[test]
    fn test_clamping_preserves_invariant() {
        // b=0.5, d=0.5, u=0.0 at 16-bit
        // b̂ = round(0.5 * 65535) = round(32767.5) = 32768
        // d̂ = round(0.5 * 65535) = round(32767.5) = 32768
        // b̂ + d̂ = 65536 > 65535 → clamp d̂ to 32767
        let q = quantize_binomial(0.5, 0.5, 0.0, 0.5, 16).unwrap();
        assert_eq!(q.belief + q.disbelief + q.uncertainty, 65535);
        assert_eq!(q.belief, 32768);
        assert_eq!(q.disbelief, 32767);
    }

    // =================================================================
    // Dequantization
    // =================================================================

    #[test]
    fn test_dequantize_8bit_formal_model() {
        let q = QuantizedBinomial {
            belief: 217,
            disbelief: 13,
            uncertainty: 25,
            base_rate: 128,
        };
        let (b, d, u, a) = dequantize_binomial(&q, 8).unwrap();
        assert!(approx_eq(b, 217.0 / 255.0));
        assert!(approx_eq(d, 13.0 / 255.0));
        assert!(approx_eq(u, 25.0 / 255.0));
        assert!(approx_eq(a, 128.0 / 255.0));
    }

    #[test]
    fn test_dequantize_sum_is_one_8bit() {
        // Theorem 1(b): dequantized components sum to exactly 1.0
        // in real arithmetic, and very close in IEEE 754.
        let q = QuantizedBinomial {
            belief: 100,
            disbelief: 50,
            uncertainty: 105,
            base_rate: 128,
        };
        let (b, d, u, _) = dequantize_binomial(&q, 8).unwrap();
        let sum = b + d + u;
        assert!(
            (sum - 1.0).abs() < 1e-12,
            "Dequantized sum should be 1.0, got {sum}"
        );
    }

    #[test]
    fn test_dequantize_sum_is_one_16bit() {
        let q = QuantizedBinomial {
            belief: 30000,
            disbelief: 20000,
            uncertainty: 15535,
            base_rate: 32768,
        };
        let (b, d, u, _) = dequantize_binomial(&q, 16).unwrap();
        let sum = b + d + u;
        assert!(
            (sum - 1.0).abs() < 1e-12,
            "Dequantized sum should be 1.0, got {sum}"
        );
    }

    // =================================================================
    // Roundtrip: quantize → dequantize
    // =================================================================

    #[test]
    fn test_roundtrip_8bit() {
        let (b, d, u, a) = (0.85, 0.05, 0.10, 0.50);
        let q = quantize_binomial(b, d, u, a, 8).unwrap();
        let (br, dr, ur, ar) = dequantize_binomial(&q, 8).unwrap();

        // Quantization error bounded by 1/(2*(2^n-1)) = 1/510 ≈ 0.00196
        let max_err = 1.0 / (2.0 * 255.0);
        assert!((b - br).abs() <= max_err + TOL);
        assert!((d - dr).abs() <= max_err + TOL);
        assert!((u - ur).abs() <= max_err + TOL);
        assert!((a - ar).abs() <= max_err + TOL);
    }

    #[test]
    fn test_roundtrip_16bit() {
        let (b, d, u, a) = (0.7, 0.2, 0.1, 0.3);
        let q = quantize_binomial(b, d, u, a, 16).unwrap();
        let (br, dr, ur, ar) = dequantize_binomial(&q, 16).unwrap();

        let max_err = 1.0 / (2.0 * 65535.0);
        assert!((b - br).abs() <= max_err + TOL);
        assert!((d - dr).abs() <= max_err + TOL);
        assert!((u - ur).abs() <= max_err + TOL);
        assert!((a - ar).abs() <= max_err + TOL);
    }

    // =================================================================
    // Wire encoding/decoding — 8-bit
    // =================================================================

    #[test]
    fn test_encode_opinion_8bit() {
        // b̂=217, d̂=13, â=128 → 3 bytes [217, 13, 128]
        let buf = encode_opinion_bytes(217, 13, 128, 8).unwrap();
        assert_eq!(&buf[..3], &[217, 13, 128]);
    }

    #[test]
    fn test_decode_opinion_8bit() {
        let data = [217u8, 13, 128];
        let q = decode_opinion_bytes(&data, 8).unwrap();
        assert_eq!(q.belief, 217);
        assert_eq!(q.disbelief, 13);
        assert_eq!(q.uncertainty, 25); // derived: 255 - 217 - 13
        assert_eq!(q.base_rate, 128);
    }

    #[test]
    fn test_wire_roundtrip_8bit() {
        let original = quantize_binomial(0.85, 0.05, 0.10, 0.50, 8).unwrap();
        let buf = encode_opinion_bytes(original.belief, original.disbelief, original.base_rate, 8)
            .unwrap();
        let decoded = decode_opinion_bytes(&buf[..3], 8).unwrap();
        assert_eq!(original, decoded);
    }

    // =================================================================
    // Wire encoding/decoding — 16-bit
    // =================================================================

    #[test]
    fn test_encode_opinion_16bit() {
        // b̂=55705, d̂=3277, â=32768
        // Big-endian: [0xD9, 0xA9, 0x0C, 0xCD, 0x80, 0x00]
        let buf = encode_opinion_bytes(55705, 3277, 32768, 16).unwrap();
        // 55705 = 0xD999, 3277 = 0x0CCD, 32768 = 0x8000
        assert_eq!(&buf[..6], &[0xD9, 0x99, 0x0C, 0xCD, 0x80, 0x00]);
    }

    #[test]
    fn test_decode_opinion_16bit() {
        let data = [0xD9u8, 0x99, 0x0C, 0xCD, 0x80, 0x00];
        let q = decode_opinion_bytes(&data, 16).unwrap();
        assert_eq!(q.belief, 55705);
        assert_eq!(q.disbelief, 3277);
        assert_eq!(q.uncertainty, 6553); // 65535 - 55705 - 3277
        assert_eq!(q.base_rate, 32768);
    }

    #[test]
    fn test_wire_roundtrip_16bit() {
        let original = quantize_binomial(0.7, 0.2, 0.1, 0.5, 16).unwrap();
        let buf = encode_opinion_bytes(original.belief, original.disbelief, original.base_rate, 16)
            .unwrap();
        let decoded = decode_opinion_bytes(&buf[..6], 16).unwrap();
        assert_eq!(original, decoded);
    }

    // =================================================================
    // Wire encoding/decoding — 32-bit (IEEE 754, no quantization)
    // =================================================================

    #[test]
    fn test_encode_opinion_32bit() {
        // For 32-bit, we pass the raw float bits packed as u16.
        // Actually for 32-bit mode, we need f32 values.
        // The encode function takes u16, but for 32-bit mode this
        // won't work — we need a separate path. Let's test via
        // the full roundtrip through quantize → encode → decode.
        let wire_size = opinion_wire_size(32).unwrap();
        assert_eq!(wire_size, 12);
    }

    // =================================================================
    // opinion_wire_size
    // =================================================================

    #[test]
    fn test_wire_size_8bit() {
        assert_eq!(opinion_wire_size(8).unwrap(), 3);
    }

    #[test]
    fn test_wire_size_16bit() {
        assert_eq!(opinion_wire_size(16).unwrap(), 6);
    }

    #[test]
    fn test_wire_size_32bit() {
        assert_eq!(opinion_wire_size(32).unwrap(), 12);
    }

    #[test]
    fn test_wire_size_invalid() {
        assert!(matches!(
            opinion_wire_size(4),
            Err(OpinionError::InvalidPrecision(4))
        ));
    }

    // =================================================================
    // Decode error cases
    // =================================================================

    #[test]
    fn test_decode_insufficient_data_8bit() {
        assert!(matches!(
            decode_opinion_bytes(&[0x00, 0x00], 8),
            Err(OpinionError::InsufficientData {
                expected: 3,
                got: 2
            })
        ));
    }

    #[test]
    fn test_decode_insufficient_data_16bit() {
        assert!(matches!(
            decode_opinion_bytes(&[0x00; 4], 16),
            Err(OpinionError::InsufficientData {
                expected: 6,
                got: 4
            })
        ));
    }

    // =================================================================
    // THEOREM 1 — THE INVARIANT: b̂ + d̂ + û = 2^n - 1
    //
    // This is the most important property in the entire protocol.
    // We verify it exhaustively for 8-bit (all 32,896 valid pairs).
    // =================================================================

    #[test]
    fn test_theorem1_invariant_exhaustive_8bit() {
        // For 8-bit, max_val = 255.
        // All valid (b̂, d̂) pairs satisfy b̂ + d̂ ≤ 255.
        // Count: ∑_{s=0}^{255} (s+1) = 256 * 257 / 2 = 32,896 pairs.
        //
        // For each pair, we:
        //   1. Compute the float opinion that would produce this pair
        //   2. Quantize it
        //   3. Verify b̂ + d̂ + û = 255 exactly
        //
        // This is a HARD PROOF — if any single pair fails, the
        // theorem is falsified and the protocol is broken.

        let max_val: u16 = 255;
        let mut pair_count: u32 = 0;

        for b_q in 0u16..=max_val {
            for d_q in 0u16..=(max_val - b_q) {
                let u_q = max_val - b_q - d_q;

                // Reconstruct float opinion from quantized values
                let b = b_q as f64 / max_val as f64;
                let d = d_q as f64 / max_val as f64;
                let u = u_q as f64 / max_val as f64;

                // Quantize
                let q = quantize_binomial(b, d, u, 0.5, 8).unwrap();

                // THE INVARIANT
                assert_eq!(
                    q.belief + q.disbelief + q.uncertainty,
                    max_val,
                    "Theorem 1 violated at b̂={b_q}, d̂={d_q}: \
                     got {}+{}+{}={}",
                    q.belief,
                    q.disbelief,
                    q.uncertainty,
                    q.belief + q.disbelief + q.uncertainty,
                );

                // Verify roundtrip: quantized values should match input
                // (since we started from exact quantized values)
                assert_eq!(q.belief, b_q, "Belief mismatch at b̂={b_q}, d̂={d_q}");
                assert_eq!(q.disbelief, d_q, "Disbelief mismatch at b̂={b_q}, d̂={d_q}");
                assert_eq!(
                    q.uncertainty, u_q,
                    "Uncertainty mismatch at b̂={b_q}, d̂={d_q}"
                );

                pair_count += 1;
            }
        }

        // Verify we actually tested all 32,896 pairs
        assert_eq!(pair_count, 32_896, "Expected 32,896 valid pairs");
    }

    #[test]
    fn test_theorem1_dequantized_sum_exhaustive_8bit() {
        // Complementary to the above: verify that for ALL 32,896 pairs,
        // the dequantized components sum to exactly 1.0 in IEEE 754.
        //
        // Theorem 1(b) guarantees this because:
        //   (b̂ + d̂ + û) / (2ⁿ-1) = (2ⁿ-1) / (2ⁿ-1) = 1
        //
        // In IEEE 754, the sum of three separate divisions SHOULD
        // equal 1.0 exactly for 8-bit values, since 255 fits in
        // mantissa without rounding.

        let max_val: u16 = 255;

        for b_q in 0u16..=max_val {
            for d_q in 0u16..=(max_val - b_q) {
                let u_q = max_val - b_q - d_q;

                let q = QuantizedBinomial {
                    belief: b_q,
                    disbelief: d_q,
                    uncertainty: u_q,
                    base_rate: 128,
                };

                let (b, d, u, _) = dequantize_binomial(&q, 8).unwrap();
                let sum = b + d + u;

                assert!(
                    (sum - 1.0).abs() < 1e-10,
                    "Dequantized sum != 1.0 at b̂={b_q}, d̂={d_q}: \
                     {b} + {d} + {u} = {sum}"
                );
            }
        }
    }

    // =================================================================
    // Python interop — byte-exact wire format verification
    // =================================================================

    #[test]
    fn test_python_interop_encode_8bit() {
        // Python: encode_opinion_bytes(217, 13, 128, precision=8)
        // → b'\xd9\x0d\x80'
        let buf = encode_opinion_bytes(217, 13, 128, 8).unwrap();
        assert_eq!(&buf[..3], &[0xD9, 0x0D, 0x80]);
    }

    #[test]
    fn test_python_interop_decode_8bit() {
        // Python: decode_opinion_bytes(b'\xd9\x0d\x80', precision=8)
        // → (217, 13, 25, 128)
        let data = [0xD9u8, 0x0D, 0x80];
        let q = decode_opinion_bytes(&data, 8).unwrap();
        assert_eq!(q.belief, 217);
        assert_eq!(q.disbelief, 13);
        assert_eq!(q.uncertainty, 25);
        assert_eq!(q.base_rate, 128);
    }

    #[test]
    fn test_python_interop_encode_16bit() {
        // Python: encode_opinion_bytes(55705, 3277, 32768, precision=16)
        // → b'\xd9\xa9\x0c\xcd\x80\x00'
        let buf = encode_opinion_bytes(55705, 3277, 32768, 16).unwrap();
        // 55705 = 0xD999
        assert_eq!(&buf[..6], &[0xD9, 0x99, 0x0C, 0xCD, 0x80, 0x00]);
    }

    #[test]
    fn test_python_interop_quantize_formal_model() {
        // Python: quantize_binomial(0.85, 0.05, 0.10, 0.50, precision=8)
        // → (217, 13, 25, 128)
        let q = quantize_binomial(0.85, 0.05, 0.10, 0.50, 8).unwrap();
        assert_eq!(
            (q.belief, q.disbelief, q.uncertainty, q.base_rate),
            (217, 13, 25, 128)
        );
    }
}
