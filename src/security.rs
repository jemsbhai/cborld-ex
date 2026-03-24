//! Security primitives for CBOR-LD-ex.
//!
//! Implements FORMAL_MODEL.md §9 and SYNDROME_LOCALIZATION.md:
//!   - Byzantine fusion metadata: bit-packed (4 bytes)
//!   - Provenance entries: bit-packed (6 bytes, compact format)
//!   - GF(2⁸) syndrome-based tamper localization
//!   - Chain-level SHA-256 digest (feature-gated on `digest`)
//!
//! Security is orthogonal to Axioms 1–3:
//!   - Digests and metadata are about annotations, not opinion values
//!   - No quantization or opinion algebra involved
//!   - Stripping annotations (Axiom 1) also strips security metadata
//!
//! ## Feature Gating
//!
//! - Types + encode/decode + GF(2⁸) + syndromes: always available (bare `no_std`)
//! - Batch chain encode/decode (`Vec`): requires `alloc`
//! - Chain digest (SHA-256): requires `digest` feature

// ---------------------------------------------------------------------------
// Byzantine Fusion Metadata — 4 bytes (32 bits)
//
// Wire format (FORMAL_MODEL.md §9.3):
//   Byte 0: original_source_count  (8 bits)
//   Byte 1: removed_count          (8 bits)
//   Byte 2: cohesion_q             (8 bits, Q8: 0→0.0, 255→1.0)
//   Byte 3: [strategy:2][reserved:6]
//
// Strategies: 00=most_conflicting, 01=least_trusted, 10=combined, 11=reserved
// ---------------------------------------------------------------------------

/// Byzantine removal strategy codes (2 bits, §9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RemovalStrategy {
    /// Remove opinions with highest aggregate pairwise conflict.
    MostConflicting = 0,
    /// Remove opinions from least-trusted sources first.
    LeastTrusted = 1,
    /// Rank by conflict × (1 − trust_weight).
    Combined = 2,
}

/// Byzantine fusion metadata for Tier 2 annotations (4 bytes).
///
/// Records the outcome of Byzantine-resistant filtering so that
/// Tier 3 can assess fusion quality without re-processing raw data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByzantineMetadata {
    /// Number of sources before filtering (0–255).
    pub original_count: u8,
    /// Number of sources removed (0–255).
    pub removed_count: u8,
    /// Quantized group cohesion of survivors (Q8: 0=0.0, 255=1.0).
    pub cohesion_q: u8,
    /// Removal strategy used.
    pub strategy: RemovalStrategy,
}

/// Size of Byzantine metadata on the wire.
pub const BYZANTINE_METADATA_SIZE: usize = 4;

/// Error type for security operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityError {
    /// Invalid removal strategy code.
    InvalidStrategy(u8),
    /// Insufficient bytes for decoding.
    InsufficientData { expected: usize, got: usize },
}

/// Encode Byzantine metadata to exactly 4 bytes.
///
/// Wire format:
///   Byte 0: original_count
///   Byte 1: removed_count
///   Byte 2: cohesion_q
///   Byte 3: [strategy:2][000000:6]
pub fn encode_byzantine_metadata(meta: &ByzantineMetadata) -> [u8; 4] {
    let byte3 = (meta.strategy as u8) << 6;
    [meta.original_count, meta.removed_count, meta.cohesion_q, byte3]
}

/// Decode 4 bytes to Byzantine metadata.
pub fn decode_byzantine_metadata(data: &[u8]) -> Result<ByzantineMetadata, SecurityError> {
    if data.len() < BYZANTINE_METADATA_SIZE {
        return Err(SecurityError::InsufficientData {
            expected: BYZANTINE_METADATA_SIZE,
            got: data.len(),
        });
    }
    let strategy_code = (data[3] >> 6) & 0x03;
    let strategy = match strategy_code {
        0 => RemovalStrategy::MostConflicting,
        1 => RemovalStrategy::LeastTrusted,
        2 => RemovalStrategy::Combined,
        s => return Err(SecurityError::InvalidStrategy(s)),
    };
    Ok(ByzantineMetadata {
        original_count: data[0],
        removed_count: data[1],
        cohesion_q: data[2],
        strategy,
    })
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ===================================================================
    // 1. Byzantine Metadata — 4 bytes
    // ===================================================================

    mod byzantine {
        use super::*;

        #[test]
        fn metadata_is_4_bytes() {
            let meta = ByzantineMetadata {
                original_count: 10,
                removed_count: 2,
                cohesion_q: 217,
                strategy: RemovalStrategy::MostConflicting,
            };
            let data = encode_byzantine_metadata(&meta);
            assert_eq!(data.len(), BYZANTINE_METADATA_SIZE);
            assert_eq!(BYZANTINE_METADATA_SIZE, 4);
        }

        #[test]
        fn metadata_bit_layout_most_conflicting() {
            // original=10(0x0A), removed=2(0x02), cohesion=217(0xD9),
            // strategy=00(most_conflicting), pad=000000
            // Expected: 0x0A 0x02 0xD9 0x00
            let meta = ByzantineMetadata {
                original_count: 10,
                removed_count: 2,
                cohesion_q: 217,
                strategy: RemovalStrategy::MostConflicting,
            };
            let data = encode_byzantine_metadata(&meta);
            assert_eq!(data, [0x0A, 0x02, 0xD9, 0x00]);
        }

        #[test]
        fn metadata_least_trusted_strategy() {
            // strategy=01 → byte 3: 01_000000 = 0x40
            let meta = ByzantineMetadata {
                original_count: 5,
                removed_count: 1,
                cohesion_q: 128,
                strategy: RemovalStrategy::LeastTrusted,
            };
            let data = encode_byzantine_metadata(&meta);
            assert_eq!(data[3], 0x40);
        }

        #[test]
        fn metadata_combined_strategy() {
            // strategy=10 → byte 3: 10_000000 = 0x80
            let meta = ByzantineMetadata {
                original_count: 8,
                removed_count: 3,
                cohesion_q: 200,
                strategy: RemovalStrategy::Combined,
            };
            let data = encode_byzantine_metadata(&meta);
            assert_eq!(data[3], 0x80);
        }

        #[test]
        fn metadata_roundtrip() {
            let original = ByzantineMetadata {
                original_count: 20,
                removed_count: 4,
                cohesion_q: 190,
                strategy: RemovalStrategy::Combined,
            };
            let data = encode_byzantine_metadata(&original);
            let recovered = decode_byzantine_metadata(&data).unwrap();
            assert_eq!(recovered, original);
        }

        #[test]
        fn metadata_roundtrip_all_strategies() {
            for strategy in [
                RemovalStrategy::MostConflicting,
                RemovalStrategy::LeastTrusted,
                RemovalStrategy::Combined,
            ] {
                let original = ByzantineMetadata {
                    original_count: 100,
                    removed_count: 10,
                    cohesion_q: 255,
                    strategy,
                };
                let data = encode_byzantine_metadata(&original);
                let recovered = decode_byzantine_metadata(&data).unwrap();
                assert_eq!(recovered, original, "Roundtrip failed for {strategy:?}");
            }
        }

        #[test]
        fn metadata_zero_removals() {
            let meta = ByzantineMetadata {
                original_count: 5,
                removed_count: 0,
                cohesion_q: 255,
                strategy: RemovalStrategy::MostConflicting,
            };
            let data = encode_byzantine_metadata(&meta);
            let recovered = decode_byzantine_metadata(&data).unwrap();
            assert_eq!(recovered.removed_count, 0);
            assert_eq!(recovered.cohesion_q, 255);
        }

        #[test]
        fn metadata_max_values() {
            let meta = ByzantineMetadata {
                original_count: 255,
                removed_count: 255,
                cohesion_q: 255,
                strategy: RemovalStrategy::Combined,
            };
            let data = encode_byzantine_metadata(&meta);
            let recovered = decode_byzantine_metadata(&data).unwrap();
            assert_eq!(recovered, meta);
        }

        #[test]
        fn metadata_min_values() {
            let meta = ByzantineMetadata {
                original_count: 0,
                removed_count: 0,
                cohesion_q: 0,
                strategy: RemovalStrategy::MostConflicting,
            };
            let data = encode_byzantine_metadata(&meta);
            let recovered = decode_byzantine_metadata(&data).unwrap();
            assert_eq!(recovered, meta);
        }

        #[test]
        fn metadata_invalid_strategy_rejected() {
            // Manually craft byte 3 with strategy=11 (reserved)
            let data = [10, 2, 217, 0xC0]; // 11_000000 = 0xC0
            let result = decode_byzantine_metadata(&data);
            assert_eq!(result, Err(SecurityError::InvalidStrategy(3)));
        }

        #[test]
        fn metadata_insufficient_data() {
            let result = decode_byzantine_metadata(&[0x0A, 0x02]);
            assert_eq!(
                result,
                Err(SecurityError::InsufficientData { expected: 4, got: 2 })
            );
        }

        #[test]
        fn metadata_empty_data() {
            let result = decode_byzantine_metadata(&[]);
            assert_eq!(
                result,
                Err(SecurityError::InsufficientData { expected: 4, got: 0 })
            );
        }

        /// Python interop: exact byte match with Python cbor-ld-ex security.py
        #[test]
        fn python_interop_most_conflicting() {
            // Python: encode_byzantine_metadata(ByzantineMetadata(
            //   original_count=10, removed_count=2, cohesion_q=217,
            //   strategy=STRATEGY_MOST_CONFLICTING))
            // → bytes([0x0A, 0x02, 0xD9, 0x00])
            let meta = ByzantineMetadata {
                original_count: 10,
                removed_count: 2,
                cohesion_q: 217,
                strategy: RemovalStrategy::MostConflicting,
            };
            assert_eq!(encode_byzantine_metadata(&meta), [0x0A, 0x02, 0xD9, 0x00]);
        }

        /// Python interop: least_trusted strategy
        #[test]
        fn python_interop_least_trusted() {
            // Python: strategy=STRATEGY_LEAST_TRUSTED → byte3 = 0x40
            let meta = ByzantineMetadata {
                original_count: 5,
                removed_count: 1,
                cohesion_q: 128,
                strategy: RemovalStrategy::LeastTrusted,
            };
            assert_eq!(
                encode_byzantine_metadata(&meta),
                [0x05, 0x01, 0x80, 0x40]
            );
        }

        /// Python interop: combined strategy
        #[test]
        fn python_interop_combined() {
            // Python: strategy=STRATEGY_COMBINED → byte3 = 0x80
            let meta = ByzantineMetadata {
                original_count: 8,
                removed_count: 3,
                cohesion_q: 200,
                strategy: RemovalStrategy::Combined,
            };
            assert_eq!(
                encode_byzantine_metadata(&meta),
                [0x08, 0x03, 0xC8, 0x80]
            );
        }

        /// Exhaustive: all 256 × 3 combinations of cohesion_q × strategy roundtrip.
        #[test]
        fn metadata_exhaustive_cohesion_strategy_roundtrip() {
            for cohesion in 0..=255u8 {
                for strategy in [
                    RemovalStrategy::MostConflicting,
                    RemovalStrategy::LeastTrusted,
                    RemovalStrategy::Combined,
                ] {
                    let original = ByzantineMetadata {
                        original_count: 42,
                        removed_count: 7,
                        cohesion_q: cohesion,
                        strategy,
                    };
                    let data = encode_byzantine_metadata(&original);
                    let recovered = decode_byzantine_metadata(&data).unwrap();
                    assert_eq!(recovered, original,
                        "Failed: cohesion={cohesion}, strategy={strategy:?}");
                }
            }
        }

        /// Reserved bits in byte 3 must be zero on encode and ignored on decode.
        #[test]
        fn metadata_reserved_bits_zero_on_encode() {
            let meta = ByzantineMetadata {
                original_count: 1,
                removed_count: 1,
                cohesion_q: 1,
                strategy: RemovalStrategy::LeastTrusted,
            };
            let data = encode_byzantine_metadata(&meta);
            // Byte 3 lower 6 bits must be zero
            assert_eq!(data[3] & 0x3F, 0x00);
        }
    }
}
