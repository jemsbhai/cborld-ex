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
    /// origin_tier must be 0–2.
    InvalidOriginTier(u8),
    /// operator_id must be 0–15 (4 bits).
    InvalidOperatorId(u8),
    /// precision_mode must be 0–2.
    InvalidPrecisionMode(u8),
    /// t must be 1–7 (MAX_T).
    InvalidT(u8),
    /// Syndrome slices have mismatched lengths.
    SyndromeLengthMismatch { stored: usize, received: usize },
    /// Syndrome slices too short (need at least 2 for single-entry localization).
    SyndromeTooShort(usize),
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

// ---------------------------------------------------------------------------
// Provenance Entry — 6 bytes (48 bits, zero waste)
//
// Compact format per SYNDROME_LOCALIZATION.md §4.1:
//   Byte 0:     [origin_tier:2][operator_id:4][precision_mode:2]
//   Bytes 1-3:  b̂, d̂, â (3 × uint8, û derived as 255 − b̂ − d̂)
//   Bytes 4-5:  time_offset (uint16, big-endian, seconds from chain base_timestamp)
//
// Total: 8 + 24 + 16 = 48 bits = 6 bytes. Zero waste.
//
// Note: This is the compact §9 hardened format. The §5 inline format
// (without digests) coexists as a separate format for Tier 3 header
// extensions and is not implemented here.
// ---------------------------------------------------------------------------

/// Size of a compact provenance entry on the wire.
pub const PROVENANCE_ENTRY_SIZE: usize = 6;

/// Maximum time offset in seconds (uint16 max = 65,535 ≈ 18.2 hours).
pub const MAX_TIME_OFFSET: u16 = u16::MAX;

/// A single entry in a provenance chain (6 bytes, compact format).
///
/// Records one processing step in the Tier 1 → Tier 2 → Tier 3
/// pipeline. Uses time_offset (seconds from chain base_timestamp)
/// instead of absolute timestamps to save 2 bytes per entry.
///
/// Opinion is always stored at 8-bit precision (3 bytes).
/// û is NOT stored — derived as 255 − b̂ − d̂ (Axiom 3).
/// The `precision_mode` field records the precision of the
/// *source annotation*, not the entry's own opinion storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvenanceEntry {
    /// Tier that produced this entry (0=constrained, 1=edge, 2=cloud). 2 bits.
    pub origin_tier: u8,
    /// Which operator was applied (Table 2, §5.2). 4 bits (0–15).
    pub operator_id: u8,
    /// Source annotation precision (0=8-bit, 1=16-bit, 2=32-bit). 2 bits.
    pub precision_mode: u8,
    /// Quantized belief (uint8).
    pub b_q: u8,
    /// Quantized disbelief (uint8).
    pub d_q: u8,
    /// Quantized base rate (uint8).
    pub a_q: u8,
    /// Seconds since chain base_timestamp (uint16, 0–65535).
    pub time_offset: u16,
}

/// Encode a provenance entry to exactly 6 bytes.
///
/// Wire format:
///   Byte 0:     [origin_tier:2][operator_id:4][precision_mode:2]
///   Bytes 1-3:  b̂, d̂, â
///   Bytes 4-5:  time_offset (uint16, big-endian)
///
/// Returns `Err` if field values exceed their bit widths.
pub fn encode_provenance_entry(entry: &ProvenanceEntry) -> Result<[u8; 6], SecurityError> {
    if entry.origin_tier > 2 {
        return Err(SecurityError::InvalidOriginTier(entry.origin_tier));
    }
    if entry.operator_id > 15 {
        return Err(SecurityError::InvalidOperatorId(entry.operator_id));
    }
    if entry.precision_mode > 2 {
        return Err(SecurityError::InvalidPrecisionMode(entry.precision_mode));
    }
    let byte0 = (entry.origin_tier << 6)
        | (entry.operator_id << 2)
        | entry.precision_mode;
    let offset_be = entry.time_offset.to_be_bytes();
    Ok([byte0, entry.b_q, entry.d_q, entry.a_q, offset_be[0], offset_be[1]])
}

/// Decode 6 bytes to a provenance entry.
pub fn decode_provenance_entry(data: &[u8]) -> Result<ProvenanceEntry, SecurityError> {
    if data.len() < PROVENANCE_ENTRY_SIZE {
        return Err(SecurityError::InsufficientData {
            expected: PROVENANCE_ENTRY_SIZE,
            got: data.len(),
        });
    }
    let byte0 = data[0];
    let origin_tier = (byte0 >> 6) & 0x03;
    let operator_id = (byte0 >> 2) & 0x0F;
    let precision_mode = byte0 & 0x03;
    let time_offset = u16::from_be_bytes([data[4], data[5]]);
    Ok(ProvenanceEntry {
        origin_tier,
        operator_id,
        precision_mode,
        b_q: data[1],
        d_q: data[2],
        a_q: data[3],
        time_offset,
    })
}

// ---------------------------------------------------------------------------
// GF(2⁸) Arithmetic — AES polynomial 0x11B
//
// SYNDROME_LOCALIZATION.md §2.1:
//   Field: GF(2)[x] / (x⁸ + x⁴ + x³ + x + 1)
//   Primitive element: α = 0x03 (order 255, generates all non-zero elements)
//   NOTE: α = 0x02 has order 51 (NOT primitive). This is load-bearing.
//
// Used for syndrome-based tamper localization. All operations are
// constant-time table lookups (no branching on data values).
//
// Static storage: 256-byte exp table + 256-byte log table = 512 bytes.
// ---------------------------------------------------------------------------

/// GF(2⁸) irreducible polynomial: x⁸ + x⁴ + x³ + x + 1 (AES).
const GF_MOD: u16 = 0x11B;

/// Primitive element α = 0x03.
const GF_ALPHA: u8 = 0x03;

/// Multiply two elements in GF(2⁸).
///
/// Russian peasant multiplication with reduction mod 0x11B.
/// Returns 0 if either input is 0.
pub fn gf_mul(a: u8, b: u8) -> u8 {
    let mut result: u8 = 0;
    let mut a = a as u16;
    let mut b = b;
    while b != 0 {
        if b & 1 != 0 {
            result ^= a as u8;
        }
        a <<= 1;
        if a & 0x100 != 0 {
            a ^= GF_MOD;
        }
        b >>= 1;
    }
    result
}

/// Const-compatible GF(2⁸) multiplication for table generation.
const fn gf_mul_const(a: u8, b: u8) -> u8 {
    let mut result: u8 = 0;
    let mut a = a as u16;
    let mut b = b;
    while b != 0 {
        if b & 1 != 0 {
            result ^= a as u8;
        }
        a <<= 1;
        if a & 0x100 != 0 {
            a ^= GF_MOD;
        }
        b >>= 1;
    }
    result
}

/// Build GF(2⁸) exp table at compile time: EXP[i] = α^i for i=0..255.
/// EXP[255] = EXP[0] = 1 (wrap-around).
const fn build_gf_exp_table() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut val: u8 = 1; // α⁰ = 1
    let mut i = 0u16;
    while i < 255 {
        table[i as usize] = val;
        val = gf_mul_const(val, GF_ALPHA);
        i += 1;
    }
    table[255] = table[0]; // α²⁵⁵ = α⁰ = 1
    table
}

/// Build GF(2⁸) log table at compile time: LOG[v] = i such that α^i = v.
/// LOG[0] = 0 (sentinel — log(0) is undefined, callers must check).
const fn build_gf_log_table() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut val: u8 = 1;
    let mut i = 0u16;
    while i < 255 {
        table[val as usize] = i as u8;
        val = gf_mul_const(val, GF_ALPHA);
        i += 1;
    }
    // table[0] remains 0 (sentinel)
    table
}

/// GF(2⁸) exp table: EXP[i] = α^i. 256 bytes static.
static GF_EXP: [u8; 256] = build_gf_exp_table();

/// GF(2⁸) log table: LOG[v] = log_α(v). 256 bytes static.
/// LOG[0] = 0 (undefined — callers must not pass 0).
static GF_LOG: [u8; 256] = build_gf_log_table();

/// Return α^power in GF(2⁸) via exp table lookup.
///
/// Power is taken mod 255 (since α²⁵⁵ = 1).
/// gf_exp(0) = 1 (α⁰ = 1).
pub fn gf_exp(power: u8) -> u8 {
    GF_EXP[(power % 255) as usize]
}

/// Return discrete log base α of val in GF(2⁸).
///
/// Panics if val is 0 (log(0) is undefined in GF(2⁸)).
/// Returns i such that α^i = val.
pub fn gf_log(val: u8) -> u8 {
    assert!(val != 0, "log(0) is undefined in GF(2^8)");
    GF_LOG[val as usize]
}

/// Multiplicative inverse of val in GF(2⁸).
///
/// val⁻¹ = α^(255 - log_α(val)).
/// Panics if val is 0.
pub fn gf_inv(val: u8) -> u8 {
    assert!(val != 0, "0 has no inverse in GF(2^8)");
    gf_exp(255 - gf_log(val))
}

// ---------------------------------------------------------------------------
// CRC-8/CCITT — generator polynomial x⁸ + x² + x + 1 (0x07)
//
// SYNDROME_LOCALIZATION.md §2.2:
//   Entry fingerprint h: {6-byte entry} → GF(2⁸)
//   Guaranteed detection of all single-bit errors.
//   Near-zero collision for multi-bit flips (empirically verified).
//
// Static storage: 256-byte lookup table.
// Total with GF tables: 768 bytes.
// ---------------------------------------------------------------------------

/// CRC-8/CCITT generator polynomial: x⁸ + x² + x + 1.
const CRC8_POLY: u8 = 0x07;

/// Build CRC-8/CCITT lookup table at compile time.
const fn build_crc8_table() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut i = 0u16;
    while i < 256 {
        let mut crc = i as u8;
        let mut bit = 0;
        while bit < 8 {
            if crc & 0x80 != 0 {
                crc = (crc << 1) ^ CRC8_POLY;
            } else {
                crc <<= 1;
            }
            bit += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
}

/// CRC-8/CCITT lookup table. 256 bytes static.
static CRC8_TABLE: [u8; 256] = build_crc8_table();

/// Compute CRC-8/CCITT over a byte slice.
///
/// Initial value: 0x00. No final XOR.
/// Returns a single byte in GF(2⁸).
pub fn crc8(data: &[u8]) -> u8 {
    let mut crc: u8 = 0x00;
    for &b in data {
        crc = CRC8_TABLE[(crc ^ b) as usize];
    }
    crc
}

// ---------------------------------------------------------------------------
// Syndrome Computation & Tamper Localization
//
// SYNDROME_LOCALIZATION.md §2.3–§2.4:
//   S_k = XOR_{i=0}^{n-1} (alpha^{k*i} * h(e_i))  for k = 0..2t-1
//   where h = CRC-8, alpha = 0x03, operations in GF(2^8)
//
// Configurable t (1..=MAX_T): localizes up to t simultaneously tampered entries.
// Default t=1: 2 syndrome bytes. Max t=7: 14 syndrome bytes.
// Chain length limited to 255 (GF(2^8) has 255 non-zero elements).
// ---------------------------------------------------------------------------

/// Maximum localization capability. t=7 → 14 syndrome bytes.
pub const MAX_T: u8 = 7;

/// Maximum syndrome byte count (2 * MAX_T).
pub const MAX_SYNDROME_BYTES: usize = 14;

/// Maximum chain length (GF(2^8) non-zero element count).
pub const MAX_CHAIN_LENGTH: usize = 255;

/// Result of single-entry tamper localization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalizationResult {
    /// Syndromes match — no tampering detected by syndromes.
    /// (Could still be h-collision; chain digest is definitive.)
    NoChange,
    /// Exactly one entry tampered at the given index (0-based).
    SingleTamper { index: u8 },
    /// Inconsistent syndrome deltas indicate multi-entry tampering.
    /// Syndromes cannot pinpoint which entries; chain digest confirms detection.
    MultiTamper,
}

/// Compute 2t syndrome bytes over a chain of 6-byte entries.
///
/// Implements SYNDROME_LOCALIZATION.md §2.3, Definition 4:
///   S_k = ⊕_{i=0}^{n-1} (α^{ki} ⊗ h(eᵢ))  for k = 0..2t-1
///
/// Returns a fixed-size array of MAX_SYNDROME_BYTES (14) bytes.
/// Only the first 2*t bytes are meaningful; the rest are zero.
///
/// # Arguments
/// * `entries` — Slice of 6-byte encoded provenance entries (raw wire bytes).
/// * `t` — Localization capability (1..=MAX_T). Produces 2t syndrome bytes.
///
/// # Errors
/// * `InvalidT` if t is 0 or > MAX_T.
/// * `InsufficientData` if entries.len() > MAX_CHAIN_LENGTH (255).
pub fn compute_syndromes(
    entries: &[[u8; 6]],
    t: u8,
) -> Result<[u8; MAX_SYNDROME_BYTES], SecurityError> {
    if t == 0 || t > MAX_T {
        return Err(SecurityError::InvalidT(t));
    }
    let n = entries.len();
    if n > MAX_CHAIN_LENGTH {
        return Err(SecurityError::InsufficientData {
            expected: MAX_CHAIN_LENGTH,
            got: n,
        });
    }

    let mut syndromes = [0u8; MAX_SYNDROME_BYTES];
    let num_syndromes = 2 * t as usize;

    for (i, entry) in entries.iter().enumerate() {
        let h = crc8(entry);
        for k in 0..num_syndromes {
            // weight = α^{k*i}. Since α^0 = 1, and (k*i) mod 255 handles wrap.
            // Special case: k*i = 0 → weight = 1 (α^0).
            let power = (k * i) % 255;
            let weight = if k == 0 || i == 0 {
                // α^0 = 1. gf_exp(0) = 1, but we avoid the mod for clarity.
                1u8
            } else {
                GF_EXP[power]
            };
            syndromes[k] ^= gf_mul(weight, h);
        }
    }

    Ok(syndromes)
}

/// Localize a single tampered entry from stored vs received syndrome slices.
///
/// Implements SYNDROME_LOCALIZATION.md §2.4, Theorem 1:
///   Δ₀ = S₀ ⊕ S₀',  Δ₁ = S₁ ⊕ S₁'
///   j = log_α(Δ₁ ⊗ Δ₀⁻¹)
///
/// Uses only the first two syndrome bytes (S₀, S₁). Slices may be
/// longer (e.g., from t=2 computation); extra bytes are ignored.
///
/// # Errors
/// * `SyndromeLengthMismatch` if slice lengths differ.
/// * `SyndromeTooShort` if either slice has fewer than 2 bytes.
pub fn localize_single_tamper(
    stored: &[u8],
    received: &[u8],
) -> Result<LocalizationResult, SecurityError> {
    if stored.len() != received.len() {
        return Err(SecurityError::SyndromeLengthMismatch {
            stored: stored.len(),
            received: received.len(),
        });
    }
    if stored.len() < 2 {
        return Err(SecurityError::SyndromeTooShort(stored.len()));
    }

    let delta0 = stored[0] ^ received[0];
    let delta1 = stored[1] ^ received[1];

    match (delta0 != 0, delta1 != 0) {
        (false, false) => Ok(LocalizationResult::NoChange),
        // One zero, one not: impossible for single-entry tampering.
        // α^j is always non-zero in GF(2⁸), so Δ₁ = α^j ⊗ Δ₀
        // means both must be non-zero or both zero.
        (false, true) | (true, false) => Ok(LocalizationResult::MultiTamper),
        (true, true) => {
            // j = log_α(Δ₁ ⊗ Δ₀⁻¹)
            let alpha_j = gf_mul(delta1, gf_inv(delta0));
            let j = gf_log(alpha_j);
            Ok(LocalizationResult::SingleTamper { index: j })
        }
    }
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
            let data = [10, 2, 217, 0xC0];
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

        #[test]
        fn python_interop_most_conflicting() {
            let meta = ByzantineMetadata {
                original_count: 10,
                removed_count: 2,
                cohesion_q: 217,
                strategy: RemovalStrategy::MostConflicting,
            };
            assert_eq!(encode_byzantine_metadata(&meta), [0x0A, 0x02, 0xD9, 0x00]);
        }

        #[test]
        fn python_interop_least_trusted() {
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

        #[test]
        fn python_interop_combined() {
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

        #[test]
        fn metadata_reserved_bits_zero_on_encode() {
            let meta = ByzantineMetadata {
                original_count: 1,
                removed_count: 1,
                cohesion_q: 1,
                strategy: RemovalStrategy::LeastTrusted,
            };
            let data = encode_byzantine_metadata(&meta);
            assert_eq!(data[3] & 0x3F, 0x00);
        }
    }

    // ===================================================================
    // 2. Provenance Entry — 6 bytes (48 bits, zero waste)
    // ===================================================================

    mod provenance_entry {
        use super::*;

        #[test]
        fn entry_is_6_bytes() {
            let entry = ProvenanceEntry {
                origin_tier: 0,
                operator_id: 0,
                precision_mode: 0,
                b_q: 217, d_q: 13, a_q: 128,
                time_offset: 0,
            };
            let data = encode_provenance_entry(&entry).unwrap();
            assert_eq!(data.len(), PROVENANCE_ENTRY_SIZE);
            assert_eq!(PROVENANCE_ENTRY_SIZE, 6);
        }

        #[test]
        fn entry_byte0_bit_layout_tier0_none_8bit() {
            // origin_tier=00, operator_id=0000, precision_mode=00
            // Byte 0: 00_0000_00 = 0x00
            let entry = ProvenanceEntry {
                origin_tier: 0,
                operator_id: 0,
                precision_mode: 0,
                b_q: 0, d_q: 0, a_q: 0,
                time_offset: 0,
            };
            let data = encode_provenance_entry(&entry).unwrap();
            assert_eq!(data[0], 0x00);
        }

        #[test]
        fn entry_byte0_bit_layout_tier1_jmeet_8bit() {
            // origin_tier=01(edge), operator_id=0100(jurisdictional_meet),
            // precision_mode=00(8-bit)
            // Byte 0: 01_0100_00 = 0x50
            let entry = ProvenanceEntry {
                origin_tier: 1,
                operator_id: 4,
                precision_mode: 0,
                b_q: 200, d_q: 30, a_q: 128,
                time_offset: 60,
            };
            let data = encode_provenance_entry(&entry).unwrap();
            assert_eq!(data[0], 0x50);
        }

        #[test]
        fn entry_byte0_bit_layout_tier2_deduction_16bit() {
            // origin_tier=10(cloud), operator_id=0011(deduction),
            // precision_mode=01(16-bit)
            // Byte 0: 10_0011_01 = 0x8D
            let entry = ProvenanceEntry {
                origin_tier: 2,
                operator_id: 3,
                precision_mode: 1,
                b_q: 150, d_q: 50, a_q: 128,
                time_offset: 120,
            };
            let data = encode_provenance_entry(&entry).unwrap();
            assert_eq!(data[0], 0x8D);
        }

        #[test]
        fn entry_byte0_bit_layout_max_fields() {
            // origin_tier=10(cloud), operator_id=1100(regulatory_change=12),
            // precision_mode=10(32-bit)
            // Byte 0: 10_1100_10 = 0xB2
            let entry = ProvenanceEntry {
                origin_tier: 2,
                operator_id: 12,
                precision_mode: 2,
                b_q: 0, d_q: 0, a_q: 0,
                time_offset: 0,
            };
            let data = encode_provenance_entry(&entry).unwrap();
            assert_eq!(data[0], 0xB2);
        }

        #[test]
        fn entry_opinion_bytes() {
            // Bytes 1-3: b̂, d̂, â
            let entry = ProvenanceEntry {
                origin_tier: 0,
                operator_id: 0,
                precision_mode: 0,
                b_q: 217, d_q: 13, a_q: 128,
                time_offset: 0,
            };
            let data = encode_provenance_entry(&entry).unwrap();
            assert_eq!(data[1], 217); // b̂
            assert_eq!(data[2], 13);  // d̂
            assert_eq!(data[3], 128); // â
        }

        #[test]
        fn entry_time_offset_big_endian() {
            // time_offset = 0x1234 → bytes 4-5: 0x12, 0x34
            let entry = ProvenanceEntry {
                origin_tier: 0,
                operator_id: 0,
                precision_mode: 0,
                b_q: 0, d_q: 0, a_q: 0,
                time_offset: 0x1234,
            };
            let data = encode_provenance_entry(&entry).unwrap();
            assert_eq!(data[4], 0x12);
            assert_eq!(data[5], 0x34);
        }

        #[test]
        fn entry_time_offset_zero() {
            let entry = ProvenanceEntry {
                origin_tier: 0,
                operator_id: 0,
                precision_mode: 0,
                b_q: 0, d_q: 0, a_q: 0,
                time_offset: 0,
            };
            let data = encode_provenance_entry(&entry).unwrap();
            assert_eq!(data[4], 0x00);
            assert_eq!(data[5], 0x00);
        }

        #[test]
        fn entry_time_offset_max() {
            // 65535 = 0xFFFF
            let entry = ProvenanceEntry {
                origin_tier: 0,
                operator_id: 0,
                precision_mode: 0,
                b_q: 0, d_q: 0, a_q: 0,
                time_offset: 65535,
            };
            let data = encode_provenance_entry(&entry).unwrap();
            assert_eq!(data[4], 0xFF);
            assert_eq!(data[5], 0xFF);
        }

        #[test]
        fn entry_roundtrip() {
            let original = ProvenanceEntry {
                origin_tier: 1,
                operator_id: 4,
                precision_mode: 0,
                b_q: 200, d_q: 30, a_q: 128,
                time_offset: 60,
            };
            let data = encode_provenance_entry(&original).unwrap();
            let recovered = decode_provenance_entry(&data).unwrap();
            assert_eq!(recovered, original);
        }

        #[test]
        fn entry_roundtrip_all_tiers() {
            for tier in 0..=2u8 {
                let original = ProvenanceEntry {
                    origin_tier: tier,
                    operator_id: 1,
                    precision_mode: 0,
                    b_q: 217, d_q: 13, a_q: 128,
                    time_offset: 100,
                };
                let data = encode_provenance_entry(&original).unwrap();
                let recovered = decode_provenance_entry(&data).unwrap();
                assert_eq!(recovered, original, "Roundtrip failed for tier={tier}");
            }
        }

        #[test]
        fn entry_roundtrip_all_operators() {
            // 4-bit operator_id: 0–12 defined, 13–15 reserved but valid on wire
            for op in 0..=15u8 {
                let original = ProvenanceEntry {
                    origin_tier: 0,
                    operator_id: op,
                    precision_mode: 0,
                    b_q: 100, d_q: 100, a_q: 128,
                    time_offset: 0,
                };
                let data = encode_provenance_entry(&original).unwrap();
                let recovered = decode_provenance_entry(&data).unwrap();
                assert_eq!(recovered, original, "Roundtrip failed for op={op}");
            }
        }

        #[test]
        fn entry_roundtrip_all_precision_modes() {
            for pm in 0..=2u8 {
                let original = ProvenanceEntry {
                    origin_tier: 0,
                    operator_id: 0,
                    precision_mode: pm,
                    b_q: 200, d_q: 30, a_q: 128,
                    time_offset: 500,
                };
                let data = encode_provenance_entry(&original).unwrap();
                let recovered = decode_provenance_entry(&data).unwrap();
                assert_eq!(recovered, original, "Roundtrip failed for pm={pm}");
            }
        }

        #[test]
        fn entry_max_all_fields() {
            let original = ProvenanceEntry {
                origin_tier: 2,
                operator_id: 15,
                precision_mode: 2,
                b_q: 255, d_q: 255, a_q: 255,
                time_offset: 65535,
            };
            let data = encode_provenance_entry(&original).unwrap();
            let recovered = decode_provenance_entry(&data).unwrap();
            assert_eq!(recovered, original);
        }

        #[test]
        fn entry_min_all_fields() {
            let original = ProvenanceEntry {
                origin_tier: 0,
                operator_id: 0,
                precision_mode: 0,
                b_q: 0, d_q: 0, a_q: 0,
                time_offset: 0,
            };
            let data = encode_provenance_entry(&original).unwrap();
            let recovered = decode_provenance_entry(&data).unwrap();
            assert_eq!(recovered, original);
        }

        // ---------------------------------------------------------------
        // Validation errors
        // ---------------------------------------------------------------

        #[test]
        fn entry_invalid_origin_tier() {
            let entry = ProvenanceEntry {
                origin_tier: 3, // invalid: max is 2
                operator_id: 0,
                precision_mode: 0,
                b_q: 0, d_q: 0, a_q: 0,
                time_offset: 0,
            };
            assert_eq!(
                encode_provenance_entry(&entry),
                Err(SecurityError::InvalidOriginTier(3))
            );
        }

        #[test]
        fn entry_invalid_operator_id() {
            let entry = ProvenanceEntry {
                origin_tier: 0,
                operator_id: 16, // invalid: max is 15 (4 bits)
                precision_mode: 0,
                b_q: 0, d_q: 0, a_q: 0,
                time_offset: 0,
            };
            assert_eq!(
                encode_provenance_entry(&entry),
                Err(SecurityError::InvalidOperatorId(16))
            );
        }

        #[test]
        fn entry_invalid_precision_mode() {
            let entry = ProvenanceEntry {
                origin_tier: 0,
                operator_id: 0,
                precision_mode: 3, // invalid: max is 2
                b_q: 0, d_q: 0, a_q: 0,
                time_offset: 0,
            };
            assert_eq!(
                encode_provenance_entry(&entry),
                Err(SecurityError::InvalidPrecisionMode(3))
            );
        }

        #[test]
        fn entry_insufficient_data() {
            let result = decode_provenance_entry(&[0x00, 0x01, 0x02]);
            assert_eq!(
                result,
                Err(SecurityError::InsufficientData { expected: 6, got: 3 })
            );
        }

        #[test]
        fn entry_empty_data() {
            let result = decode_provenance_entry(&[]);
            assert_eq!(
                result,
                Err(SecurityError::InsufficientData { expected: 6, got: 0 })
            );
        }

        // ---------------------------------------------------------------
        // Wire size verification
        // ---------------------------------------------------------------

        #[test]
        fn entry_wire_size_exactly_6() {
            // Verify the claim: 48 bits = 6 bytes, zero waste
            // Byte 0: 2+4+2 = 8 bits
            // Bytes 1-3: 3×8 = 24 bits
            // Bytes 4-5: 16 bits
            // Total: 8+24+16 = 48 bits = 6 bytes
            assert_eq!(PROVENANCE_ENTRY_SIZE, 6);
            assert_eq!(8 + 24 + 16, 48);  // bit budget
            assert_eq!(48 / 8, 6);         // byte count
        }

        // ---------------------------------------------------------------
        // Python interop — byte-exact cross-validation
        //
        // The Python format uses 16-byte entries with absolute timestamps
        // and prev_digest. The compact Rust format is 6 bytes with
        // time_offset and no digest. Byte 0 layout is IDENTICAL:
        //   [origin_tier:2][operator_id:4][precision_mode:2]
        // Bytes 1-3 (opinion) are also identical.
        // We verify byte 0 and opinion bytes match Python's encoding.
        // ---------------------------------------------------------------

        #[test]
        fn python_interop_byte0_tier0_none() {
            // Python: byte0 = (0 << 6) | (0 << 2) | 0 = 0x00
            let entry = ProvenanceEntry {
                origin_tier: 0,
                operator_id: 0,
                precision_mode: 0,
                b_q: 217, d_q: 13, a_q: 128,
                time_offset: 0,
            };
            let data = encode_provenance_entry(&entry).unwrap();
            assert_eq!(data[0], 0x00);
            assert_eq!(data[1], 217);
            assert_eq!(data[2], 13);
            assert_eq!(data[3], 128);
        }

        #[test]
        fn python_interop_byte0_tier1_jmeet() {
            // Python: byte0 = (1 << 6) | (4 << 2) | 0 = 0x50
            let entry = ProvenanceEntry {
                origin_tier: 1,
                operator_id: 4,
                precision_mode: 0,
                b_q: 200, d_q: 30, a_q: 128,
                time_offset: 60,
            };
            let data = encode_provenance_entry(&entry).unwrap();
            assert_eq!(data[0], 0x50);
        }

        #[test]
        fn python_interop_byte0_tier2_cumfusion() {
            // Python: byte0 = (2 << 6) | (1 << 2) | 0 = 0x84
            let entry = ProvenanceEntry {
                origin_tier: 2,
                operator_id: 1,
                precision_mode: 0,
                b_q: 180, d_q: 40, a_q: 128,
                time_offset: 120,
            };
            let data = encode_provenance_entry(&entry).unwrap();
            assert_eq!(data[0], 0x84);
        }

        // ---------------------------------------------------------------
        // Exhaustive byte 0 roundtrip: all valid (tier, op, pm) combos
        // 3 tiers × 16 operators × 3 precisions = 144 combinations
        // ---------------------------------------------------------------

        #[test]
        fn entry_exhaustive_byte0_roundtrip() {
            for tier in 0..=2u8 {
                for op in 0..=15u8 {
                    for pm in 0..=2u8 {
                        let original = ProvenanceEntry {
                            origin_tier: tier,
                            operator_id: op,
                            precision_mode: pm,
                            b_q: 100, d_q: 50, a_q: 128,
                            time_offset: 300,
                        };
                        let data = encode_provenance_entry(&original).unwrap();
                        let recovered = decode_provenance_entry(&data).unwrap();
                        assert_eq!(recovered, original,
                            "Failed: tier={tier}, op={op}, pm={pm}");
                    }
                }
            }
        }
    }

    // ===================================================================
    // 3. GF(2⁸) Arithmetic + CRC-8
    // ===================================================================

    mod gf_crc {
        use super::*;

        // ---------------------------------------------------------------
        // GF(2⁸) primitivity: α=0x03 generates all 255 non-zero elements
        // ---------------------------------------------------------------

        #[test]
        fn alpha_is_primitive() {
            // α=0x03 must generate all 255 non-zero elements of GF(2^8).
            // If this fails, localization is unsound for positions outside
            // the generated subgroup (see SYNDROME_LOCALIZATION.md §2.1).
            let mut seen = [false; 256];
            let mut val: u8 = 1; // α⁰ = 1
            for _ in 0..255 {
                assert!(!seen[val as usize], "Duplicate: α generated {val} twice");
                seen[val as usize] = true;
                val = gf_mul(val, 0x03);
            }
            // After 255 multiplications, must return to 1
            assert_eq!(val, 1, "α^255 should equal 1, got {val}");
            // All 255 non-zero elements must have been visited
            for v in 1..=255u16 {
                assert!(seen[v as usize], "Element {v} not generated by α=0x03");
            }
            // Zero must NOT be generated
            assert!(!seen[0], "Zero should not be in the generated group");
        }

        // ---------------------------------------------------------------
        // GF(2⁸) field axioms
        // ---------------------------------------------------------------

        #[test]
        fn gf_mul_identity() {
            for a in 0..=255u8 {
                assert_eq!(gf_mul(a, 1), a, "a*1 should equal a for a={a}");
                assert_eq!(gf_mul(1, a), a, "1*a should equal a for a={a}");
            }
        }

        #[test]
        fn gf_mul_zero() {
            for a in 0..=255u8 {
                assert_eq!(gf_mul(a, 0), 0, "a*0 should equal 0 for a={a}");
                assert_eq!(gf_mul(0, a), 0, "0*a should equal 0 for a={a}");
            }
        }

        #[test]
        fn gf_mul_commutativity() {
            // Exhaustive: all 256×256 = 65,536 pairs
            for a in 0..=255u8 {
                for b in 0..=255u8 {
                    assert_eq!(gf_mul(a, b), gf_mul(b, a),
                        "Commutativity failed: {a}*{b}");
                }
            }
        }

        #[test]
        fn gf_inverse_all_nonzero() {
            for a in 1..=255u8 {
                let inv = gf_inv(a);
                assert_eq!(gf_mul(a, inv), 1,
                    "Inverse failed: {a} * {inv} = {}, expected 1",
                    gf_mul(a, inv));
            }
        }

        // ---------------------------------------------------------------
        // exp/log roundtrip
        // ---------------------------------------------------------------

        #[test]
        fn gf_exp_log_roundtrip_all() {
            // For all non-zero v: gf_exp(gf_log(v)) == v
            for v in 1..=255u8 {
                let log_v = gf_log(v);
                let exp_log_v = gf_exp(log_v);
                assert_eq!(exp_log_v, v,
                    "exp(log({v})) = exp({log_v}) = {exp_log_v}, expected {v}");
            }
        }

        #[test]
        fn gf_log_exp_roundtrip_all() {
            // For all powers 0..254: gf_log(gf_exp(i)) == i
            for i in 0..255u8 {
                let exp_i = gf_exp(i);
                let log_exp_i = gf_log(exp_i);
                assert_eq!(log_exp_i, i,
                    "log(exp({i})) = log({exp_i}) = {log_exp_i}, expected {i}");
            }
        }

        #[test]
        fn gf_exp_zero_is_one() {
            assert_eq!(gf_exp(0), 1, "α⁰ must equal 1");
        }

        #[test]
        fn gf_exp_one_is_alpha() {
            assert_eq!(gf_exp(1), 0x03, "α¹ must equal 0x03");
        }

        #[test]
        fn gf_log_one_is_zero() {
            assert_eq!(gf_log(1), 0, "log(1) must equal 0 (α⁰ = 1)");
        }

        #[test]
        fn gf_log_alpha_is_one() {
            assert_eq!(gf_log(0x03), 1, "log(α) must equal 1");
        }

        // ---------------------------------------------------------------
        // Known power values (cross-check with Python verification)
        // ---------------------------------------------------------------

        #[test]
        fn gf_exp_known_values() {
            // Hand-computed powers of α=0x03 in GF(2⁸) mod 0x11B:
            //   α⁰ = 1, α¹ = 3, α² = gf_mul(3,3) = 5
            //   α³ = gf_mul(5,3) = 15, α⁴ = gf_mul(15,3) = 17
            //   α⁵ = gf_mul(17,3) = 17^34 = 51 = 0x33
            //   α⁶ = gf_mul(51,3) = 51^102 = 85 = 0x55
            //   α⁷ = gf_mul(85,3) = 85^170 = 255 = 0xFF
            assert_eq!(gf_exp(0), 0x01);
            assert_eq!(gf_exp(1), 0x03);
            assert_eq!(gf_exp(2), 0x05);
            assert_eq!(gf_exp(3), 0x0F);
            assert_eq!(gf_exp(4), 0x11);
            assert_eq!(gf_exp(5), 0x33);
            assert_eq!(gf_exp(6), 0x55);
            assert_eq!(gf_exp(7), 0xFF);
        }

        // ---------------------------------------------------------------
        // CRC-8/CCITT
        // ---------------------------------------------------------------

        #[test]
        fn crc8_deterministic() {
            let data = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
            assert_eq!(crc8(&data), crc8(&data));
        }

        #[test]
        fn crc8_empty_is_zero() {
            // CRC-8 with init=0x00 over empty input is 0
            assert_eq!(crc8(&[]), 0);
        }

        #[test]
        fn crc8_detects_all_single_bit_flips() {
            // For a 6-byte entry (48 bits), every single-bit flip
            // must produce a different CRC. This is guaranteed by
            // polynomial construction, not probabilistic.
            let original = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06];
            let orig_crc = crc8(&original);
            let mut flips_detected = 0u32;
            let mut total_flips = 0u32;
            for byte_pos in 0..6 {
                for bit_pos in 0..8u8 {
                    let mut flipped = original;
                    flipped[byte_pos] ^= 1 << bit_pos;
                    total_flips += 1;
                    if crc8(&flipped) != orig_crc {
                        flips_detected += 1;
                    }
                }
            }
            assert_eq!(flips_detected, total_flips,
                "CRC-8 must detect ALL {total_flips} single-bit flips, detected {flips_detected}");
        }

        #[test]
        fn crc8_different_data_different_crc() {
            // Not guaranteed in general, but overwhelmingly likely
            // for these structured inputs
            let a = [0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00];
            let b = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
            assert_ne!(crc8(&a), crc8(&b));
        }

        // ---------------------------------------------------------------
        // Static storage size verification
        // ---------------------------------------------------------------

        #[test]
        fn total_table_storage_768_bytes() {
            // GF exp table: 256 bytes
            // GF log table: 256 bytes
            // CRC-8 table:  256 bytes
            // Total: 768 bytes — fits on any microcontroller
            assert_eq!(256 + 256 + 256, 768);
        }
    }

    // ===================================================================
    // 4. Syndrome Computation — 2t bytes
    // ===================================================================

    mod syndrome {
        use super::*;

        // ---------------------------------------------------------------
        // compute_syndromes: validation
        // ---------------------------------------------------------------

        #[test]
        fn syndromes_t0_invalid() {
            let entry = [0u8; 6];
            let result = compute_syndromes(&[entry], 0);
            assert_eq!(result, Err(SecurityError::InvalidT(0)));
        }

        #[test]
        fn syndromes_t8_invalid() {
            let entry = [0u8; 6];
            let result = compute_syndromes(&[entry], 8);
            assert_eq!(result, Err(SecurityError::InvalidT(8)));
        }

        #[test]
        fn syndromes_t7_valid() {
            let entry = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06];
            let result = compute_syndromes(&[entry], 7);
            assert!(result.is_ok());
        }

        #[test]
        fn syndromes_chain_too_long() {
            // n=256 exceeds GF(2⁸) range (max 255)
            let entries: [[u8; 6]; 256] = [[0xAA; 6]; 256];
            let result = compute_syndromes(&entries, 1);
            assert!(result.is_err());
        }

        // ---------------------------------------------------------------
        // compute_syndromes: mathematical correctness
        //
        // S_k = XOR_{i=0}^{n-1} (alpha^{k*i} * h(e_i))
        // ---------------------------------------------------------------

        #[test]
        fn syndromes_empty_chain_all_zero() {
            // XOR of empty set is 0 for all syndrome positions
            let empty: &[[u8; 6]] = &[];
            let s = compute_syndromes(empty, 1).unwrap();
            assert_eq!(s[0], 0);
            assert_eq!(s[1], 0);
        }

        #[test]
        fn syndromes_single_entry_t1() {
            // n=1: S0 = alpha^0 * h(e0) = h(e0)
            //      S1 = alpha^0 * h(e0) = h(e0)
            // (because k*i = k*0 = 0 for i=0, so weight = alpha^0 = 1)
            let entry = [0x50u8, 0xC8, 0x1E, 0x80, 0x00, 0x3C];
            let h = crc8(&entry);
            let s = compute_syndromes(&[entry], 1).unwrap();
            assert_eq!(s[0], h, "S0 = h(e0) for single entry");
            assert_eq!(s[1], h, "S1 = h(e0) for single entry");
        }

        #[test]
        fn syndromes_single_entry_all_k_equal_hash() {
            // For n=1, ALL S_k = alpha^{k*0} * h(e0) = 1 * h(e0) = h(e0)
            let entry = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06];
            let h = crc8(&entry);
            let s = compute_syndromes(&[entry], MAX_T).unwrap();
            for k in 0..(2 * MAX_T as usize) {
                assert_eq!(s[k], h, "S_{k} should equal h for single entry");
            }
        }

        #[test]
        fn syndromes_two_entries_t1_manual() {
            // n=2, t=1:
            //   h0 = crc8(e0), h1 = crc8(e1)
            //   S0 = (alpha^0 * h0) XOR (alpha^0 * h1) = h0 XOR h1
            //   S1 = (alpha^0 * h0) XOR (alpha^1 * h1) = h0 XOR gf_mul(3, h1)
            let e0 = [0x00u8, 0xD9, 0x0D, 0x80, 0x00, 0x00];
            let e1 = [0x50u8, 0xC8, 0x1E, 0x80, 0x00, 0x3C];
            let h0 = crc8(&e0);
            let h1 = crc8(&e1);
            let s = compute_syndromes(&[e0, e1], 1).unwrap();
            assert_eq!(s[0], h0 ^ h1, "S0 = h0 XOR h1");
            assert_eq!(s[1], h0 ^ gf_mul(0x03, h1), "S1 = h0 XOR alpha*h1");
        }

        #[test]
        fn syndromes_three_entries_s0_is_xor_of_hashes() {
            // S0 = XOR of all h(e_i) (since alpha^0 = 1 for all terms)
            let e0 = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06];
            let e1 = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
            let e2 = [0x50, 0xC8, 0x1E, 0x80, 0x00, 0x3C];
            let s = compute_syndromes(&[e0, e1, e2], 1).unwrap();
            let expected_s0 = crc8(&e0) ^ crc8(&e1) ^ crc8(&e2);
            assert_eq!(s[0], expected_s0);
        }

        #[test]
        fn syndromes_three_entries_s1_manual() {
            // S1 = alpha^0*h0 XOR alpha^1*h1 XOR alpha^2*h2
            //    = h0 XOR gf_mul(3, h1) XOR gf_mul(gf_exp(2), h2)
            let e0 = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06];
            let e1 = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
            let e2 = [0x50, 0xC8, 0x1E, 0x80, 0x00, 0x3C];
            let h0 = crc8(&e0);
            let h1 = crc8(&e1);
            let h2 = crc8(&e2);
            let s = compute_syndromes(&[e0, e1, e2], 1).unwrap();
            let expected_s1 = h0 ^ gf_mul(gf_exp(1), h1) ^ gf_mul(gf_exp(2), h2);
            assert_eq!(s[1], expected_s1);
        }

        #[test]
        fn syndromes_t2_four_entries_manual() {
            // t=2 → 4 syndrome bytes: S0, S1, S2, S3
            // S2 = XOR_i alpha^{2i} * h(e_i)
            // S3 = XOR_i alpha^{3i} * h(e_i)
            let entries: [[u8; 6]; 4] = [
                [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
                [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE],
                [0x50, 0xC8, 0x1E, 0x80, 0x00, 0x3C],
                [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            ];
            let h: [u8; 4] = core::array::from_fn(|i| crc8(&entries[i]));
            let s = compute_syndromes(&entries, 2).unwrap();

            // S2 = alpha^0*h0 XOR alpha^2*h1 XOR alpha^4*h2 XOR alpha^6*h3
            let expected_s2 = h[0]
                ^ gf_mul(gf_exp(2), h[1])
                ^ gf_mul(gf_exp(4), h[2])
                ^ gf_mul(gf_exp(6), h[3]);
            assert_eq!(s[2], expected_s2, "S2 manual check");

            // S3 = alpha^0*h0 XOR alpha^3*h1 XOR alpha^6*h2 XOR alpha^9*h3
            let expected_s3 = h[0]
                ^ gf_mul(gf_exp(3), h[1])
                ^ gf_mul(gf_exp(6), h[2])
                ^ gf_mul(gf_exp(9), h[3]);
            assert_eq!(s[3], expected_s3, "S3 manual check");
        }

        #[test]
        fn syndromes_deterministic() {
            let entries = [
                [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06],
                [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE],
            ];
            let s1 = compute_syndromes(&entries, 1).unwrap();
            let s2 = compute_syndromes(&entries, 1).unwrap();
            assert_eq!(s1[0], s2[0]);
            assert_eq!(s1[1], s2[1]);
        }

        #[test]
        fn syndromes_unused_bytes_are_zero() {
            // For t=1, only s[0] and s[1] are meaningful.
            // Remaining s[2..14] should be zero-initialized.
            let entry = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06];
            let s = compute_syndromes(&[entry], 1).unwrap();
            for k in 2..MAX_SYNDROME_BYTES {
                assert_eq!(s[k], 0, "Unused syndrome byte {k} should be 0");
            }
        }

        // ---------------------------------------------------------------
        // Localization roundtrip property:
        // compute syndromes, tamper one entry, recompute, verify delta
        // algebra yields correct position.
        // This validates the FULL pipeline, not just individual functions.
        // ---------------------------------------------------------------

        #[test]
        fn syndromes_tamper_roundtrip_position0_of5() {
            let entries = [
                [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06],
                [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE],
                [0x50, 0xC8, 0x1E, 0x80, 0x00, 0x3C],
                [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
                [0x10, 0x20, 0x30, 0x40, 0x50, 0x60],
            ];
            let s_orig = compute_syndromes(&entries, 1).unwrap();
            let mut tampered = entries;
            tampered[0][0] ^= 0x01; // single-bit flip (guaranteed CRC change)
            let s_recv = compute_syndromes(&tampered, 1).unwrap();

            // Manual delta computation: j = log_alpha(delta1 / delta0)
            let delta0 = s_orig[0] ^ s_recv[0];
            let delta1 = s_orig[1] ^ s_recv[1];
            assert_ne!(delta0, 0, "CRC must change on bit flip");
            let alpha_j = gf_mul(delta1, gf_inv(delta0));
            let j = gf_log(alpha_j);
            assert_eq!(j, 0, "Manual localization should find position 0");
        }

        #[test]
        fn syndromes_tamper_roundtrip_position3_of5() {
            let entries = [
                [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06],
                [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE],
                [0x50, 0xC8, 0x1E, 0x80, 0x00, 0x3C],
                [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
                [0x10, 0x20, 0x30, 0x40, 0x50, 0x60],
            ];
            let s_orig = compute_syndromes(&entries, 1).unwrap();
            let mut tampered = entries;
            tampered[3][2] ^= 0x40; // flip bit in entry 3
            let s_recv = compute_syndromes(&tampered, 1).unwrap();

            let delta0 = s_orig[0] ^ s_recv[0];
            let delta1 = s_orig[1] ^ s_recv[1];
            assert_ne!(delta0, 0);
            let alpha_j = gf_mul(delta1, gf_inv(delta0));
            let j = gf_log(alpha_j);
            assert_eq!(j, 3, "Manual localization should find position 3");
        }

        #[test]
        fn syndromes_localize_each_position_n10() {
            // Verify delta algebra localizes correctly for ALL 10 positions
            let entries: [[u8; 6]; 10] = core::array::from_fn(|i| {
                let i = i as u8;
                [i.wrapping_mul(17), i.wrapping_mul(31), i.wrapping_mul(47),
                 i.wrapping_mul(63), i.wrapping_mul(79), i.wrapping_mul(97)]
            });
            let s_orig = compute_syndromes(&entries, 1).unwrap();

            for j in 0..10u8 {
                let mut tampered = entries;
                tampered[j as usize][1] ^= 0x80; // single-bit flip
                let s_recv = compute_syndromes(&tampered, 1).unwrap();

                let delta0 = s_orig[0] ^ s_recv[0];
                let delta1 = s_orig[1] ^ s_recv[1];
                assert_ne!(delta0, 0, "CRC must change at position {j}");
                let alpha_j = gf_mul(delta1, gf_inv(delta0));
                let recovered = gf_log(alpha_j);
                assert_eq!(recovered, j, "Localization failed at position {j}");
            }
        }

        // ---------------------------------------------------------------
        // localize_single_tamper: validation
        // ---------------------------------------------------------------

        #[test]
        fn localize_mismatched_lengths() {
            let result = localize_single_tamper(&[0x00, 0x00], &[0x00]);
            assert_eq!(
                result,
                Err(SecurityError::SyndromeLengthMismatch { stored: 2, received: 1 })
            );
        }

        #[test]
        fn localize_too_short() {
            // Need at least 2 syndrome bytes (t=1) for single-entry localization
            let result = localize_single_tamper(&[0x00], &[0x00]);
            assert_eq!(result, Err(SecurityError::SyndromeTooShort(1)));
        }

        #[test]
        fn localize_empty_slices() {
            let result = localize_single_tamper(&[], &[]);
            assert_eq!(result, Err(SecurityError::SyndromeTooShort(0)));
        }

        // ---------------------------------------------------------------
        // localize_single_tamper: NoChange
        // ---------------------------------------------------------------

        #[test]
        fn localize_no_change_zeros() {
            let s = [0u8, 0u8];
            assert_eq!(
                localize_single_tamper(&s, &s).unwrap(),
                LocalizationResult::NoChange
            );
        }

        #[test]
        fn localize_no_change_nonzero_matching() {
            let s = [0xAB, 0xCD];
            assert_eq!(
                localize_single_tamper(&s, &s).unwrap(),
                LocalizationResult::NoChange
            );
        }

        // ---------------------------------------------------------------
        // localize_single_tamper: MultiTamper (inconsistent deltas)
        // ---------------------------------------------------------------

        #[test]
        fn localize_delta0_zero_delta1_nonzero_is_multi() {
            // delta0=0 but delta1≠0: impossible for single entry, indicates multi
            let stored   = [0xAA, 0xBB];
            let received = [0xAA, 0xCC]; // delta0=0, delta1=0xBB^0xCC=0x77
            assert_eq!(
                localize_single_tamper(&stored, &received).unwrap(),
                LocalizationResult::MultiTamper
            );
        }

        #[test]
        fn localize_delta0_nonzero_delta1_zero_is_multi() {
            // delta0≠0 but delta1=0: would require α^j=0, impossible in GF(2⁸)
            let stored   = [0xAA, 0xBB];
            let received = [0xCC, 0xBB]; // delta0=0xAA^0xCC=0x66, delta1=0
            assert_eq!(
                localize_single_tamper(&stored, &received).unwrap(),
                LocalizationResult::MultiTamper
            );
        }

        // ---------------------------------------------------------------
        // localize_single_tamper: SingleTamper (correct index recovery)
        // ---------------------------------------------------------------

        #[test]
        fn localize_position0_of5() {
            let entries = [
                [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06],
                [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE],
                [0x50, 0xC8, 0x1E, 0x80, 0x00, 0x3C],
                [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
                [0x10, 0x20, 0x30, 0x40, 0x50, 0x60],
            ];
            let s_orig = compute_syndromes(&entries, 1).unwrap();
            let mut tampered = entries;
            tampered[0][0] ^= 0x01;
            let s_recv = compute_syndromes(&tampered, 1).unwrap();
            assert_eq!(
                localize_single_tamper(&s_orig[..2], &s_recv[..2]).unwrap(),
                LocalizationResult::SingleTamper { index: 0 }
            );
        }

        #[test]
        fn localize_position4_of5() {
            let entries = [
                [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06],
                [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE],
                [0x50, 0xC8, 0x1E, 0x80, 0x00, 0x3C],
                [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
                [0x10, 0x20, 0x30, 0x40, 0x50, 0x60],
            ];
            let s_orig = compute_syndromes(&entries, 1).unwrap();
            let mut tampered = entries;
            tampered[4][3] ^= 0x20;
            let s_recv = compute_syndromes(&tampered, 1).unwrap();
            assert_eq!(
                localize_single_tamper(&s_orig[..2], &s_recv[..2]).unwrap(),
                LocalizationResult::SingleTamper { index: 4 }
            );
        }

        #[test]
        fn localize_all_positions_n9() {
            // Typical IoT pipeline: 8 sensors + 1 fusion = 9 entries
            let entries: [[u8; 6]; 9] = core::array::from_fn(|i| {
                let i = i as u8;
                [i.wrapping_mul(13), i.wrapping_mul(29), i.wrapping_mul(41),
                 i.wrapping_mul(59), i.wrapping_mul(71), i.wrapping_mul(83)]
            });
            let s_orig = compute_syndromes(&entries, 1).unwrap();

            for j in 0..9u8 {
                let mut tampered = entries;
                tampered[j as usize][0] ^= 0x04;
                let s_recv = compute_syndromes(&tampered, 1).unwrap();
                assert_eq!(
                    localize_single_tamper(&s_orig[..2], &s_recv[..2]).unwrap(),
                    LocalizationResult::SingleTamper { index: j },
                    "Failed to localize position {j}"
                );
            }
        }

        #[test]
        fn localize_untampered_chain_no_change() {
            let entries = [
                [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06],
                [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE],
            ];
            let s = compute_syndromes(&entries, 1).unwrap();
            assert_eq!(
                localize_single_tamper(&s[..2], &s[..2]).unwrap(),
                LocalizationResult::NoChange
            );
        }

        #[test]
        fn localize_works_with_longer_syndrome_slices() {
            // If caller passes t=2 (4 bytes), localize_single_tamper
            // uses only the first 2 (S0, S1). Should still work.
            let entries = [
                [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06],
                [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE],
                [0x50, 0xC8, 0x1E, 0x80, 0x00, 0x3C],
            ];
            let s_orig = compute_syndromes(&entries, 2).unwrap();
            let mut tampered = entries;
            tampered[2][5] ^= 0x10;
            let s_recv = compute_syndromes(&tampered, 2).unwrap();
            // Pass all 4 bytes — function should use first 2
            assert_eq!(
                localize_single_tamper(&s_orig[..4], &s_recv[..4]).unwrap(),
                LocalizationResult::SingleTamper { index: 2 }
            );
        }
    }
}
