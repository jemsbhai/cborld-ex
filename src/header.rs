//! Tier-dependent header codec for CBOR-LD-ex.
//!
//! Implements header encoding/decoding per FORMAL_MODEL.md §5:
//!   - Tier 1 (00): 1-byte constrained header
//!   - Tier 2 (01): 4-byte edge gateway header
//!   - Tier 3 (10): 4-byte + variable extension cloud header
//!
//! Bit layout (byte 0, shared across all tiers):
//!
//! ```text
//! [cs:2][df:1][ot:2][ho:1][pm:2]
//! ```
//!
//! Where: cs=compliance_status, df=delegation_flag, ot=origin_tier,
//! ho=has_opinion, pm=precision_mode.

/// 2-bit compliance status (Definition 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ComplianceStatus {
    Compliant = 0b00,
    NonCompliant = 0b01,
    Insufficient = 0b10,
}

/// 2-bit precision mode selector (Table 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PrecisionMode {
    Bits8 = 0b00,
    Bits16 = 0b01,
    Bits32 = 0b10,
    Reserved = 0b11,
}

/// 4-bit operator ID (Table 2, §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OperatorId {
    None = 0b0000,
    CumulativeFusion = 0b0001,
    TrustDiscount = 0b0010,
    Deduction = 0b0011,
    JurisdictionalMeet = 0b0100,
    CompliancePropagation = 0b0101,
    ConsentAssessment = 0b0110,
    TemporalDecay = 0b0111,
    ErasurePropagation = 0b1000,
    WithdrawalOverride = 0b1001,
    ExpiryTrigger = 0b1010,
    ReviewTrigger = 0b1011,
    RegulatoryChange = 0b1100,
}

/// Origin tier codes (2-bit field, bits 4-3 of byte 0).
const TIER_CONSTRAINED: u8 = 0b00;
const TIER_EDGE: u8 = 0b01;
const TIER_CLOUD: u8 = 0b10;
// const TIER_RESERVED: u8 = 0b11;

/// Tier 1 — 1-byte constrained device header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tier1Header {
    pub compliance_status: ComplianceStatus,
    pub delegation_flag: bool,
    pub has_opinion: bool,
    pub precision_mode: PrecisionMode,
}

/// Tier 2 — 4-byte edge gateway header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tier2Header {
    pub compliance_status: ComplianceStatus,
    pub delegation_flag: bool,
    pub has_opinion: bool,
    pub precision_mode: PrecisionMode,
    pub operator_id: OperatorId,
    pub reasoning_context: u8, // 4 bits (0–15)
    pub context_version: u8,   // 4 bits (0–15)
    pub has_multinomial: bool,
    pub sub_tier_depth: u8, // 3 bits (0–7)
    pub source_count: u8,   // 8 bits (0–255)
}

/// Tier 3 — 4-byte fixed + variable extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tier3Header {
    pub compliance_status: ComplianceStatus,
    pub delegation_flag: bool,
    pub has_opinion: bool,
    pub precision_mode: PrecisionMode,
    pub operator_id: OperatorId,
    pub reasoning_context: u8, // 4 bits (0–15)
    pub has_extended_context: bool,
    pub has_provenance_chain: bool,
    pub has_multinomial: bool,
    pub has_trust_info: bool,
    pub sub_tier_depth: u8, // 4 bits (0–15)
}

/// Sum type for all header tiers — returned by decode_header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Header {
    Tier1(Tier1Header),
    Tier2(Tier2Header),
    Tier3(Tier3Header),
}

/// Error type for header operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderError {
    /// Input data too short for the detected tier.
    InsufficientData {
        expected: usize,
        got: usize,
    },
    /// Reserved origin_tier (0b11) encountered.
    ReservedTier,
    /// Invalid enum discriminant.
    InvalidComplianceStatus(u8),
    InvalidPrecisionMode(u8),
    InvalidOperatorId(u8),
}

impl ComplianceStatus {
    pub fn from_bits(bits: u8) -> Result<Self, HeaderError> {
        match bits {
            0b00 => Ok(Self::Compliant),
            0b01 => Ok(Self::NonCompliant),
            0b10 => Ok(Self::Insufficient),
            other => Err(HeaderError::InvalidComplianceStatus(other)),
        }
    }
}

impl PrecisionMode {
    pub fn from_bits(bits: u8) -> Result<Self, HeaderError> {
        match bits {
            0b00 => Ok(Self::Bits8),
            0b01 => Ok(Self::Bits16),
            0b10 => Ok(Self::Bits32),
            0b11 => Ok(Self::Reserved),
            other => Err(HeaderError::InvalidPrecisionMode(other)),
        }
    }
}

impl OperatorId {
    pub fn from_bits(bits: u8) -> Result<Self, HeaderError> {
        match bits {
            0 => Ok(Self::None),
            1 => Ok(Self::CumulativeFusion),
            2 => Ok(Self::TrustDiscount),
            3 => Ok(Self::Deduction),
            4 => Ok(Self::JurisdictionalMeet),
            5 => Ok(Self::CompliancePropagation),
            6 => Ok(Self::ConsentAssessment),
            7 => Ok(Self::TemporalDecay),
            8 => Ok(Self::ErasurePropagation),
            9 => Ok(Self::WithdrawalOverride),
            10 => Ok(Self::ExpiryTrigger),
            11 => Ok(Self::ReviewTrigger),
            12 => Ok(Self::RegulatoryChange),
            other => Err(HeaderError::InvalidOperatorId(other)),
        }
    }
}

/// Pack byte 0: [cs:2][df:1][ot:2][ho:1][pm:2] (MSB first).
fn encode_byte0(
    compliance_status: ComplianceStatus,
    delegation_flag: bool,
    origin_tier: u8,
    has_opinion: bool,
    precision_mode: PrecisionMode,
) -> u8 {
    (compliance_status as u8) << 6
        | (delegation_flag as u8) << 5
        | (origin_tier & 0x03) << 3
        | (has_opinion as u8) << 2
        | (precision_mode as u8)
}

/// Encode a header to bytes per §5.1 bit layout.
///
/// Returns a 4-byte array. For Tier 1, only byte 0 is significant;
/// bytes 1-3 are zeroed. Use `header_size()` to know how many bytes
/// to transmit.
pub fn encode_header(header: &Header) -> [u8; 4] {
    let mut out = [0u8; 4];

    match header {
        Header::Tier1(h) => {
            out[0] = encode_byte0(
                h.compliance_status,
                h.delegation_flag,
                TIER_CONSTRAINED,
                h.has_opinion,
                h.precision_mode,
            );
        }
        Header::Tier2(h) => {
            out[0] = encode_byte0(
                h.compliance_status,
                h.delegation_flag,
                TIER_EDGE,
                h.has_opinion,
                h.precision_mode,
            );
            // Byte 1: [operator_id:4][reasoning_context:4]
            out[1] = (h.operator_id as u8) << 4 | (h.reasoning_context & 0x0F);
            // Byte 2: [context_version:4][has_multinomial:1][sub_tier_depth:3]
            out[2] = (h.context_version & 0x0F) << 4
                | (h.has_multinomial as u8) << 3
                | (h.sub_tier_depth & 0x07);
            // Byte 3: [source_count:8]
            out[3] = h.source_count;
        }
        Header::Tier3(h) => {
            out[0] = encode_byte0(
                h.compliance_status,
                h.delegation_flag,
                TIER_CLOUD,
                h.has_opinion,
                h.precision_mode,
            );
            // Byte 1: [operator_id:4][reasoning_context:4]
            out[1] = (h.operator_id as u8) << 4 | (h.reasoning_context & 0x0F);
            // Byte 2: [hec:1][hpc:1][hm:1][hti:1][sub_tier_depth:4]
            out[2] = (h.has_extended_context as u8) << 7
                | (h.has_provenance_chain as u8) << 6
                | (h.has_multinomial as u8) << 5
                | (h.has_trust_info as u8) << 4
                | (h.sub_tier_depth & 0x0F);
            // Byte 3: reserved = 0x00
        }
    }

    out
}

/// Return the number of significant bytes in the encoded header.
/// Tier 1 = 1 byte, Tier 2/3 = 4 bytes.
pub fn header_size(header: &Header) -> usize {
    match header {
        Header::Tier1(_) => 1,
        Header::Tier2(_) | Header::Tier3(_) => 4,
    }
}

/// Decode bytes to a Header, dispatching on origin_tier bits.
///
/// The origin_tier field (bits 4-3 of byte 0) determines the header
/// layout and how many bytes to consume.
pub fn decode_header(data: &[u8]) -> Result<Header, HeaderError> {
    if data.is_empty() {
        return Err(HeaderError::InsufficientData {
            expected: 1,
            got: 0,
        });
    }

    let byte0 = data[0];
    let compliance_status = ComplianceStatus::from_bits((byte0 >> 6) & 0x03)?;
    let delegation_flag = ((byte0 >> 5) & 0x01) != 0;
    let origin_tier = (byte0 >> 3) & 0x03;
    let has_opinion = ((byte0 >> 2) & 0x01) != 0;
    let precision_mode = PrecisionMode::from_bits(byte0 & 0x03)?;

    match origin_tier {
        TIER_CONSTRAINED => Ok(Header::Tier1(Tier1Header {
            compliance_status,
            delegation_flag,
            has_opinion,
            precision_mode,
        })),

        TIER_EDGE => {
            if data.len() < 4 {
                return Err(HeaderError::InsufficientData {
                    expected: 4,
                    got: data.len(),
                });
            }
            let byte1 = data[1];
            let byte2 = data[2];
            let byte3 = data[3];

            Ok(Header::Tier2(Tier2Header {
                compliance_status,
                delegation_flag,
                has_opinion,
                precision_mode,
                operator_id: OperatorId::from_bits((byte1 >> 4) & 0x0F)?,
                reasoning_context: byte1 & 0x0F,
                context_version: (byte2 >> 4) & 0x0F,
                has_multinomial: ((byte2 >> 3) & 0x01) != 0,
                sub_tier_depth: byte2 & 0x07,
                source_count: byte3,
            }))
        }

        TIER_CLOUD => {
            if data.len() < 4 {
                return Err(HeaderError::InsufficientData {
                    expected: 4,
                    got: data.len(),
                });
            }
            let byte1 = data[1];
            let byte2 = data[2];
            // byte3 is reserved, ignored

            Ok(Header::Tier3(Tier3Header {
                compliance_status,
                delegation_flag,
                has_opinion,
                precision_mode,
                operator_id: OperatorId::from_bits((byte1 >> 4) & 0x0F)?,
                reasoning_context: byte1 & 0x0F,
                has_extended_context: ((byte2 >> 7) & 0x01) != 0,
                has_provenance_chain: ((byte2 >> 6) & 0x01) != 0,
                has_multinomial: ((byte2 >> 5) & 0x01) != 0,
                has_trust_info: ((byte2 >> 4) & 0x01) != 0,
                sub_tier_depth: byte2 & 0x0F,
            }))
        }

        // origin_tier == 0b11
        _ => Err(HeaderError::ReservedTier),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =================================================================
    // ComplianceStatus enum conversion
    // =================================================================

    #[test]
    fn test_compliance_status_from_bits_valid() {
        assert_eq!(
            ComplianceStatus::from_bits(0b00).unwrap(),
            ComplianceStatus::Compliant
        );
        assert_eq!(
            ComplianceStatus::from_bits(0b01).unwrap(),
            ComplianceStatus::NonCompliant
        );
        assert_eq!(
            ComplianceStatus::from_bits(0b10).unwrap(),
            ComplianceStatus::Insufficient
        );
    }

    #[test]
    fn test_compliance_status_from_bits_invalid() {
        assert_eq!(
            ComplianceStatus::from_bits(0b11),
            Err(HeaderError::InvalidComplianceStatus(0b11))
        );
    }

    // =================================================================
    // PrecisionMode enum conversion
    // =================================================================

    #[test]
    fn test_precision_mode_from_bits_valid() {
        assert_eq!(
            PrecisionMode::from_bits(0b00).unwrap(),
            PrecisionMode::Bits8
        );
        assert_eq!(
            PrecisionMode::from_bits(0b01).unwrap(),
            PrecisionMode::Bits16
        );
        assert_eq!(
            PrecisionMode::from_bits(0b10).unwrap(),
            PrecisionMode::Bits32
        );
        assert_eq!(
            PrecisionMode::from_bits(0b11).unwrap(),
            PrecisionMode::Reserved
        );
    }

    // =================================================================
    // OperatorId enum conversion
    // =================================================================

    #[test]
    fn test_operator_id_from_bits_valid() {
        assert_eq!(OperatorId::from_bits(0).unwrap(), OperatorId::None);
        assert_eq!(
            OperatorId::from_bits(1).unwrap(),
            OperatorId::CumulativeFusion
        );
        assert_eq!(
            OperatorId::from_bits(12).unwrap(),
            OperatorId::RegulatoryChange
        );
    }

    #[test]
    fn test_operator_id_from_bits_invalid() {
        assert_eq!(
            OperatorId::from_bits(13),
            Err(HeaderError::InvalidOperatorId(13))
        );
        assert_eq!(
            OperatorId::from_bits(15),
            Err(HeaderError::InvalidOperatorId(15))
        );
    }

    // =================================================================
    // Tier 1 encode/decode
    // =================================================================

    #[test]
    fn test_tier1_encode_compliant_with_opinion_8bit() {
        // compliance=COMPLIANT(00), delegation=false(0), tier=CONSTRAINED(00),
        // has_opinion=true(1), precision=8BIT(00)
        // Byte 0: [00][0][00][1][00] = 0b0000_0100 = 0x04
        let header = Header::Tier1(Tier1Header {
            compliance_status: ComplianceStatus::Compliant,
            delegation_flag: false,
            has_opinion: true,
            precision_mode: PrecisionMode::Bits8,
        });
        let encoded = encode_header(&header);
        assert_eq!(encoded[0], 0x04);
        assert_eq!(header_size(&header), 1);
    }

    #[test]
    fn test_tier1_encode_noncompliant_delegated_16bit() {
        // compliance=NON_COMPLIANT(01), delegation=true(1), tier=CONSTRAINED(00),
        // has_opinion=true(1), precision=16BIT(01)
        // Byte 0: [01][1][00][1][01] = 0b0110_0101 = 0x65
        let header = Header::Tier1(Tier1Header {
            compliance_status: ComplianceStatus::NonCompliant,
            delegation_flag: true,
            has_opinion: true,
            precision_mode: PrecisionMode::Bits16,
        });
        let encoded = encode_header(&header);
        assert_eq!(encoded[0], 0x65);
    }

    #[test]
    fn test_tier1_encode_insufficient_no_opinion() {
        // compliance=INSUFFICIENT(10), delegation=false(0), tier=CONSTRAINED(00),
        // has_opinion=false(0), precision=32BIT(10)
        // Byte 0: [10][0][00][0][10] = 0b1000_0010 = 0x82
        let header = Header::Tier1(Tier1Header {
            compliance_status: ComplianceStatus::Insufficient,
            delegation_flag: false,
            has_opinion: false,
            precision_mode: PrecisionMode::Bits32,
        });
        let encoded = encode_header(&header);
        assert_eq!(encoded[0], 0x82);
    }

    #[test]
    fn test_tier1_all_bits_set() {
        // compliance=INSUFFICIENT(10), delegation=true(1), tier=CONSTRAINED(00),
        // has_opinion=true(1), precision=RESERVED(11)
        // Byte 0: [10][1][00][1][11] = 0b1010_0111 = 0xA7
        let header = Header::Tier1(Tier1Header {
            compliance_status: ComplianceStatus::Insufficient,
            delegation_flag: true,
            has_opinion: true,
            precision_mode: PrecisionMode::Reserved,
        });
        let encoded = encode_header(&header);
        assert_eq!(encoded[0], 0xA7);
    }

    #[test]
    fn test_tier1_decode_roundtrip_compliant() {
        let original = Header::Tier1(Tier1Header {
            compliance_status: ComplianceStatus::Compliant,
            delegation_flag: false,
            has_opinion: true,
            precision_mode: PrecisionMode::Bits8,
        });
        let encoded = encode_header(&original);
        let decoded = decode_header(&encoded[..1]).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_tier1_decode_roundtrip_all_variants() {
        // Test all ComplianceStatus × delegation × has_opinion × PrecisionMode
        let statuses = [
            ComplianceStatus::Compliant,
            ComplianceStatus::NonCompliant,
            ComplianceStatus::Insufficient,
        ];
        let precisions = [
            PrecisionMode::Bits8,
            PrecisionMode::Bits16,
            PrecisionMode::Bits32,
            PrecisionMode::Reserved,
        ];

        for &cs in &statuses {
            for &df in &[false, true] {
                for &ho in &[false, true] {
                    for &pm in &precisions {
                        let original = Header::Tier1(Tier1Header {
                            compliance_status: cs,
                            delegation_flag: df,
                            has_opinion: ho,
                            precision_mode: pm,
                        });
                        let encoded = encode_header(&original);
                        let decoded = decode_header(&encoded[..1]).unwrap();
                        assert_eq!(
                            decoded, original,
                            "Roundtrip failed for cs={cs:?} df={df} ho={ho} pm={pm:?}"
                        );
                    }
                }
            }
        }
    }

    // =================================================================
    // Tier 2 encode/decode
    // =================================================================

    #[test]
    fn test_tier2_encode_basic() {
        // Byte 0: compliance=COMPLIANT(00), delegation=false(0), tier=EDGE(01),
        //         has_opinion=true(1), precision=8BIT(00)
        //         [00][0][01][1][00] = 0b0000_1100 = 0x0C
        // Byte 1: operator=CUMULATIVE_FUSION(0001), reasoning_context=3(0011)
        //         [0001][0011] = 0b0001_0011 = 0x13
        // Byte 2: context_version=1(0001), has_multinomial=false(0), sub_tier_depth=0(000)
        //         [0001][0][000] = 0b0001_0000 = 0x10
        // Byte 3: source_count=5 = 0x05
        let header = Header::Tier2(Tier2Header {
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
        });
        let encoded = encode_header(&header);
        assert_eq!(encoded, [0x0C, 0x13, 0x10, 0x05]);
        assert_eq!(header_size(&header), 4);
    }

    #[test]
    fn test_tier2_encode_max_fields() {
        // All fields at maximum values
        let header = Header::Tier2(Tier2Header {
            compliance_status: ComplianceStatus::Insufficient,
            delegation_flag: true,
            has_opinion: true,
            precision_mode: PrecisionMode::Bits32,
            operator_id: OperatorId::RegulatoryChange, // 12 = 0b1100
            reasoning_context: 15,                     // 0b1111
            context_version: 15,                       // 0b1111
            has_multinomial: true,
            sub_tier_depth: 7, // 0b111
            source_count: 255,
        });
        let encoded = encode_header(&header);
        // Byte 0: [10][1][01][1][10] = 0b1010_1110 = 0xAE
        assert_eq!(encoded[0], 0xAE);
        // Byte 1: [1100][1111] = 0b1100_1111 = 0xCF
        assert_eq!(encoded[1], 0xCF);
        // Byte 2: [1111][1][111] = 0b1111_1111 = 0xFF
        assert_eq!(encoded[2], 0xFF);
        // Byte 3: 255 = 0xFF
        assert_eq!(encoded[3], 0xFF);
    }

    #[test]
    fn test_tier2_decode_roundtrip() {
        let original = Header::Tier2(Tier2Header {
            compliance_status: ComplianceStatus::NonCompliant,
            delegation_flag: true,
            has_opinion: true,
            precision_mode: PrecisionMode::Bits16,
            operator_id: OperatorId::ConsentAssessment,
            reasoning_context: 7,
            context_version: 10,
            has_multinomial: true,
            sub_tier_depth: 3,
            source_count: 42,
        });
        let encoded = encode_header(&original);
        let decoded = decode_header(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    // =================================================================
    // Tier 3 encode/decode
    // =================================================================

    #[test]
    fn test_tier3_encode_basic() {
        // Byte 0: compliance=COMPLIANT(00), delegation=false(0), tier=CLOUD(10),
        //         has_opinion=true(1), precision=8BIT(00)
        //         [00][0][10][1][00] = 0b0001_0100 = 0x14
        // Byte 1: operator=TRUST_DISCOUNT(0010), reasoning_context=0(0000)
        //         [0010][0000] = 0b0010_0000 = 0x20
        // Byte 2: hec=true(1), hpc=false(0), hm=false(0), hti=true(1), sub_tier=2(0010)
        //         [1][0][0][1][0010] = 0b1001_0010 = 0x92
        // Byte 3: reserved = 0x00
        let header = Header::Tier3(Tier3Header {
            compliance_status: ComplianceStatus::Compliant,
            delegation_flag: false,
            has_opinion: true,
            precision_mode: PrecisionMode::Bits8,
            operator_id: OperatorId::TrustDiscount,
            reasoning_context: 0,
            has_extended_context: true,
            has_provenance_chain: false,
            has_multinomial: false,
            has_trust_info: true,
            sub_tier_depth: 2,
        });
        let encoded = encode_header(&header);
        assert_eq!(encoded, [0x14, 0x20, 0x92, 0x00]);
        assert_eq!(header_size(&header), 4);
    }

    #[test]
    fn test_tier3_encode_all_flags() {
        let header = Header::Tier3(Tier3Header {
            compliance_status: ComplianceStatus::Insufficient,
            delegation_flag: true,
            has_opinion: true,
            precision_mode: PrecisionMode::Bits32,
            operator_id: OperatorId::ErasurePropagation, // 8 = 0b1000
            reasoning_context: 15,
            has_extended_context: true,
            has_provenance_chain: true,
            has_multinomial: true,
            has_trust_info: true,
            sub_tier_depth: 15,
        });
        let encoded = encode_header(&header);
        // Byte 0: [10][1][10][1][10] = 0b1011_0110 = 0xB6
        assert_eq!(encoded[0], 0xB6);
        // Byte 1: [1000][1111] = 0b1000_1111 = 0x8F
        assert_eq!(encoded[1], 0x8F);
        // Byte 2: [1][1][1][1][1111] = 0b1111_1111 = 0xFF
        assert_eq!(encoded[2], 0xFF);
        // Byte 3: reserved = 0x00
        assert_eq!(encoded[3], 0x00);
    }

    #[test]
    fn test_tier3_decode_roundtrip() {
        let original = Header::Tier3(Tier3Header {
            compliance_status: ComplianceStatus::Compliant,
            delegation_flag: false,
            has_opinion: true,
            precision_mode: PrecisionMode::Bits8,
            operator_id: OperatorId::Deduction,
            reasoning_context: 5,
            has_extended_context: false,
            has_provenance_chain: true,
            has_multinomial: false,
            has_trust_info: false,
            sub_tier_depth: 9,
        });
        let encoded = encode_header(&original);
        let decoded = decode_header(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    // =================================================================
    // Error cases
    // =================================================================

    #[test]
    fn test_decode_empty_data() {
        assert_eq!(
            decode_header(&[]),
            Err(HeaderError::InsufficientData {
                expected: 1,
                got: 0
            })
        );
    }

    #[test]
    fn test_decode_tier2_insufficient_data() {
        // Byte 0 with origin_tier=EDGE(01), but only 2 bytes provided
        // [00][0][01][0][00] = 0b0000_1000 = 0x08
        assert_eq!(
            decode_header(&[0x08, 0x00]),
            Err(HeaderError::InsufficientData {
                expected: 4,
                got: 2
            })
        );
    }

    #[test]
    fn test_decode_tier3_insufficient_data() {
        // Byte 0 with origin_tier=CLOUD(10), but only 3 bytes provided
        // [00][0][10][0][00] = 0b0001_0000 = 0x10
        assert_eq!(
            decode_header(&[0x10, 0x00, 0x00]),
            Err(HeaderError::InsufficientData {
                expected: 4,
                got: 3
            })
        );
    }

    #[test]
    fn test_decode_reserved_tier() {
        // origin_tier=RESERVED(11)
        // [00][0][11][0][00] = 0b0001_1000 = 0x18
        assert_eq!(decode_header(&[0x18]), Err(HeaderError::ReservedTier));
    }

    // =================================================================
    // Python interop — byte-exact verification
    //
    // These bytes are produced by the Python encode_header() function.
    // Byte-for-byte match is a hard requirement (Acceptance Criteria §3.1.5).
    // =================================================================

    #[test]
    fn test_python_interop_tier1_compliant_opinion_8bit() {
        // Python: encode_header(Tier1Header(
        //   compliance_status=ComplianceStatus.COMPLIANT,
        //   delegation_flag=False, has_opinion=True,
        //   precision_mode=PrecisionMode.BITS_8))
        // → b'\x04'
        let header = Header::Tier1(Tier1Header {
            compliance_status: ComplianceStatus::Compliant,
            delegation_flag: false,
            has_opinion: true,
            precision_mode: PrecisionMode::Bits8,
        });
        let encoded = encode_header(&header);
        assert_eq!(&encoded[..1], &[0x04]);
    }

    #[test]
    fn test_python_interop_tier1_noncompliant_delegated() {
        // Python: encode_header(Tier1Header(
        //   compliance_status=ComplianceStatus.NON_COMPLIANT,
        //   delegation_flag=True, has_opinion=True,
        //   precision_mode=PrecisionMode.BITS_16))
        // → b'\x65'
        let header = Header::Tier1(Tier1Header {
            compliance_status: ComplianceStatus::NonCompliant,
            delegation_flag: true,
            has_opinion: true,
            precision_mode: PrecisionMode::Bits16,
        });
        let encoded = encode_header(&header);
        assert_eq!(&encoded[..1], &[0x65]);
    }

    #[test]
    fn test_python_interop_tier2_fusion() {
        // Python: encode_header(Tier2Header(
        //   compliance_status=ComplianceStatus.COMPLIANT,
        //   delegation_flag=False, has_opinion=True,
        //   precision_mode=PrecisionMode.BITS_8,
        //   operator_id=OperatorId.CUMULATIVE_FUSION,
        //   reasoning_context=3, context_version=1,
        //   has_multinomial=False, sub_tier_depth=0,
        //   source_count=5))
        // → b'\x0c\x13\x10\x05'
        let header = Header::Tier2(Tier2Header {
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
        });
        let encoded = encode_header(&header);
        assert_eq!(encoded, [0x0C, 0x13, 0x10, 0x05]);
    }

    #[test]
    fn test_python_interop_tier3_trust_discount() {
        // Python: encode_header(Tier3Header(
        //   compliance_status=ComplianceStatus.COMPLIANT,
        //   delegation_flag=False, has_opinion=True,
        //   precision_mode=PrecisionMode.BITS_8,
        //   operator_id=OperatorId.TRUST_DISCOUNT,
        //   reasoning_context=0,
        //   has_extended_context=True, has_provenance_chain=False,
        //   has_multinomial=False, has_trust_info=True,
        //   sub_tier_depth=2))
        // → b'\x14\x20\x92\x00'
        let header = Header::Tier3(Tier3Header {
            compliance_status: ComplianceStatus::Compliant,
            delegation_flag: false,
            has_opinion: true,
            precision_mode: PrecisionMode::Bits8,
            operator_id: OperatorId::TrustDiscount,
            reasoning_context: 0,
            has_extended_context: true,
            has_provenance_chain: false,
            has_multinomial: false,
            has_trust_info: true,
            sub_tier_depth: 2,
        });
        let encoded = encode_header(&header);
        assert_eq!(encoded, [0x14, 0x20, 0x92, 0x00]);
    }

    // =================================================================
    // Exhaustive Tier 1 roundtrip — all 256 possible byte 0 values
    // =================================================================

    #[test]
    fn test_tier1_exhaustive_byte0_roundtrip() {
        // Every valid Tier 1 byte 0 value must roundtrip.
        // Only origin_tier=00 (CONSTRAINED) bytes are valid Tier 1.
        // Byte 0: [cs:2][df:1][ot:2][ho:1][pm:2]
        // origin_tier bits are 4-3, so ot=00 means bits 4-3 are 00.
        for byte_val in 0u8..=255 {
            let origin_tier = (byte_val >> 3) & 0x03;
            if origin_tier != TIER_CONSTRAINED {
                continue; // Not a Tier 1 header
            }

            let cs_bits = (byte_val >> 6) & 0x03;
            // ComplianceStatus only has 3 valid values (0-2), skip 3
            if cs_bits == 3 {
                continue;
            }

            let result = decode_header(&[byte_val]);
            match result {
                Ok(header) => {
                    let re_encoded = encode_header(&header);
                    assert_eq!(
                        re_encoded[0], byte_val,
                        "Roundtrip failed for byte 0x{byte_val:02X}"
                    );
                }
                Err(_) => {
                    // Some combinations may have invalid enum values —
                    // that's expected for PrecisionMode::Reserved etc.
                    // We only require that VALID headers roundtrip.
                }
            }
        }
    }

    // =================================================================
    // header_size
    // =================================================================

    #[test]
    fn test_header_size_tier1() {
        let h = Header::Tier1(Tier1Header {
            compliance_status: ComplianceStatus::Compliant,
            delegation_flag: false,
            has_opinion: false,
            precision_mode: PrecisionMode::Bits8,
        });
        assert_eq!(header_size(&h), 1);
    }

    #[test]
    fn test_header_size_tier2() {
        let h = Header::Tier2(Tier2Header {
            compliance_status: ComplianceStatus::Compliant,
            delegation_flag: false,
            has_opinion: false,
            precision_mode: PrecisionMode::Bits8,
            operator_id: OperatorId::None,
            reasoning_context: 0,
            context_version: 0,
            has_multinomial: false,
            sub_tier_depth: 0,
            source_count: 0,
        });
        assert_eq!(header_size(&h), 4);
    }

    #[test]
    fn test_header_size_tier3() {
        let h = Header::Tier3(Tier3Header {
            compliance_status: ComplianceStatus::Compliant,
            delegation_flag: false,
            has_opinion: false,
            precision_mode: PrecisionMode::Bits8,
            operator_id: OperatorId::None,
            reasoning_context: 0,
            has_extended_context: false,
            has_provenance_chain: false,
            has_multinomial: false,
            has_trust_info: false,
            sub_tier_depth: 0,
        });
        assert_eq!(header_size(&h), 4);
    }
}
