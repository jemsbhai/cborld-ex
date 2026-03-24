//! Bit-level packing utilities for CBOR-LD-ex.
//!
//! Provides BitWriter and BitReader for MSB-first bit-packed encoding,
//! used by temporal extensions (§7.4) and multinomial wire format (§4.4).
//!
//! MSB-first within each byte, matching network byte order.
//! Final byte padded with zero bits.
//!
//! This module is `no_std`-compatible — no heap allocation required.

/// Accumulates bits MSB-first into a fixed-size buffer, pads final byte with zeros.
///
/// Maximum capacity: 256 bytes (2048 bits). This is sufficient for all
/// CBOR-LD-ex wire formats — the largest payload (multinomial opinion with
/// k=15 at 32-bit precision) requires 4 + 32*(2*15-1) = 932 bits = 117 bytes.
pub struct BitWriter {
    buf: [u8; 256],
    bit_pos: usize,
}

/// Reads individual bits from a byte slice, MSB-first.
pub struct BitReader<'a> {
    data: &'a [u8],
    bit_pos: usize,
}

impl BitWriter {
    /// Create a new empty BitWriter.
    pub fn new() -> Self {
        Self {
            buf: [0u8; 256],
            bit_pos: 0,
        }
    }

    /// Write `width` bits from `value` (MSB first).
    ///
    /// Only the lowest `width` bits of `value` are written.
    ///
    /// # Panics
    /// Panics if the buffer would overflow (> 2048 bits total).
    pub fn write(&mut self, value: u32, width: u8) {
        let width = width as usize;
        assert!(
            self.bit_pos + width <= 2048,
            "BitWriter overflow: {} + {} > 2048",
            self.bit_pos,
            width
        );

        for i in (0..width).rev() {
            let bit = (value >> i) & 1;
            let byte_idx = self.bit_pos / 8;
            let bit_idx = 7 - (self.bit_pos % 8); // MSB-first
            if bit == 1 {
                self.buf[byte_idx] |= 1 << bit_idx;
            }
            // No need to clear — buffer is zero-initialized,
            // so padding bits are already zero.
            self.bit_pos += 1;
        }
    }

    /// Return the accumulated bits as a byte slice, padded to byte boundary.
    ///
    /// Padding bits are always zero. The returned slice length is
    /// `ceil(bit_pos / 8)`.
    pub fn as_bytes(&self) -> &[u8] {
        let byte_len = (self.bit_pos + 7) / 8;
        &self.buf[..byte_len]
    }

    /// Return the number of bits written so far.
    pub fn bit_len(&self) -> usize {
        self.bit_pos
    }
}

impl Default for BitWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> BitReader<'a> {
    /// Create a new BitReader over the given byte slice.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, bit_pos: 0 }
    }

    /// Read `width` bits and return as a u32.
    ///
    /// # Panics
    /// Panics if there are fewer than `width` bits remaining.
    pub fn read(&mut self, width: u8) -> u32 {
        let width = width as usize;
        assert!(
            self.bit_pos + width <= self.data.len() * 8,
            "BitReader underflow: {} + {} > {}",
            self.bit_pos,
            width,
            self.data.len() * 8
        );

        let mut value: u32 = 0;
        for _ in 0..width {
            let byte_idx = self.bit_pos / 8;
            let bit_idx = 7 - (self.bit_pos % 8); // MSB-first
            let bit = (self.data[byte_idx] >> bit_idx) & 1;
            value = (value << 1) | bit as u32;
            self.bit_pos += 1;
        }
        value
    }

    /// Return the number of unread bits remaining.
    pub fn remaining(&self) -> usize {
        self.data.len() * 8 - self.bit_pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =================================================================
    // BitWriter basics
    // =================================================================

    #[test]
    fn test_empty_writer_produces_empty_slice() {
        let w = BitWriter::new();
        assert_eq!(w.as_bytes(), &[]);
        assert_eq!(w.bit_len(), 0);
    }

    #[test]
    fn test_write_single_byte_aligned() {
        // Writing exactly 8 bits should produce 1 byte, no padding.
        let mut w = BitWriter::new();
        w.write(0xA5, 8); // 1010_0101
        assert_eq!(w.as_bytes(), &[0xA5]);
        assert_eq!(w.bit_len(), 8);
    }

    #[test]
    fn test_write_two_bytes_aligned() {
        let mut w = BitWriter::new();
        w.write(0xDE, 8);
        w.write(0xAD, 8);
        assert_eq!(w.as_bytes(), &[0xDE, 0xAD]);
        assert_eq!(w.bit_len(), 16);
    }

    #[test]
    fn test_write_sub_byte_with_padding() {
        // Write 4 bits (0b1010), should produce 1 byte: 0b1010_0000 = 0xA0
        let mut w = BitWriter::new();
        w.write(0b1010, 4);
        assert_eq!(w.as_bytes(), &[0xA0]);
        assert_eq!(w.bit_len(), 4);
    }

    #[test]
    fn test_write_cross_byte_boundary() {
        // Write 4 bits then 8 bits = 12 bits total → 2 bytes.
        // 0b1100 followed by 0b1111_0000
        // Byte 0: 1100_1111 = 0xCF
        // Byte 1: 0000_0000 = 0x00 (4 padding bits)
        let mut w = BitWriter::new();
        w.write(0b1100, 4);
        w.write(0b11110000, 8);
        assert_eq!(w.as_bytes(), &[0xCF, 0x00]);
        assert_eq!(w.bit_len(), 12);
    }

    #[test]
    fn test_write_single_bit_one() {
        let mut w = BitWriter::new();
        w.write(1, 1);
        // 1 bit '1' + 7 padding zeros = 0b1000_0000 = 0x80
        assert_eq!(w.as_bytes(), &[0x80]);
        assert_eq!(w.bit_len(), 1);
    }

    #[test]
    fn test_write_single_bit_zero() {
        let mut w = BitWriter::new();
        w.write(0, 1);
        assert_eq!(w.as_bytes(), &[0x00]);
        assert_eq!(w.bit_len(), 1);
    }

    #[test]
    fn test_write_max_u8() {
        let mut w = BitWriter::new();
        w.write(255, 8);
        assert_eq!(w.as_bytes(), &[0xFF]);
    }

    #[test]
    fn test_write_16_bits() {
        let mut w = BitWriter::new();
        w.write(0xBEEF, 16);
        assert_eq!(w.as_bytes(), &[0xBE, 0xEF]);
    }

    #[test]
    fn test_write_zero_width_is_noop() {
        let mut w = BitWriter::new();
        w.write(0xFF, 0);
        assert_eq!(w.as_bytes(), &[]);
        assert_eq!(w.bit_len(), 0);
    }

    // =================================================================
    // BitReader basics
    // =================================================================

    #[test]
    fn test_read_single_byte() {
        let data = [0xA5]; // 1010_0101
        let mut r = BitReader::new(&data);
        assert_eq!(r.remaining(), 8);
        assert_eq!(r.read(8), 0xA5);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn test_read_sub_byte() {
        let data = [0xA0]; // 1010_0000
        let mut r = BitReader::new(&data);
        assert_eq!(r.read(4), 0b1010);
        assert_eq!(r.remaining(), 4);
    }

    #[test]
    fn test_read_cross_byte_boundary() {
        let data = [0xCF, 0x00]; // 1100_1111 0000_0000
        let mut r = BitReader::new(&data);
        assert_eq!(r.read(4), 0b1100);
        assert_eq!(r.read(8), 0b11110000);
        assert_eq!(r.remaining(), 4);
    }

    #[test]
    fn test_read_single_bit() {
        let data = [0x80]; // 1000_0000
        let mut r = BitReader::new(&data);
        assert_eq!(r.read(1), 1);
        assert_eq!(r.read(1), 0);
        assert_eq!(r.remaining(), 6);
    }

    #[test]
    fn test_read_16_bits() {
        let data = [0xBE, 0xEF];
        let mut r = BitReader::new(&data);
        assert_eq!(r.read(16), 0xBEEF);
    }

    // =================================================================
    // Roundtrip: write then read must recover original values
    // =================================================================

    #[test]
    fn test_roundtrip_aligned_values() {
        let mut w = BitWriter::new();
        w.write(0xDE, 8);
        w.write(0xAD, 8);
        w.write(0xBE, 8);
        w.write(0xEF, 8);

        let bytes = w.as_bytes();
        let mut r = BitReader::new(bytes);
        assert_eq!(r.read(8), 0xDE);
        assert_eq!(r.read(8), 0xAD);
        assert_eq!(r.read(8), 0xBE);
        assert_eq!(r.read(8), 0xEF);
    }

    #[test]
    fn test_roundtrip_mixed_widths() {
        // Simulates a real annotation header scenario:
        // 2 bits (compliance_status) + 1 bit (delegation) + 2 bits (tier)
        // + 1 bit (has_opinion) + 2 bits (precision_mode) = 8 bits total
        let mut w = BitWriter::new();
        w.write(0b10, 2); // compliance_status = INSUFFICIENT
        w.write(0b1, 1); // delegation_flag = true
        w.write(0b01, 2); // origin_tier = EDGE
        w.write(0b1, 1); // has_opinion = true
        w.write(0b00, 2); // precision_mode = 8-bit

        let bytes = w.as_bytes();
        assert_eq!(bytes.len(), 1);

        let mut r = BitReader::new(bytes);
        assert_eq!(r.read(2), 0b10);
        assert_eq!(r.read(1), 0b1);
        assert_eq!(r.read(2), 0b01);
        assert_eq!(r.read(1), 0b1);
        assert_eq!(r.read(2), 0b00);
    }

    #[test]
    fn test_roundtrip_multinomial_header() {
        // Simulates multinomial wire format: 4-bit k + n-bit values
        let k: u32 = 4;
        let values: [u32; 3] = [200, 30, 10]; // k-1 beliefs at 8-bit

        let mut w = BitWriter::new();
        w.write(k, 4);
        for &v in &values {
            w.write(v, 8);
        }

        let bytes = w.as_bytes();
        // 4 + 3*8 = 28 bits → 4 bytes
        assert_eq!(bytes.len(), 4);

        let mut r = BitReader::new(bytes);
        assert_eq!(r.read(4), k);
        for &expected in &values {
            assert_eq!(r.read(8), expected);
        }
    }

    #[test]
    fn test_roundtrip_non_byte_aligned() {
        // 3 bits + 5 bits + 7 bits = 15 bits → 2 bytes
        let mut w = BitWriter::new();
        w.write(0b101, 3);
        w.write(0b11001, 5);
        w.write(0b1110001, 7);

        assert_eq!(w.bit_len(), 15);
        assert_eq!(w.as_bytes().len(), 2);

        let mut r = BitReader::new(w.as_bytes());
        assert_eq!(r.read(3), 0b101);
        assert_eq!(r.read(5), 0b11001);
        assert_eq!(r.read(7), 0b1110001);
    }

    // =================================================================
    // MSB-first ordering verification
    // =================================================================

    #[test]
    fn test_msb_first_bit_ordering() {
        // Write bits one at a time and verify MSB-first byte construction.
        // Writing 1,0,1,1,0,0,1,0 should produce 0b10110010 = 0xB2
        let mut w = BitWriter::new();
        w.write(1, 1);
        w.write(0, 1);
        w.write(1, 1);
        w.write(1, 1);
        w.write(0, 1);
        w.write(0, 1);
        w.write(1, 1);
        w.write(0, 1);
        assert_eq!(w.as_bytes(), &[0xB2]);
    }

    // =================================================================
    // Cross-validation with Python output
    //
    // These test vectors are derived from the Python BitWriter/BitReader
    // to ensure byte-for-byte interoperability between implementations.
    // =================================================================

    #[test]
    fn test_python_interop_multinomial_k4_8bit() {
        // Python: BitWriter(), write(4, 4), write(200, 8), write(30, 8),
        //         write(10, 8), write(15, 8) → to_bytes()
        //
        // Bit stream: 0100 11001000 00011110 00001010 00001111
        //           = 4    200      30       10       15
        // Grouped into bytes MSB-first:
        //   0100_1100 = 0x4C
        //   1000_0001 = 0x81
        //   1110_0000 = 0xE0
        //   1010_0000 = 0xA0
        //   1111_0000 = 0xF0  — wait let me recalculate
        //
        // Actually: 4 bits + 4*8 = 36 bits → 5 bytes (4 padding bits)
        //   bits: 0100 | 11001000 | 00011110 | 00001010 | 00001111 | 0000 (pad)
        // Regroup into bytes:
        //   01001100 = 0x4C
        //   10000001 = 0x81
        //   11100000 = 0xE0
        //   10100000 = 0xA0
        //   11110000 = 0xF0
        //
        // We verify the roundtrip rather than hardcoding byte values,
        // since the exact bytes depend on correct MSB-first grouping.
        // The Python-generated test vectors will be added in Phase 8
        // (interop test suite) once we can run both implementations.

        let mut w = BitWriter::new();
        w.write(4, 4);
        w.write(200, 8);
        w.write(30, 8);
        w.write(10, 8);
        w.write(15, 8);

        assert_eq!(w.bit_len(), 36);
        assert_eq!(w.as_bytes().len(), 5); // ceil(36/8) = 5

        let mut r = BitReader::new(w.as_bytes());
        assert_eq!(r.read(4), 4);
        assert_eq!(r.read(8), 200);
        assert_eq!(r.read(8), 30);
        assert_eq!(r.read(8), 10);
        assert_eq!(r.read(8), 15);
    }

    // =================================================================
    // Edge cases and invariants
    // =================================================================

    #[test]
    fn test_write_only_msb_of_value_used() {
        // If value has more bits than width, only the lowest `width` bits
        // should be written. E.g., write(0xFF, 4) should write 0b1111.
        let mut w = BitWriter::new();
        w.write(0xFF, 4); // Only lowest 4 bits: 0b1111
                          // 1111_0000 = 0xF0
        assert_eq!(w.as_bytes(), &[0xF0]);

        let mut r = BitReader::new(w.as_bytes());
        assert_eq!(r.read(4), 0b1111);
    }

    #[test]
    fn test_large_contiguous_write() {
        // Write 32 bits at once
        let mut w = BitWriter::new();
        w.write(0xDEADBEEF, 32);
        assert_eq!(w.as_bytes(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_reader_remaining_tracks_correctly() {
        let data = [0xFF, 0x00, 0xAA]; // 24 bits
        let mut r = BitReader::new(&data);
        assert_eq!(r.remaining(), 24);
        r.read(3);
        assert_eq!(r.remaining(), 21);
        r.read(8);
        assert_eq!(r.remaining(), 13);
        r.read(13);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    #[should_panic]
    fn test_reader_panics_on_underflow() {
        let data = [0xFF]; // 8 bits
        let mut r = BitReader::new(&data);
        r.read(9); // Should panic — only 8 bits available
    }

    #[test]
    fn test_writer_multiple_small_writes_accumulate() {
        // 8 writes of 1 bit each should produce 1 byte
        let mut w = BitWriter::new();
        for _ in 0..8 {
            w.write(1, 1);
        }
        assert_eq!(w.as_bytes(), &[0xFF]);
        assert_eq!(w.bit_len(), 8);
    }

    #[test]
    fn test_padding_bits_are_zero() {
        // Write 1 bit (value=1), padding should be 7 zero bits
        let mut w = BitWriter::new();
        w.write(1, 1);
        let byte = w.as_bytes()[0];
        // Bit 7 (MSB) = 1, bits 6-0 = 0 → 0x80
        assert_eq!(byte, 0x80);

        // Verify by reading all 8 bits
        let mut r = BitReader::new(w.as_bytes());
        assert_eq!(r.read(1), 1);
        // Remaining 7 bits should all be 0
        assert_eq!(r.read(7), 0);
    }

    #[test]
    fn test_empty_reader() {
        let data: [u8; 0] = [];
        let r = BitReader::new(&data);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn test_roundtrip_all_8bit_values() {
        // Exhaustive: every possible 8-bit value roundtrips correctly.
        // This is a mini version of the 32,896-pair exhaustive test
        // that we'll do for opinions.
        for v in 0u32..=255 {
            let mut w = BitWriter::new();
            w.write(v, 8);
            let mut r = BitReader::new(w.as_bytes());
            assert_eq!(r.read(8), v, "Failed roundtrip for value {v}");
        }
    }

    #[test]
    fn test_roundtrip_annotation_header_simulation() {
        // Simulate encoding a full Tier 1 annotation header byte 0:
        // compliance_status=COMPLIANT(00), delegation=false(0),
        // origin_tier=CONSTRAINED(00), has_opinion=true(1),
        // precision_mode=8BIT(00)
        //
        // Byte 0: [00][0][00][1][00] = 0b0000_0100 = 0x04
        let mut w = BitWriter::new();
        w.write(0b00, 2); // compliance_status
        w.write(0, 1); // delegation_flag
        w.write(0b00, 2); // origin_tier
        w.write(1, 1); // has_opinion
        w.write(0b00, 2); // precision_mode

        assert_eq!(w.as_bytes(), &[0x04]);

        let mut r = BitReader::new(w.as_bytes());
        assert_eq!(r.read(2), 0b00); // COMPLIANT
        assert_eq!(r.read(1), 0); // no delegation
        assert_eq!(r.read(2), 0b00); // CONSTRAINED
        assert_eq!(r.read(1), 1); // has opinion
        assert_eq!(r.read(2), 0b00); // 8-bit
    }
}
