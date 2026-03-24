# cborld-ex

**Compact Binary Linked Data with Semantic Reasoning for Constrained IoT Networks**

A Rust implementation of [CBOR-LD-ex](https://github.com/jemsbhai/cbor-ld-ex), providing bit-packed Subjective Logic annotations for constrained IoT devices.

## Features

- **Bit-packed headers** — 1-byte (Tier 1) to 4-byte (Tier 2/3) annotation headers
- **Quantized opinions** — Subjective Logic opinion tuples at 8/16/32-bit precision
- **Algebraic closure** — All operations preserve the SL invariant b̂+d̂+û = 2ⁿ−1 exactly
- **93% bit efficiency** — Shannon-optimal encoding, 37× smaller than JSON-LD
- **`no_std` support** — Runs on bare-metal, WASM, and ESP32 targets
- **Byte-for-byte interop** — Cross-validated against the Python reference implementation

## Design Axioms

1. **Backward Compatibility**: Every CBOR-LD-ex message is a valid CBOR-LD message
2. **Algebraic Closure**: Every annotation operation produces a valid annotation
3. **Quantization Correctness**: b̂ + d̂ + û = 2ⁿ−1 exactly (Theorem 1)

## Usage

```toml
[dependencies]
cborld-ex = "0.1"
```

```rust
use cborld_ex::header::*;
use cborld_ex::opinion::*;

// Encode a Tier 1 annotation: compliant, 85% belief, 8-bit precision
let header = Header::Tier1(Tier1Header {
    compliance_status: ComplianceStatus::Compliant,
    delegation_flag: false,
    has_opinion: true,
    precision_mode: PrecisionMode::Bits8,
});

let (b_q, d_q, u_q, a_q) = quantize_binomial(0.85, 0.05, 0.10, 0.50, 8);
// b̂=217, d̂=13, û=25 (derived), â=128
// Total wire cost: 4 bytes. JSON-LD equivalent: ~148 bytes.
```

## Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `std` | ✓ | Full standard library support |
| `alloc` | ✓ (via `std`) | Heap allocation for `no_std` + allocator |

For `no_std` bare-metal: `default-features = false`

## Companion Projects

- **[cbor-ld-ex](https://pypi.org/project/cbor-ld-ex/)** — Python reference implementation (PyPI)
- **[jsonld-ex](https://pypi.org/project/jsonld-ex/)** — JSON-LD extensions with compliance algebra (PyPI)

## References

- Jøsang, A. (2016). *Subjective Logic*. Springer.
- RFC 8949: Concise Binary Object Representation (CBOR)
- Syed, M. et al. (2026). A Compliance Algebra. Working paper.

## License

MIT
