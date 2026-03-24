//! # cborld-ex
//!
//! Compact Binary Linked Data with Semantic Reasoning for Constrained IoT Networks.
//!
//! CBOR-LD-ex extends CBOR-LD (W3C) with bit-packed Subjective Logic annotations
//! for constrained IoT devices. This crate provides:
//!
//! - **Bit-packed headers** — 1-byte (Tier 1) to 4-byte (Tier 2/3) annotation headers
//! - **Quantized opinions** — Subjective Logic opinion tuples at 8/16/32-bit precision
//! - **Algebraic closure** — All operations preserve the SL invariant b+d+u=1 exactly
//! - **93% bit efficiency** — Shannon-optimal encoding, 37× smaller than JSON-LD
//!
//! ## Design Axioms
//!
//! 1. **Backward Compatibility**: Every CBOR-LD-ex message is a valid CBOR-LD message
//! 2. **Algebraic Closure**: Every annotation operation produces a valid annotation
//! 3. **Quantization Correctness**: b̂ + d̂ + û = 2ⁿ−1 exactly (Theorem 1)
//!
//! ## Feature Flags
//!
//! - `std` (default) — Full standard library support
//! - `alloc` — Heap allocation without full std (for `no_std` + allocator environments)
//! - Default-features = false — Bare `no_std`, no heap allocation
//!
//! ## References
//!
//! - Jøsang, A. (2016). *Subjective Logic*. Springer.
//! - RFC 8949: Concise Binary Object Representation (CBOR)
//! - Syed, M. et al. (2026). A Compliance Algebra. Working paper.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

// ==========================================================================
// Core modules — available on ALL targets, including bare `no_std`.
//
// These implement the CBOR-LD-ex wire format for constrained Tier 1 devices:
//   bitpack    → MSB-first bit reader/writer (256-byte fixed buffer, no heap)
//   header     → 1-byte (Tier 1) to 4-byte (Tier 2/3) annotation headers
//   opinion    → Quantized Subjective Logic opinions (8/16/32-bit precision)
//   annotation → Header + opinion assembly, encode/decode to byte arrays
//
// Total wire cost for a Tier 1 + 8-bit opinion: 4 bytes.
// JSON-LD equivalent: ~148 bytes. Compression ratio: 37×.
// ==========================================================================
pub mod bitpack;
pub mod header;
pub mod opinion;
pub mod annotation;

// ==========================================================================
// `alloc` modules — require heap allocation (Vec, String).
//
// Available with `features = ["alloc"]` or `features = ["std"]` (default).
// Suitable for `no_std` environments with a global allocator (e.g., ESP32
// with `#[global_allocator]`, WASM with wee_alloc).
//
//   temporal → Half-life codec, decay functions, bit-packed ExtensionBlock
// ==========================================================================
#[cfg(feature = "alloc")]
pub mod temporal;

// ==========================================================================
// `std` modules — require the full standard library.
//
// Available with `features = ["std"]` (default). These pull in `ciborium`
// for full CBOR serialization and use `std::collections::BTreeMap`.
//
//   codec → ContextRegistry, full CBOR encode/decode pipeline with Tag(60000)
// ==========================================================================
#[cfg(feature = "std")]
pub mod codec;

// Planned modules (not yet implemented):
// pub mod security;   // Annotation digests, Byzantine fusion metadata
// pub mod transport;  // MQTT/CoAP serialization
