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

pub mod bitpack;
// Modules added incrementally as tests are written:
// pub mod error;
pub mod header;
pub mod opinion;
// pub mod annotation;
// pub mod codec;
// pub mod temporal;
// pub mod security;
// pub mod transport;
