# 🌠 FRIEDA

<p align="center">
  <img src="https://img.shields.io/badge/Rust-2021-orange.svg" alt="Rust 2021"/>
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"/>
  <img src="https://img.shields.io/badge/Status-Experimental-yellow.svg" alt="Status: Experimental"/>
</p>

<h3 align="center">FRI-based Erasure-coded Interactive Data Availability</h3>

<p align="center">A blazing-fast, zero-knowledge data availability sampling library for blockchains and L2s.</p>

---

FRIEDA implements the ground-breaking [FRIDA paper](https://eprint.iacr.org/2024/248) data availability sampling scheme with **polylogarithmic overhead** and **no trusted setup**. It enables light clients to verify data availability without downloading the entire dataset, crucial for scalable blockchain systems.

## 🚀 Key Features

- **Zero Knowledge & Zero Trust**: No trusted setup required, fully transparent
- **Light Speed Verification**: Verify data availability by sampling just a tiny fraction
- **Mathematical Guarantees**: Statistical security with adjustable parameters
- **Blockchain Ready**: Integration-ready for L2s, rollups, and data availability committees
- **Pure Rust Implementation**: Safe, efficient cryptography with no unsafe code

## 💡 Why FRIEDA?

Traditional data availability schemes face a trilemma:

1. ❌ **KZG-based**: Requires trusted setup, limited polynomial degree
2. ❌ **Merkle-based**: Linear overhead for sampling
3. ❌ **Tensor codes**: Limited to two-dimensional construction

**FRIEDA solves all three problems** by leveraging Fast Reed-Solomon Interactive Oracle Proofs (FRI) to create an erasure code commitment with **polylogarithmic overhead** and **no trusted setup**.

```
                      ╭───────────────╮
                      │   FRIEDA DA   │
                      ╰───────────────╯
                             │
             ┌───────────────┴───────────────┐
             │                               │
    ╭───────────────╮               ╭───────────────╮
    │   FRI Proofs   │               │  Reed-Solomon │
    ╰───────────────╯               ╰───────────────╯
```

## 🔧 Quick Start

```rust
use frieda::api::{commit, sample, verify};

// The data provider commits to their data
let commitment = commit(&my_data)?;

// Light client samples the data to verify availability
let sample_queries = sample(&commitment)?;

// Data provider responds with proofs
let proofs = generate_proof_for_queries(&my_data, &sample_queries)?;

// Light client verifies without downloading everything
let is_available = verify(&commitment, &proofs)?;
```

## 📚 Components

FRIEDA is built with clean, modular architecture:

- **🧮 Field Arithmetic**: M31 prime field (2³¹ - 1) via [stwo-prover](https://github.com/starkware-libs/stwo)
- **📊 Polynomial Ops**: FFT, IFFT, interpolation for efficient encoding
- **🔍 FRI Protocol**: Core low-degree testing implementation
- **🔐 Cryptographic Primitives**: Merkle trees, hashing, and verification
- **🌐 Sampling Strategy**: Optimized data availability sampling

## 💻 Running the Demo

```bash
git clone https://github.com/AbdelStark/frieda.git
cd frieda
cargo run --release
```

## 📋 Background

FRIDA (the research paper) establishes a connection between Data Availability Sampling and Interactive Oracle Proofs of Proximity, showing that any IOPP with a consistency criterion can be transformed into an erasure code commitment scheme with strong guarantees.

This implementation transforms that theory into practical, usable code that can be integrated into blockchain systems.

## 📜 License

Licensed under MIT - Copyright (c) 2025 [AbdelStark](https://github.com/AbdelStark)

## 🔗 References

- [FRIDA: Data Availability Sampling from FRI](https://eprint.iacr.org/2024/248)
- [Foundations of Data Availability Sampling](https://eprint.iacr.org/2023/1079)
- [Fast Reed-Solomon Interactive Oracle Proofs](https://eccc.weizmann.ac.il/report/2017/134/)
