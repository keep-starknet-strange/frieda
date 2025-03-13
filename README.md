# FRIEDA

**FRI-based Erasure-coded Interactive Data Availability**

[![Rust 2021](https://img.shields.io/badge/Rust-2021-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Status: Experimental](https://img.shields.io/badge/Status-Experimental-yellow.svg)](https://github.com/AbdelStark/frieda)

A Rust implementation of data availability sampling using Fast Reed-Solomon Interactive Oracle Proofs (FRI) as described in the [FRIDA paper](https://eprint.iacr.org/2024/248).

## Overview

Data Availability (DA) is a critical property in blockchain scaling solutions. It ensures that sufficient information about state transitions is published, allowing network participants to reconstruct the full state if needed. Data Availability Sampling (DAS) allows resource-constrained clients to probabilistically verify data availability without downloading the entire dataset.

FRIEDA implements the FRIDA scheme, which offers several theoretical improvements over previous approaches:

- **Polylogarithmic overhead** for both prover and verifier
- **No trusted setup requirement** (unlike polynomial commitment schemes based on pairings)
- **Practical sampling efficiency** and tight security bounds

## Technical Background

### Data Availability Problem

In decentralized systems, particularly Layer 2 scaling solutions like rollups, participants need assurance that transaction data has been published without downloading all data. Sampling-based approaches allow light clients to verify availability with high probability by requesting random fragments of the data.

### The FRIDA Approach

FRIDA establishes a connection between Data Availability Sampling and Interactive Oracle Proofs of Proximity (IOPPs). It demonstrates that any IOPP meeting a specific consistency criterion can be transformed into an erasure code commitment scheme suitable for data availability sampling.

The paper shows that FRI (Fast Reed-Solomon Interactive Oracle Proofs) satisfies these properties, leading to an efficient DAS scheme with:

1. **Reed-Solomon Encoding**: Data is encoded with an expansion factor to ensure erasure resilience
2. **FRI Protocol**: Provides low-degree proximity testing with logarithmic proof size
3. **Merkle Commitments**: Authenticates erasure-encoded data efficiently

## Implementation

FRIEDA is structured with the following components:

- **Field Arithmetic (`field.rs`)**: Operations over the M31 prime field (2³¹ - 1)
- **Polynomial Operations (`polynomial.rs`)**: FFT, IFFT, and Reed-Solomon encoding
- **FRI Protocol (`fri.rs`)**: Low-degree testing mechanisms
- **Data Availability Layer (`da.rs`)**: High-level data commitment and verification
- **Sampling (`sampling.rs`)**: Probability-based sampling strategy
- **Utilities (`utils.rs`)**: Merkle tree implementation and other helpers

### API Usage

The library provides a straightforward API for the core operations:

```rust
use frieda::api::{commit, sample, verify};

// Data provider commits to the data
let commitment = commit(&data)?;

// Light client samples the committed data
let sample_result = sample(&commitment)?;

// Data provider generates proof for the requested samples
// (In a real implementation, this would use the original data)
let proof = generate_proof(&commitment, &sample_result)?;

// Light client verifies the samples
let is_available = verify(&commitment, &proof)?;
```

## Comparative Analysis

The FRIDA scheme has distinct advantages over other approaches:

| Scheme | Overhead | Trusted Setup | Limitations |
|--------|----------|---------------|-------------|
| KZG-based | O(log n) | Required | Limited polynomial degree, setup complexity |
| Merkle-based | O(n) | Not required | Linear sampling overhead |
| Tensor codes | O(√n log n) | Not required | Limited to two-dimensional construction |
| FRIDA (FRI-based) | O(log² n) | Not required | More complex protocol |

## Running the Code

```bash
git clone https://github.com/AbdelStark/frieda.git
cd frieda
cargo run --release
```

## Repository Structure

```
frieda/
├── src/
│   ├── field.rs       # M31 field arithmetic
│   ├── polynomial.rs  # FFT and polynomial operations
│   ├── fri.rs         # FRI protocol implementation
│   ├── da.rs          # Data availability layer
│   ├── sampling.rs    # Sampling strategies
│   ├── utils.rs       # Merkle trees and utilities
│   ├── lib.rs         # Core library definitions
│   └── main.rs        # Demo application
└── README.md
```

## Limitations

This implementation is primarily for educational and research purposes. Several limitations should be noted:

1. The implementation focuses on the core concepts rather than optimizations
2. The proof generation is partially implemented
3. Security audits have not been performed
4. The library should not be used in production without further development

## License

MIT License - Copyright (c) 2024 [AbdelStark](https://github.com/AbdelStark)

## References

1. Hall-Andersen, M., Simkin, M., & Wagner, B. (2024). "FRIDA: Data Availability Sampling from FRI." *IACR Cryptology ePrint Archive*, 2024/248.
2. Ben-Sasson, E., Bentov, I., Horesh, Y., & Riabzev, M. (2018). "Fast Reed-Solomon Interactive Oracle Proofs of Proximity." *Electronic Colloquium on Computational Complexity*, Report No. 134.
3. Hall-Andersen, M., Simkin, M., & Wagner, B. (2023). "Foundations of Data Availability Sampling." *IACR Cryptology ePrint Archive*, 2023/1079.
