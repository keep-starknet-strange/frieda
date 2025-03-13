# FRIEDA

**FRI-based Data Availability Sampling Library**

FRIEDA is a Rust implementation of the [FRIDA paper](https://eprint.iacr.org/2024/248), which provides an efficient data availability sampling scheme based on the FRI (Fast Reed-Solomon Interactive Oracle Proofs) protocol.

## Overview

Data Availability Sampling (DAS) is a critical component in various blockchain scaling solutions, particularly in rollups and data availability committees. It allows light clients to verify that a dataset is fully available without having to download the entire dataset.

FRIEDA implements:

- **Fast Reed-Solomon Interactive Oracle Proof (FRI)** for polynomial commitments
- **Low-degree testing** to verify data integrity
- **Efficient sampling** with tight security bounds
- **Merkle tree commitments** for data authentication

The library is designed to be:

- **Modular**: Clearly separated components for field arithmetic, polynomial operations, FRI protocol, and data availability sampling
- **Well-documented**: Extensive documentation with examples and references to the original paper
- **Efficient**: Optimized implementations of key cryptographic primitives

## Features

- **M31 Field Arithmetic**: Uses the M31 prime field (2³¹ - 1) for efficient field operations
- **Fast Fourier Transform (FFT)**: Optimized FFT implementation for polynomial operations
- **Reed-Solomon Encoding**: Erasure coding with expansion factor configuration
- **FRI Commitment Scheme**: Implementation of the FRI protocol as described in the FRIDA paper
- **Data Availability Sampling**: Functions for sampling, verifying, and reconstructing data

## Installation

Add FRIEDA to your Cargo.toml:

```toml
[dependencies]
frieda = { git = "https://github.com/yourusername/frieda.git" }
```

## Usage

Here's a basic example of how to use FRIEDA:

```rust
use frieda::api::{commit, generate_proof, verify, sample};

fn main() -> frieda::Result<()> {
    // Example data
    let data = b"Hello, world! This is some test data.";
    
    // Commit to the data
    let commitment = commit(data)?;
    
    // In a real scenario, the verifier would sample the data
    let sample_result = sample(&commitment)?;
    
    // The verifier would then verify the samples
    // (Not fully implemented in this demo)
    
    println!("Commitment: {:?}", commitment);
    println!("Sample indices: {:?}", sample_result.indices);
    
    Ok(())
}
```

## Components

FRIEDA is organized into the following modular components:

- **Field Arithmetic (`field.rs`)**: Implements M31 prime field arithmetic
- **Polynomial Operations (`polynomial.rs`)**: Provides FFT, interpolation, and encoding
- **FRI Core (`fri.rs`)**: Implements the FRI protocol
- **Data Availability Layer (`da.rs`)**: High-level API for data availability
- **Sampling and Verification (`sampling.rs`)**: Implements light-client sampling
- **Utilities (`utils.rs`)**: Merkle trees, hashing, and serialization

## Understanding DAS and FRIDA

Data Availability Sampling allows light clients to verify that a piece of data is available without downloading the entire dataset. The FRIDA paper establishes a connection between DAS and Interactive Oracle Proofs of Proximity (IOPPs), showing that any IOPP meeting a consistency criterion can be turned into an erasure code commitment and then into a DAS scheme.

The main advantages of FRIDA's approach include:

1. **No Trusted Setup**: The construction does not require a trusted setup
2. **Asymptotic Efficiency**: Polylogarithmic overhead compared to earlier schemes
3. **Concrete Efficiency**: Better performance in multiple parameters

## Security

FRIEDA is an educational implementation of the FRIDA paper and should not be used in production without further security audits. The implementation focuses on correctness and follows the paper's specifications, but has not been audited for security vulnerabilities.

## References

- [FRIDA: Data Availability Sampling from FRI](https://eprint.iacr.org/2024/248)
- [Fast Reed-Solomon Interactive Oracle Proofs of Proximity](https://eccc.weizmann.ac.il/report/2017/134/)
- [Foundations of Data Availability Sampling](https://eprint.iacr.org/2023/1079)

## License

This project is licensed under the MIT License - see the LICENSE file for details.
