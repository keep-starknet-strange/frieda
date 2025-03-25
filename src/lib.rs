//! # FRIEDA
//!
//! FRIEDA (FRI-based Data Availability Sampling) is a Rust implementation
//! of the FRIDA paper, which provides an efficient data availability sampling scheme
//! based on the FRI (Fast Reed-Solomon Interactive Oracle Proofs) protocol.
//!
//! The library implements erasure code commitments and data availability sampling
//! mechanisms that allow light clients to verify data availability without
//! downloading the entire dataset.

#![cfg_attr(not(feature = "std"), no_std)]

/// Re-export of stwo-prover's M31 field for arithmetic operations
pub use stwo_prover::core::fields::m31::M31;

// Define library modules
pub mod commit;
pub mod proof;
pub mod sample;
mod utils;

/// Error types for the FRIEDA library
#[derive(Debug)]
pub enum FriedaError {
    /// Input validation error
    SomeError,
}

/// Result type for FRIEDA operations
pub type Result<T> = std::result::Result<T, FriedaError>;

/// Metadata for a commitment
#[derive(Debug, Clone)]
pub struct CommitmentMetadata {
    // Domain size for evaluation
    pub domain_size: usize,
    // Expansion factor (inverse rate)
    pub expansion_factor: usize,
    // Batch size for batched FRI
    pub batch_size: usize,
    // Field size in bits
    pub field_size: usize,
}

/// Information for a single query in the FRI protocol
#[derive(Debug, Clone)]
pub struct QueryInfo {
    // The index being queried
    pub index: usize,
    // The value at the index
    pub value: M31,
    // The authentication path in the Merkle tree
    pub auth_path: Vec<[u8; 32]>,
}

/// Result of sampling data availability
#[derive(Debug, Clone)]
pub struct SampleResult {
    // Whether the sampling succeeded
    pub success: bool,
    // The sampled values
    pub values: Vec<M31>,
    // The indices that were sampled
    pub indices: Vec<usize>,
}

/// Core public API for FRIEDA
pub mod api {

    use crate::{commit::Commitment, proof::Proof};

    use super::*;

    /// Commit to data using FRI protocol
    pub fn commit(data: &[u8]) -> Commitment {
        commit::commit(data)
    }

    /// Generate a FRI proof for committed data
    pub fn generate_proof(data: &[u8]) -> Proof {
        proof::generate_proof(data)
    }

    /// Verify a FRI proof against a commitment
    pub fn verify(proof: Proof) -> bool {
        proof::verify_proof(proof)
    }

    /// Sample data availability using a commitment
    pub fn sample(_commitment: &Commitment) -> Result<SampleResult> {
        // sampling::sample(commitment)
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_workflow() {
        // Create some test data
        let data =
            b"Hello, world! This is a test of the FRI-based data availability sampling scheme.";

        // Commit to the data
        let _commitment = api::commit(data);

        // // Sample the commitment
        // let sample_result = api::sample(&commitment).unwrap();

        // // Verify that we have sample indices
        // assert!(!sample_result.indices.is_empty());

        // // Note: In a complete implementation, we would:
        // // 1. Generate a proof with api::generate_proof()
        // // 2. Verify the proof with api::verify()
        // // 3. Reconstruct the data from samples

        // // For now, we just check that the commit and sample functions work
        // println!("Commitment: {:?}", commitment);
        // println!("Sample indices: {:?}", sample_result.indices);
    }

    #[test]
    fn test_end_to_end() {
        // This test demonstrates the intended workflow, even though some parts
        // are not fully implemented yet

        // Step 1: Data provider has some data
        let original_data = b"This is the original data that needs to be made available.";

        // Step 2: Data provider commits to the data
        let commitment = api::commit(original_data);
        println!("Commitment created with root: {:?}", commitment);

        // Step 3: Data provider publishes the commitment
        // (In a real system, this would be published to a blockchain or broadcast)

        // Step 4: Light client wants to verify data availability
        // let sample_result = api::sample(&commitment).unwrap();
        // println!(
        //     "Light client sampled {} indices",
        //     sample_result.indices.len()
        // );

        // Step 5: Light client requests samples from data provider
        // (In a real system, the light client would query a network of providers)

        // Step 6: Data provider generates proofs for the requested samples
        // Note: generate_proof is not fully implemented, so this would fail
        let proof = api::generate_proof(original_data);

        // Step 7: Light client verifies the proofs
        // Note: verify is not fully implemented with real proofs
        let verification_result = api::verify(proof);
        assert!(verification_result);

        // Step 8: Light client concludes that data is available
        // In this demo, we just check that sampling works
        // assert!(!sample_result.indices.is_empty());
    }
}
