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

use thiserror::Error;

/// Re-export of stwo-prover's M31 field for arithmetic operations
pub use stwo_prover::core::fields::m31::M31;

// Define library modules
pub mod da;
pub mod field;
pub mod fri;
pub mod polynomial;
pub mod sampling;
pub mod utils;

/// Error types for the FRIEDA library
#[derive(Error, Debug)]
pub enum FriedaError {
    /// Input validation error
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Verification error
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Encoding error
    #[error("Encoding error: {0}")]
    EncodingError(String),

    /// Decoding error
    #[error("Decoding error: {0}")]
    DecodingError(String),

    /// Merkle tree error
    #[error("Merkle tree error: {0}")]
    MerkleTreeError(String),
}

/// Result type for FRIEDA operations
pub type Result<T> = std::result::Result<T, FriedaError>;

/// A commitment to data using the FRI protocol
#[derive(Debug, Clone)]
pub struct Commitment {
    // The root of the Merkle tree for the base layer
    pub root: [u8; 32],
    // The commitment metadata
    pub metadata: CommitmentMetadata,
}

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

/// A FRI proof for data availability
#[derive(Debug, Clone)]
pub struct FriProof {
    // The query phase information
    pub query_info: Vec<QueryInfo>,
    // The final layer
    pub final_layer: Vec<M31>,
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
    use super::*;

    /// Commit to data using FRI protocol
    pub fn commit(data: &[u8]) -> Result<Commitment> {
        da::commit(data)
    }

    /// Generate a FRI proof for committed data
    pub fn generate_proof(commitment: &Commitment) -> Result<FriProof> {
        da::generate_proof(commitment)
    }

    /// Verify a FRI proof against a commitment
    pub fn verify(commitment: &Commitment, proof: &FriProof) -> Result<bool> {
        da::verify(commitment, proof)
    }

    /// Sample data availability using a commitment
    pub fn sample(commitment: &Commitment) -> Result<SampleResult> {
        sampling::sample(commitment)
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
        let commitment = api::commit(data).unwrap();

        // Sample the commitment
        let sample_result = api::sample(&commitment).unwrap();

        // Verify that we have sample indices
        assert!(!sample_result.indices.is_empty());

        // Note: In a complete implementation, we would:
        // 1. Generate a proof with api::generate_proof()
        // 2. Verify the proof with api::verify()
        // 3. Reconstruct the data from samples

        // For now, we just check that the commit and sample functions work
        println!("Commitment: {:?}", commitment);
        println!("Sample indices: {:?}", sample_result.indices);
    }

    #[test]
    fn test_end_to_end() {
        // This test demonstrates the intended workflow, even though some parts
        // are not fully implemented yet

        // Step 1: Data provider has some data
        let original_data = b"This is the original data that needs to be made available.";

        // Step 2: Data provider commits to the data
        let commitment = api::commit(original_data).unwrap();
        println!("Commitment created with root: {:?}", commitment.root);

        // Step 3: Data provider publishes the commitment
        // (In a real system, this would be published to a blockchain or broadcast)

        // Step 4: Light client wants to verify data availability
        let sample_result = api::sample(&commitment).unwrap();
        println!(
            "Light client sampled {} indices",
            sample_result.indices.len()
        );

        // Step 5: Light client requests samples from data provider
        // (In a real system, the light client would query a network of providers)

        // Step 6: Data provider generates proofs for the requested samples
        // Note: generate_proof is not fully implemented, so this would fail
        // let proof = api::generate_proof(&commitment).unwrap();

        // Step 7: Light client verifies the proofs
        // Note: verify is not fully implemented with real proofs
        // let verification_result = api::verify(&commitment, &proof).unwrap();
        // assert!(verification_result);

        // Step 8: Light client concludes that data is available
        // In this demo, we just check that sampling works
        assert!(!sample_result.indices.is_empty());
    }
}
