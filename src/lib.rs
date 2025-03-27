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
pub mod reconstruct;
mod utils;

/// Core public API for FRIEDA
pub mod api {

    use stwo_prover::core::pcs::PcsConfig;

    use crate::{commit::Commitment, proof::Proof};

    use super::*;

    /// Commit to data using FRI protocol
    pub fn commit(data: &[u8], log_blowup_factor: u32) -> Commitment {
        commit::commit(data, log_blowup_factor)
    }

    /// Generate a FRI proof for committed data
    pub fn generate_proof(data: &[u8], seed: Option<u64>, pcs_config: PcsConfig) -> Proof {
        proof::generate_proof(data, seed, pcs_config)
    }

    /// Verify a FRI proof against a commitment
    pub fn verify(proof: Proof, seed: Option<u64>) -> bool {
        proof::verify_proof(proof, seed)
    }
}

#[cfg(test)]
mod tests {
    use stwo_prover::core::{fri::FriConfig, pcs::PcsConfig};

    use super::*;

    #[test]
    fn test_end_to_end() {
        // This test demonstrates the intended workflow, even though some parts
        // are not fully implemented yet

        // Step 1: Data provider has some data
        let original_data = b"This is the original data that needs to be made available.";

        // Step 2: Data provider commits to the data
        let commitment = api::commit(original_data, 4);
        println!("Commitment created with root: {:?}", commitment);

        // Step 3: Data provider publishes the commitment
        // (In a real system, this would be published to a blockchain or broadcast)

        // Step 4: Light client asks for a proof with a seed so the sample points is randomized
        let proof = api::generate_proof(
            original_data,
            None,
            PcsConfig {
                fri_config: FriConfig {
                    log_blowup_factor: 4,
                    log_last_layer_degree_bound: 0,
                    n_queries: 20,
                },
                pow_bits: 20,
            },
        );

        // Step 5: Light client verifies the proofs
        // Note: verify is not fully implemented with real proofs
        let verification_result = api::verify(proof, None);
        assert!(verification_result);
    }
}
