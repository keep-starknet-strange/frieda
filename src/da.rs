//! Data Availability (DA) layer module
//!
//! This module provides the high-level abstraction for data availability sampling.
//! It implements the core functionality for committing to data, generating proofs,
//! and verifying proofs.

use crate::{
    fri::{FriProver, FriVerifier},
    polynomial, Commitment, CommitmentMetadata, FriProof, FriedaError, Result, M31,
};

// Default parameters for the FRI protocol
const DEFAULT_EXPANSION_FACTOR: usize = 4;
const DEFAULT_BATCH_SIZE: usize = 8;
const DEFAULT_FIELD_SIZE: usize = 31; // M31 field
const DEFAULT_NUM_QUERIES: usize = 40;
const DEFAULT_FAN_IN: usize = 4;
const DEFAULT_BASE_DIMENSION: usize = 16;

/// Converts raw data bytes to a sequence of field elements
///
/// # Arguments
///
/// * `data` - The raw data bytes
///
/// # Returns
///
/// A vector of field elements
fn bytes_to_field_elements(data: &[u8]) -> Vec<M31> {
    let mut elements = Vec::new();

    // Process 4 bytes at a time to create field elements
    for chunk in data.chunks(4) {
        let mut bytes = [0u8; 4];
        for (i, &byte) in chunk.iter().enumerate() {
            bytes[i] = byte;
        }

        // Treat the bytes as a u32 and convert to a field element
        let value = u32::from_le_bytes(bytes);
        elements.push(M31::from(value));
    }

    elements
}

/// Converts field elements back to raw data bytes
///
/// # Arguments
///
/// * `elements` - The field elements
///
/// # Returns
///
/// A vector of raw data bytes
#[allow(dead_code)]
fn field_elements_to_bytes(elements: &[M31]) -> Vec<u8> {
    let mut bytes = Vec::new();

    for element in elements {
        // In stwo-prover, M31 doesn't have direct conversion to u32
        // Parse from string representation
        let value = element.to_string().parse::<u32>().unwrap_or(0);
        let element_bytes = value.to_le_bytes();
        bytes.extend_from_slice(&element_bytes);
    }

    bytes
}

/// Commits to data using the FRI protocol
///
/// # Arguments
///
/// * `data` - The raw data bytes
///
/// # Returns
///
/// A commitment to the data
pub fn commit(data: &[u8]) -> Result<Commitment> {
    // Convert the data to field elements
    let elements = bytes_to_field_elements(data);

    // Determine the domain size based on the number of elements
    let domain_size = calculate_domain_size(elements.len(), DEFAULT_EXPANSION_FACTOR);

    // Create a FRI prover with the default parameters
    let prover = FriProver::new(
        domain_size,
        DEFAULT_EXPANSION_FACTOR,
        DEFAULT_BATCH_SIZE,
        DEFAULT_FIELD_SIZE,
        DEFAULT_NUM_QUERIES,
        DEFAULT_FAN_IN,
        DEFAULT_BASE_DIMENSION,
    );

    // Reed-Solomon encode the data
    let encoded = polynomial::reed_solomon_encode(&elements, DEFAULT_EXPANSION_FACTOR)?;

    // Commit to the encoded data
    let (root, _) = prover.commit(&encoded)?;

    // Create and return the commitment
    let commitment = Commitment {
        root,
        metadata: CommitmentMetadata {
            domain_size,
            expansion_factor: DEFAULT_EXPANSION_FACTOR,
            batch_size: DEFAULT_BATCH_SIZE,
            field_size: DEFAULT_FIELD_SIZE,
        },
    };

    Ok(commitment)
}

/// Generates a FRI proof for committed data
///
/// # Arguments
///
/// * `commitment` - The commitment to the data
///
/// # Returns
///
/// A FRI proof
pub fn generate_proof(_commitment: &Commitment) -> Result<FriProof> {
    // Initialize FRI prover with the same parameters as during commitment
    // This is commented out for now since we don't use it yet
    // let prover = FriProver::new(
    //     commitment.metadata.domain_size,
    //     commitment.metadata.expansion_factor,
    //     commitment.metadata.batch_size,
    //     commitment.metadata.field_size,
    //     DEFAULT_NUM_QUERIES,
    //     DEFAULT_FAN_IN,
    //     DEFAULT_BASE_DIMENSION,
    // );

    // This would normally require access to the original data
    // For the purpose of this example, we'll generate a dummy proof
    // In a real implementation, the original data would be stored or reconstructed

    Err(FriedaError::InvalidInput(
        "Cannot generate proof without original data. Store the data in a database or reconstruct it.".to_string()
    ))
}

/// Verifies a FRI proof
///
/// # Arguments
///
/// * `commitment` - The commitment to the data
/// * `proof` - The FRI proof
///
/// # Returns
///
/// `true` if the proof is valid, `false` otherwise
pub fn verify(commitment: &Commitment, proof: &FriProof) -> Result<bool> {
    // Initialize FRI verifier with the same parameters as during commitment
    let verifier = FriVerifier::new(
        commitment.metadata.domain_size,
        commitment.metadata.expansion_factor,
        commitment.metadata.batch_size,
        commitment.metadata.field_size,
        DEFAULT_FAN_IN,
        DEFAULT_BASE_DIMENSION,
    );

    // Verify the proof
    verifier.verify(&commitment.root, proof)
}

/// Calculates the domain size for a given data size and expansion factor
///
/// # Arguments
///
/// * `data_size` - The size of the data (number of field elements)
/// * `expansion_factor` - The expansion factor (inverse rate)
///
/// # Returns
///
/// The domain size (must be a power of 2)
fn calculate_domain_size(data_size: usize, expansion_factor: usize) -> usize {
    let min_domain_size = data_size * expansion_factor;
    min_domain_size.next_power_of_two()
}

/// Reconstructs the original data from a FRI proof and commitment
///
/// # Arguments
///
/// * `commitment` - The commitment to the data
/// * `proof` - The FRI proof
///
/// # Returns
///
/// The reconstructed data, if possible
pub fn reconstruct(commitment: &Commitment, proof: &FriProof) -> Result<Vec<u8>> {
    // This is a simplified example and doesn't fully implement reconstruction
    // In a real implementation, reconstruction would require:
    // 1. Verifying the proof
    // 2. Collecting enough samples from the proof
    // 3. Interpolating the original polynomial
    // 4. Decoding the Reed-Solomon code

    if !verify(commitment, proof)? {
        return Err(FriedaError::VerificationFailed(
            "Proof verification failed".to_string(),
        ));
    }

    // Extract the samples from the proof
    let mut samples = Vec::new();
    for query_info in &proof.query_info {
        samples.push((query_info.index, query_info.value));
    }

    // We'd need enough samples to reconstruct the original data
    // For now, return an error since this is not fully implemented
    Err(FriedaError::DecodingError(
        "Data reconstruction not fully implemented".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_conversion() {
        // Test data
        let data = b"Hello, world!";

        // Convert to field elements and back
        let elements = bytes_to_field_elements(data);
        let recovered = field_elements_to_bytes(&elements);

        // Make sure the recovered data matches the original (up to padding)
        assert_eq!(&recovered[..data.len()], data);
    }

    #[test]
    fn test_calculate_domain_size() {
        // Test with various data sizes and expansion factors
        assert_eq!(calculate_domain_size(10, 2), 32);
        assert_eq!(calculate_domain_size(20, 4), 128);
        assert_eq!(calculate_domain_size(100, 2), 256);
    }
}
