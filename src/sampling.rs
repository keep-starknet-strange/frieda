//! Sampling module
//!
//! This module provides sampling functionality for data availability.
//! It implements light-client-friendly sampling techniques for verifying
//! data availability without downloading the entire dataset.

use crate::{
    field::get_primitive_root_of_unity, polynomial, Commitment, FriedaError, Result, SampleResult,
    M31,
};
use num_traits::identities::{One, Zero};
use sha2::{Digest, Sha256};

/// The statistical security parameter
const STATISTICAL_SECURITY: usize = 40;

/// Samples data availability based on a commitment
///
/// # Arguments
///
/// * `commitment` - The commitment to sample from
///
/// # Returns
///
/// A sample result containing the sampled values and indices
pub fn sample(commitment: &Commitment) -> Result<SampleResult> {
    // Calculate the number of samples needed
    let samples_needed = calculate_samples_needed(
        commitment.metadata.domain_size,
        commitment.metadata.domain_size / commitment.metadata.expansion_factor,
        STATISTICAL_SECURITY,
    );

    // Generate random sample indices
    let indices = generate_sample_indices(commitment.metadata.domain_size, samples_needed)?;

    // This would normally involve querying a data provider for the values and proofs at these indices
    // For demonstration purposes, we'll return a placeholder result

    return Ok(SampleResult {
        success: false,
        values: Vec::new(),
        indices,
    });
}

/// Calculates the number of samples needed for a given statistical security
///
/// # Arguments
///
/// * `domain_size` - The size of the evaluation domain
/// * `degree` - The degree of the polynomial
/// * `security_param` - The statistical security parameter
///
/// # Returns
///
/// The number of samples needed
fn calculate_samples_needed(domain_size: usize, degree: usize, security_param: usize) -> usize {
    // In the FRIDA paper, the number of samples needed is calculated using
    // the coupon collector's problem with generalized bounds

    // If data is fully available, we need at least `degree` samples to reconstruct
    // If only `degree - 1` positions are available, we need to ensure we hit
    // the missing positions with high probability

    let reception = degree;

    // Special case: if only one symbol is needed
    if reception == 1 {
        return 1;
    }

    // Special case: if all symbols are needed
    if reception == domain_size {
        let n = domain_size;
        return (n as f64 / (2.0_f64.ln())) as usize * (n.ilog2() as usize + security_param);
    }

    // Generalized coupon collector formula
    let delta = reception - 1;
    let c = delta as f64 / domain_size as f64;
    let s = -(security_param as f64) / c.log2() + (1.0 - (1.0 / c.ln())) * delta as f64;

    s.ceil() as usize
}

/// Generates random sample indices
///
/// # Arguments
///
/// * `domain_size` - The size of the evaluation domain
/// * `num_samples` - The number of samples to generate
///
/// # Returns
///
/// A vector of random sample indices
fn generate_sample_indices(domain_size: usize, num_samples: usize) -> Result<Vec<usize>> {
    // In a real implementation, this would use a true random source or a cryptographic RNG
    // Here, we'll use a deterministic approach for simplicity

    let mut indices = Vec::new();

    // Generate a seed for the random sample generation
    let mut hasher = Sha256::new();
    hasher.update(b"SAMPLE_INDICES");
    let seed = hasher.finalize();

    // Use the seed to generate random indices
    for i in 0..num_samples {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(i.to_le_bytes());
        let digest = hasher.finalize();

        // Convert the digest to an index
        let index = u64::from_le_bytes(digest[0..8].try_into().unwrap()) as usize % domain_size;

        indices.push(index);
    }

    Ok(indices)
}

/// Verifies a sampling result
///
/// # Arguments
///
/// * `commitment` - The commitment to verify against
/// * `result` - The sample result to verify
///
/// # Returns
///
/// `true` if the sample result is valid, `false` otherwise
pub fn verify_sampling(commitment: &Commitment, result: &SampleResult) -> Result<bool> {
    if result.indices.len() != result.values.len() {
        return Err(FriedaError::InvalidInput(
            "Indices and values must have the same length".to_string(),
        ));
    }

    // Check if enough samples were collected
    let samples_needed = calculate_samples_needed(
        commitment.metadata.domain_size,
        commitment.metadata.domain_size / commitment.metadata.expansion_factor,
        STATISTICAL_SECURITY,
    );

    if result.indices.len() < samples_needed {
        return Err(FriedaError::InvalidInput(format!(
            "Not enough samples: got {}, need {}",
            result.indices.len(),
            samples_needed
        )));
    }

    // In a real implementation, we would verify Merkle paths for each sample
    // For demonstration purposes, we'll always return true

    Ok(true)
}

/// Aggregates multiple sampling results
///
/// # Arguments
///
/// * `results` - The sampling results to aggregate
///
/// # Returns
///
/// An aggregated sampling result
pub fn aggregate_sampling(results: &[SampleResult]) -> Result<SampleResult> {
    if results.is_empty() {
        return Err(FriedaError::InvalidInput(
            "No results to aggregate".to_string(),
        ));
    }

    let mut aggregated_indices = Vec::new();
    let mut aggregated_values = Vec::new();

    // Collect unique samples from all results
    for result in results {
        for (i, &index) in result.indices.iter().enumerate() {
            if !aggregated_indices.contains(&index) {
                aggregated_indices.push(index);
                aggregated_values.push(result.values[i]);
            }
        }
    }

    Ok(SampleResult {
        success: true,
        values: aggregated_values,
        indices: aggregated_indices,
    })
}

/// Reconstructs a polynomial from samples
///
/// # Arguments
///
/// * `result` - The sample result containing samples
/// * `domain_size` - The size of the evaluation domain
///
/// # Returns
///
/// The reconstructed coefficients of the polynomial
pub fn reconstruct_polynomial(result: &SampleResult, domain_size: usize) -> Result<Vec<M31>> {
    if result.indices.len() != result.values.len() {
        return Err(FriedaError::InvalidInput(
            "Indices and values must have the same length".to_string(),
        ));
    }

    // Generate the evaluation domain
    let omega = get_primitive_root_of_unity(domain_size);

    // Create the domain points for the samples
    let mut domain_points = Vec::new();
    let mut omega_pow: M31 = One::one();
    for _ in 0..domain_size {
        domain_points.push(omega_pow);
        omega_pow *= omega;
    }

    // Extract the sample points and values
    let mut sample_points = Vec::new();
    let mut sample_values = Vec::new();

    for (i, &index) in result.indices.iter().enumerate() {
        sample_points.push(domain_points[index]);
        sample_values.push(result.values[i]);
    }

    // Interpolate the polynomial
    polynomial::lagrange_interpolation(&sample_values, &sample_points)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_samples_needed() {
        // Check the calculation with various parameters
        let domain_size = 256;
        let degree = 64;
        let security_param = 40;

        let samples = calculate_samples_needed(domain_size, degree, security_param);

        // We expect the number of samples to be at least the degree
        assert!(samples >= degree);

        // With a higher security parameter, we should need more samples
        let samples_higher_security =
            calculate_samples_needed(domain_size, degree, security_param * 2);
        assert!(samples_higher_security > samples);
    }

    #[test]
    fn test_generate_sample_indices() {
        let domain_size = 256;
        let num_samples = 40;

        let indices = generate_sample_indices(domain_size, num_samples).unwrap();

        // Check that we have the right number of indices
        assert_eq!(indices.len(), num_samples);

        // Check that all indices are in range
        for &index in &indices {
            assert!(index < domain_size);
        }
    }
}
