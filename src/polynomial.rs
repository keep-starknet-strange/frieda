//! Polynomial operations module
//!
//! This module provides polynomial interpolation, evaluation, and commitment logic.
//! It implements Fast Fourier Transform (FFT), Inverse FFT (IFFT), Lagrange interpolation,
//! and Reed-Solomon encoding.

use crate::{
    field::{get_primitive_root_of_unity}, 
    FriedaError, Result, M31
};
use num_traits::identities::{One, Zero};

/// Evaluates a polynomial at a specific point
///
/// # Arguments
///
/// * `coeffs` - The coefficients of the polynomial in ascending order of degree
/// * `point` - The point at which to evaluate the polynomial
///
/// # Returns
///
/// The value of the polynomial at the specified point
pub fn evaluate_polynomial(coeffs: &[M31], point: M31) -> M31 {
    if coeffs.is_empty() {
        return Zero::zero();
    }
    
    // Use Horner's method for efficient evaluation
    let mut result = coeffs[coeffs.len() - 1];
    for i in (0..coeffs.len() - 1).rev() {
        result = result * point + coeffs[i];
    }
    
    result
}

/// Performs Fast Fourier Transform (FFT) on the given coefficients
///
/// # Arguments
///
/// * `coeffs` - The coefficients of the polynomial in ascending order of degree
/// * `domain_size` - The size of the evaluation domain (must be a power of 2)
///
/// # Returns
///
/// The evaluations of the polynomial at the domain points
pub fn fft(mut coeffs: Vec<M31>, domain_size: usize) -> Result<Vec<M31>> {
    if !domain_size.is_power_of_two() {
        return Err(FriedaError::InvalidInput("Domain size must be a power of 2".to_string()));
    }
    
    // Pad the coefficients with zeros if necessary
    coeffs.resize(domain_size, M31::default());
    
    let omega = get_primitive_root_of_unity(domain_size);
    
    // Call the recursive FFT implementation
    Ok(fft_recursive(&coeffs, domain_size, omega))
}

/// Recursive implementation of the Fast Fourier Transform
///
/// # Arguments
///
/// * `coeffs` - The coefficients of the polynomial
/// * `n` - The size of the subproblem (must be a power of 2)
/// * `omega` - The primitive n-th root of unity
///
/// # Returns
///
/// The result of the FFT
fn fft_recursive(coeffs: &[M31], n: usize, omega: M31) -> Vec<M31> {
    if n == 1 {
        return vec![coeffs[0]];
    }
    
    let n_half = n / 2;
    
    // Split coefficients into even and odd indices
    let mut even = Vec::with_capacity(n_half);
    let mut odd = Vec::with_capacity(n_half);
    
    for i in 0..n_half {
        even.push(coeffs[2 * i]);
        odd.push(coeffs[2 * i + 1]);
    }
    
    // Recursively compute FFT on the even and odd parts
    let omega_squared = omega * omega;
    let even_fft = fft_recursive(&even, n_half, omega_squared);
    let odd_fft = fft_recursive(&odd, n_half, omega_squared);
    
    // Combine the results
    let mut result = vec![M31::default(); n];
    let mut omega_pow: M31 = One::one();
    
    for i in 0..n_half {
        result[i] = even_fft[i] + omega_pow * odd_fft[i];
        result[i + n_half] = even_fft[i] - omega_pow * odd_fft[i];
        omega_pow *= omega;
    }
    
    result
}

/// Performs Inverse Fast Fourier Transform (IFFT) on the given evaluations
///
/// # Arguments
///
/// * `evals` - The evaluations of the polynomial at the domain points
/// * `domain_size` - The size of the evaluation domain (must be a power of 2)
///
/// # Returns
///
/// The coefficients of the polynomial in ascending order of degree
pub fn ifft(mut evals: Vec<M31>, domain_size: usize) -> Result<Vec<M31>> {
    if !domain_size.is_power_of_two() {
        return Err(FriedaError::InvalidInput("Domain size must be a power of 2".to_string()));
    }
    
    // Pad the evaluations with zeros if necessary
    evals.resize(domain_size, M31::default());
    
    // Compute the inverse of the primitive root of unity
    let omega = get_primitive_root_of_unity(domain_size);
    // We use One for the identity and division for the inverse
    let one: M31 = One::one();
    let omega_inv = one / omega;
    
    // Call the FFT with the inverse root
    let mut coeffs = fft_recursive(&evals, domain_size, omega_inv);
    
    // Scale by the inverse of domain_size
    let domain_size_inv = one / M31::from(domain_size as u32);
    for coeff in &mut coeffs {
        *coeff *= domain_size_inv;
    }
    
    Ok(coeffs)
}

/// Performs Reed-Solomon encoding on the given data
///
/// # Arguments
///
/// * `data` - The data to encode
/// * `expansion_factor` - The factor by which to expand the data (must be >= 1)
///
/// # Returns
///
/// The Reed-Solomon encoded data
pub fn reed_solomon_encode(data: &[M31], expansion_factor: usize) -> Result<Vec<M31>> {
    if expansion_factor < 1 {
        return Err(FriedaError::InvalidInput("Expansion factor must be at least 1".to_string()));
    }
    
    let data_len = data.len();
    let domain_size = data_len * expansion_factor;
    
    // Ensure domain_size is a power of 2
    let domain_size = domain_size.next_power_of_two();
    
    // Compute the FFT (polynomial evaluations at domain points)
    let encoded = fft(data.to_vec(), domain_size)?;
    
    Ok(encoded)
}

/// Interpolates a polynomial from the given evaluations
///
/// # Arguments
///
/// * `evals` - The evaluations of the polynomial at the domain points
/// * `domain` - The domain points at which the polynomial was evaluated
///
/// # Returns
///
/// The coefficients of the interpolated polynomial in ascending order of degree
pub fn lagrange_interpolation(evals: &[M31], domain: &[M31]) -> Result<Vec<M31>> {
    if evals.len() != domain.len() {
        return Err(FriedaError::InvalidInput(
            "Number of evaluations must match number of domain points".to_string()
        ));
    }
    
    let n = evals.len();
    
    // For each domain point, compute the Lagrange basis polynomial
    let mut result = vec![M31::default(); n];
    
    for i in 0..n {
        let mut basis: Vec<M31> = vec![M31::default(); n];
        basis[0] = One::one();
        
        // Compute the Lagrange basis polynomial for the i-th point
        for j in 0..n {
            if i == j {
                continue;
            }
            
            // Compute (x - domain[j]) and update the basis polynomial
            let mut new_basis: Vec<M31> = vec![M31::default(); n + 1];
            for k in 0..basis.len() {
                new_basis[k + 1] += basis[k];
                new_basis[k] -= basis[k] * domain[j];
            }
            
            // Truncate to keep the degree correct
            basis = new_basis[..n].to_vec();
            
            // Scale by 1/(domain[i] - domain[j])
            let one: M31 = One::one();
            let scale = one / (domain[i] - domain[j]);
            for k in 0..basis.len() {
                basis[k] *= scale;
            }
        }
        
        // Multiply by evaluation and add to result
        for k in 0..n {
            result[k] += basis[k] * evals[i];
        }
    }
    
    Ok(result)
}

/// Checks if a polynomial is low-degree (degree < degree_bound)
///
/// # Arguments
///
/// * `coeffs` - The coefficients of the polynomial in ascending order of degree
/// * `degree_bound` - The upper bound on the degree
///
/// # Returns
///
/// `true` if the polynomial's degree is less than the bound, `false` otherwise
pub fn is_low_degree(coeffs: &[M31], degree_bound: usize) -> bool {
    // Find the actual degree of the polynomial
    let mut actual_degree = coeffs.len() - 1;
    while actual_degree > 0 && coeffs[actual_degree] == M31::default() {
        actual_degree -= 1;
    }
    
    actual_degree < degree_bound
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluate_polynomial() {
        // Polynomial: 3x^2 + 2x + 1
        let coeffs = vec![M31::from(1), M31::from(2), M31::from(3)];
        
        // Evaluate at x = 2: 3(2)^2 + 2(2) + 1 = 3*4 + 4 + 1 = 12 + 5 = 17
        let point = M31::from(2);
        let expected = M31::from(17);
        
        assert_eq!(evaluate_polynomial(&coeffs, point), expected);
    }

    #[test]
    fn test_fft_and_ifft() {
        // Polynomial: 3x^2 + 2x + 1
        let coeffs = vec![M31::from(1), M31::from(2), M31::from(3)];
        
        // Use a domain size of 4
        let domain_size = 4;
        
        // Compute the FFT
        let evals = fft(coeffs.clone(), domain_size).unwrap();
        
        // Compute the IFFT
        let recovered_coeffs = ifft(evals, domain_size).unwrap();
        
        // Check that the first 3 coefficients match (the rest should be zero)
        assert_eq!(recovered_coeffs[0], coeffs[0]);
        assert_eq!(recovered_coeffs[1], coeffs[1]);
        assert_eq!(recovered_coeffs[2], coeffs[2]);
    }

    #[test]
    fn test_reed_solomon_encode() {
        // Data: [1, 2, 3]
        let data = vec![M31::from(1), M31::from(2), M31::from(3)];
        
        // Encode with expansion factor 2
        let encoded = reed_solomon_encode(&data, 2).unwrap();
        
        // The encoded data should have length 8 (next power of 2 after 3*2)
        assert_eq!(encoded.len(), 8);
        
        // Check that the encoded data is consistent with the original
        let recovered = ifft(encoded, 8).unwrap();
        assert_eq!(recovered[0], data[0]);
        assert_eq!(recovered[1], data[1]);
        assert_eq!(recovered[2], data[2]);
    }

    #[test]
    fn test_is_low_degree() {
        // Polynomial: 3x^2 + 2x + 1 (degree 2)
        let coeffs = vec![M31::from(1), M31::from(2), M31::from(3)];
        
        // Check if degree < 3
        assert!(is_low_degree(&coeffs, 3));
        
        // Check if degree < 2
        assert!(!is_low_degree(&coeffs, 2));
    }
}