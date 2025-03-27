use stwo_prover::core::{
    backend::CpuBackend,
    circle::Coset,
    fields::{
        m31::{BaseField, M31},
        qm31::QM31,
    },
    poly::{
        circle::{CircleDomain, CircleEvaluation},
        BitReversedOrder,
    },
};

use crate::utils;

pub fn reconstruct(samples: Vec<QM31>, coset_log_size: u32) -> Vec<u8> {
    let domain = CircleDomain::new(Coset::half_odds(coset_log_size))
        .split(4)
        .0;
    let evaluations = CircleEvaluation::<CpuBackend, BaseField, BitReversedOrder>::new(
        domain,
        samples.iter().map(|x| x.to_m31_array()[0]).collect(),
    );
    let polynomial = evaluations.interpolate();
    utils::felts_to_bytes_le(&polynomial.coeffs)
}

#[cfg(test)]
mod tests {
    use rayon::prelude::*;
    use std::collections::HashSet;

    use crate::proof::{generate_proof, get_queries_from_proof, verify_proof};
    use stwo_prover::core::{fri::FriConfig, pcs::PcsConfig};

    use super::*;
    const PCS_CONFIG: PcsConfig = PcsConfig {
        fri_config: FriConfig {
            log_blowup_factor: 4,
            log_last_layer_degree_bound: 1,
            n_queries: 20,
        },
        pow_bits: 20,
    };

    #[test]
    fn test_reconstruct() {
        // original data
        let data = include_bytes!("../blob").to_vec();
        let mut evaluations = Vec::with_capacity(data.len());
        let mut query_positions = Vec::with_capacity(data.len());
        let coset_log_size = generate_proof(&data, None, PCS_CONFIG).coset_log_size;
        println!("poly coeffs {}", utils::bytes_to_felt_le(&data).len());
        let poly_size = utils::bytes_to_felt_le(&data).len().next_power_of_two();
        println!("poly_size {}", poly_size);
        println!("coset_log_size {}", coset_log_size);
        println!(
            "n_queries {}",
            poly_size / PCS_CONFIG.fri_config.n_queries + PCS_CONFIG.security_bits() as usize
        );
        // Collect evaluations and query positions
        let pairs = (0..((poly_size / PCS_CONFIG.fri_config.n_queries) as u64
            + PCS_CONFIG.security_bits() as u64))
            .into_par_iter()
            .map(|i| {
                println!("i {}", i);
                let proof = generate_proof(&data, Some(i), PCS_CONFIG);
                let pos = get_queries_from_proof(proof.clone(), Some(i));
                (proof.evaluations, pos)
            })
            .collect::<Vec<_>>();
        for (evals, pos) in pairs {
            evaluations.extend_from_slice(&evals);
            query_positions.extend_from_slice(&pos);
        }
        println!("evaluations {:?}", evaluations.len());
        // Sort evaluations according to query positions
        let mut sorted_pairs: Vec<_> = query_positions
            .into_iter()
            .zip(evaluations)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        sorted_pairs.sort_by_key(|(pos, _)| *pos);
        let mut verifier = 0;
        println!("sorted_pairs {:?}", sorted_pairs.len());
        println!("verifying continuity");
        sorted_pairs.iter().for_each(|(pos, _)| {
            assert_eq!(pos, &verifier, "failed position at index {}", verifier);
            verifier += 1;
        });
        println!("verifying continuity done");
        let sorted_evaluations: Vec<_> = sorted_pairs.into_iter().map(|(_, eval)| eval).collect();

        // Use only 1/16th of the evaluations (since blowup_factor is 4)
        let sample_size = poly_size / 16;
        println!(
            "Using {} samples out of {}",
            sample_size,
            sorted_evaluations.len()
        );

        let reconstructed = reconstruct(sorted_evaluations[..sample_size].to_vec(), coset_log_size);
        println!("reconstructed len {}", reconstructed.len());
        println!("data len {}", data.len());

        for i in 0..data.len() {
            assert_eq!(reconstructed[i], data[i], "failed at index {}", i);
        }
    }
}
