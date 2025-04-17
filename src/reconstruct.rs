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

/// Returns the bit-reversed position of an index for a given array size
fn bit_reversed_index(index: usize, size: usize) -> usize {
    let bits = size.ilog2();
    let res = ((index as u32).reverse_bits() >> (32 - bits)) as usize;
    println!("res {}", res);
    res
}

/// Reorders evaluations from FFT bit-reversed order to normal order
fn reorder_evaluations(data: &mut [QM31]) {
    let n = data.len();
    let mut temp = vec![QM31::default(); n];

    // Copy values to their correct positions
    for i in 0..n {
        // For each index i, compute its position in the ordered array
        // This is done by reversing the bits of i and shifting right by (32 - log2(n))
        let bits = (n as f64).log2() as u32;
        let reversed = (i as u32).reverse_bits() >> (32 - bits);
        temp[reversed as usize] = data[i];
    }

    // Copy back to original array
    data.copy_from_slice(&temp);
}

/// Reorders evaluations from normal order to FFT bit-reversed order
fn reorder_to_bit_reversed(data: &mut [QM31]) {
    let n = data.len();
    let mut temp = vec![QM31::default(); n];

    // Copy values to their bit-reversed positions
    for i in 0..n {
        // For each index i, compute its position in the bit-reversed array
        // This is done by reversing the bits of i and shifting right by (32 - log2(n))
        let bits = (n as f64).log2() as u32;
        let reversed = (i as u32).reverse_bits() >> (32 - bits);
        temp[i] = data[reversed as usize];
    }

    // Copy back to original array
    data.copy_from_slice(&temp);
}

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

    use crate::proof::{generate_proof, get_queries_from_proof};
    use stwo_prover::core::{fri::FriConfig, pcs::PcsConfig};

    use super::*;
    const PCS_CONFIG: PcsConfig = PcsConfig {
        fri_config: FriConfig {
            log_blowup_factor: 4,
            log_last_layer_degree_bound: 1,
            n_queries: 5,
        },
        pow_bits: 20,
    };

    #[test]
    fn test_reconstruct() {
        let data = include_bytes!("../blob")[..100].to_vec();
        let polys = utils::polynomial_from_bytes(&data);
        let (proof, (_, pos)) = {
            let proof = generate_proof(&data, None, PCS_CONFIG);
            let queries = get_queries_from_proof(proof.clone(), None);
            println!("test queries {:?}", queries);
            (proof, queries)
        };

        let domain = CircleDomain::new(Coset::half_odds(proof.coset_log_size));

        let mut new_evals = Vec::with_capacity(pos.len());

        for pos in pos {
            println!("pos {}", pos);
            let point = domain.at(bit_reversed_index(pos, domain.size()));
            new_evals.push(polys.eval_at_point(point.into_ef()));
        }
        println!("new_evals {:#?}", new_evals);
        println!("proof.evaluations {:#?}", proof.evaluations);
        assert_eq!(new_evals, proof.evaluations);
    }
    #[test]
    fn test_something() {
        let data = include_bytes!("../blob").to_vec();
        let polys = utils::polynomial_from_bytes(&data);
        println!(
            "generating {} proofs",
            (data.len() as f64 / (3.75 * 20.)) as u32
        );
        let proofs_pos = (0..10)
            .into_par_iter()
            .map(|i| {
                let proof = generate_proof(&data, Some(i), PCS_CONFIG);
                let queries = get_queries_from_proof(proof.clone(), Some(i));
                (proof, queries)
            })
            .collect::<Vec<_>>();

        let domain = CircleDomain::new(Coset::half_odds(proofs_pos[0].0.coset_log_size));
        let pos = proofs_pos
            .iter()
            .flat_map(|(proof, (_log_size, pos))| {
                pos.iter()
                    .map(move |p| domain.at(bit_reversed_index(*p, proof.coset_log_size as usize)))
            })
            .collect::<Vec<_>>();
        let evals = proofs_pos
            .into_iter()
            .flat_map(|(proof, _)| proof.evaluations)
            .collect::<Vec<_>>();
        pos.into_par_iter().zip(evals).for_each(|(point, eval)| {
            let new_eval = polys.eval_at_point(point.into_ef());
            println!("eval {}", eval);
            println!("new_eval {}", new_eval);
            assert_eq!(eval, new_eval);
        });
    }

    // #[test]
    // fn test_bidibop() {
    //     // original data
    //     let data = include_bytes!("../blob").to_vec();
    //     let mut evaluations = Vec::with_capacity(data.len());
    //     // let mut query_positions = Vec::with_capacity(data.len());
    //     let coset_log_size = generate_proof(&data, None, PCS_CONFIG).coset_log_size;
    //     let polys = utils::polynomial_from_bytes(&data);
    //     let poly_size = utils::bytes_to_felt_le(&data).len().next_power_of_two();
    //     println!("poly_size {}", poly_size);
    //     println!("coset_log_size {}", coset_log_size);
    //     println!(
    //         "n_queries {}",
    //         poly_size / PCS_CONFIG.fri_config.n_queries + PCS_CONFIG.security_bits() as usize
    //     );

    //     // Collect evaluations and query positions
    //     let pairs = (0..((poly_size / (16 * PCS_CONFIG.fri_config.n_queries)) as u64
    //         + PCS_CONFIG.security_bits() as u64))
    //         .into_par_iter()
    //         .map(|i| {
    //             println!("i {}", i);
    //             let proof = generate_proof(&data, Some(i), PCS_CONFIG);
    //             let pos = get_queries_from_proof(proof.clone(), Some(i));
    //             (proof.evaluations, pos)
    //         })
    //         .collect::<Vec<_>>();
    //     // for (evals, pos) in pairs {
    //     //     evaluations.extend_from_slice(&evals);
    //     //     query_positions.extend_from_slice(&pos);
    //     // }
    //     println!("evaluations {:?}", evaluations.len());
    //     // Sort evaluations according to query positions
    //     let mut sorted_pairs: Vec<_> = query_positions
    //         .into_iter()
    //         .zip(evaluations)
    //         .collect::<HashSet<_>>()
    //         .into_iter()
    //         .collect::<Vec<_>>();
    //     sorted_pairs.sort_by_key(|(pos, _)| *pos);
    //     let mut verifier = 0;
    //     println!("sorted_pairs {:?}", sorted_pairs.len());
    //     // println!("verifying continuity");
    //     // sorted_pairs.iter().for_each(|(pos, _)| {
    //     //     assert_eq!(pos, &verifier, "failed position at index {}", verifier);
    //     //     verifier += 1;
    //     // });
    //     // println!("verifying continuity done");
    //     let domain_points = sorted_pairs
    //         .iter()
    //         .map(|(pos, _)| CirclePoint::get_point(*pos as u128))
    //         .collect::<Vec<_>>();
    //     let new_evals = domain_points
    //         .into_par_iter()
    //         .flat_map(|point| {
    //             polys
    //                 .iter()
    //                 .map(|poly| CpuBackend::eval_at_point(poly, point))
    //                 .collect::<Vec<_>>()
    //         })
    //         .collect::<Vec<_>>();
    //     let sorted_evaluations: Vec<_> = sorted_pairs.into_iter().map(|(_, eval)| eval).collect();
    //     assert_eq!(sorted_evaluations, new_evals);

    //     // Use only 1/16th of the evaluations (since blowup_factor is 4)
    //     let sample_size = poly_size / 16;
    //     println!(
    //         "Using {} samples out of {}",
    //         sample_size,
    //         sorted_evaluations.len()
    //     );

    //     let reconstructed = reconstruct(sorted_evaluations[..sample_size].to_vec(), coset_log_size);
    //     println!("reconstructed len {}", reconstructed.len());
    //     println!("data len {}", data.len());

    //     for i in 0..data.len() {
    //         assert_eq!(reconstructed[i], data[i], "failed at index {}", i);
    //     }
    // }
}
