use serde::{Deserialize, Serialize};
use stwo_prover::core::{
    backend::CpuBackend,
    channel::{Blake2sChannel, Channel},
    circle::Coset,
    fields::{
        m31::{BaseField, M31},
        qm31::{SecureField, QM31},
    },
    fri::{CirclePolyDegreeBound, FriProof, FriProver, FriVerifier},
    pcs::PcsConfig,
    poly::{
        circle::{CircleDomain, CircleEvaluation, CirclePoly, PolyOps, SecureEvaluation},
        BitReversedOrder,
    },
    proof_of_work::GrindOps,
    vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher},
};

use crate::{commit::Commitment, utils};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    pub proof: FriProof<Blake2sMerkleHasher>,
    pub proof_of_work: u64,
    pub pcs_config: PcsConfig,
    pub log_size_bound: u32,
    pub evaluations: Vec<QM31>,
    pub coset_log_size: u32,
}

pub fn generate_proof(data: &[u8], seed: Option<u64>, pcs_config: PcsConfig) -> Proof {
    commit_and_generate_proof(data, seed, pcs_config).1
}

pub fn commit_and_generate_proof(
    data: &[u8],
    seed: Option<u64>,
    pcs_config: PcsConfig,
) -> (Commitment, Proof) {
    // Parse bytes to field elements.
    let polynomial = utils::polynomial_from_bytes(data);

    let channel = &mut Blake2sChannel::default();
    if let Some(seed) = seed {
        channel.mix_u64(seed);
    }

    let coset_log_size = polynomial.log_size() + pcs_config.fri_config.log_blowup_factor - 1;
    let coset = Coset::half_odds(coset_log_size);
    let domain = CircleDomain::new(coset);
    let twiddles = CpuBackend::precompute_twiddles(coset);
    let evaluations: SecureEvaluation<CpuBackend, BitReversedOrder> =
        polynomial.evaluate_with_twiddles(domain, &twiddles);
    let secure_evaluations = [SecureEvaluation::<CpuBackend, BitReversedOrder>::new(
        domain,
        evaluations.into_iter().collect(),
    ); 1];

    let fri_prover = FriProver::<CpuBackend, Blake2sMerkleChannel>::commit(
        channel,
        pcs_config.fri_config,
        &secure_evaluations,
        &twiddles,
    );
    let proof_of_work = CpuBackend::grind(channel, pcs_config.pow_bits);
    channel.mix_u64(proof_of_work);
    let (proof, queries) = fri_prover.decommit(channel);
    assert!(queries.keys().len() == 1);
    let queries = queries.values().next().unwrap();

    let evaluations = queries
        .iter()
        .map(|i| secure_evaluations[0].at(*i))
        .collect();
    (
        proof.first_layer.commitment.0,
        Proof {
            proof,
            proof_of_work,
            pcs_config,
            log_size_bound: polynomial.log_size(),
            evaluations,
            coset_log_size,
        },
    )
}

pub fn verify_proof(proof: Proof, seed: Option<u64>) -> bool {
    let channel = &mut Blake2sChannel::default();
    if let Some(seed) = seed {
        channel.mix_u64(seed);
    }
    let Ok(mut fri_verifier) = FriVerifier::<Blake2sMerkleChannel>::commit(
        channel,
        proof.pcs_config.fri_config,
        proof.proof,
        vec![CirclePolyDegreeBound::new(proof.log_size_bound)],
    ) else {
        return false;
    };
    channel.mix_u64(proof.proof_of_work);
    if channel.trailing_zeros() < proof.pcs_config.pow_bits {
        return false;
    }
    let queries = fri_verifier.sample_query_positions(channel);
    println!("verify queries {:?}", queries);
    assert!(queries.keys().len() == 1);
    fri_verifier
        .decommit(vec![proof.evaluations.into_iter().collect()])
        .is_ok()
}

pub fn get_queries_from_proof(proof: Proof, seed: Option<u64>) -> (u32, Vec<usize>) {
    let channel = &mut Blake2sChannel::default();
    if let Some(seed) = seed {
        channel.mix_u64(seed);
    }
    let Ok(mut fri_verifier) = FriVerifier::<Blake2sMerkleChannel>::commit(
        channel,
        proof.pcs_config.fri_config,
        proof.proof,
        vec![CirclePolyDegreeBound::new(proof.log_size_bound)],
    ) else {
        panic!("Failed to commit");
    };
    channel.mix_u64(proof.proof_of_work);
    if channel.trailing_zeros() < proof.pcs_config.pow_bits {
        panic!("Proof of work is invalid");
    }
    let queries = fri_verifier.sample_query_positions(channel);
    queries.into_iter().next().unwrap()
}

#[cfg(test)]
mod tests {
    use stwo_prover::core::fri::FriConfig;

    use crate::commit::commit;

    const PCS_CONFIG: PcsConfig = PcsConfig {
        fri_config: FriConfig {
            log_blowup_factor: 4,
            log_last_layer_degree_bound: 1,
            n_queries: 20,
        },
        pow_bits: 20,
    };
    use super::*;

    #[test]
    fn test_generate_proof() {
        let data = include_bytes!("../blob");
        let proof = generate_proof(data, None, PCS_CONFIG);
        assert_ne!(proof.proof.inner_layers.len(), 0);
    }

    #[test]
    fn test_commit_and_generate_proof() {
        let data = include_bytes!("../blob");
        let (commitment, proof) = commit_and_generate_proof(data, None, PCS_CONFIG);
        assert_eq!(
            commitment,
            commit(data, PCS_CONFIG.fri_config.log_blowup_factor)
        );
        assert_eq!(proof.proof.first_layer.commitment.0, commitment);
    }
    #[test]
    fn test_verify_proof() {
        let data = include_bytes!("../blob");
        let proof = generate_proof(data, None, PCS_CONFIG);
        assert!(verify_proof(proof, None));
    }

    #[test]
    fn test_verify_proof_with_invalid_pow() {
        let data = include_bytes!("../blob");
        let mut proof = generate_proof(data, None, PCS_CONFIG);
        proof.proof_of_work += 1;
        assert!(!verify_proof(proof, None));
    }

    #[test]
    fn test_verify_proof_with_invalid_evaluations() {
        let data = include_bytes!("../blob");
        let mut proof = generate_proof(data, None, PCS_CONFIG);
        proof.evaluations[0] += M31::from_u32_unchecked(1);
        assert!(!verify_proof(proof, None));
    }
    #[test]
    fn test_verify_proof_with_invalid_evaluations_order() {
        let data = include_bytes!("../blob");
        let mut proof = generate_proof(data, None, PCS_CONFIG);
        proof.evaluations.reverse();
        assert!(!verify_proof(proof, None));
    }

    #[test]
    #[should_panic]
    fn test_verify_proof_with_invalid_evaluations_length() {
        let data = include_bytes!("../blob");
        let mut proof = generate_proof(data, None, PCS_CONFIG);
        proof.evaluations.pop();
        assert!(!verify_proof(proof, None));
    }

    #[test]
    fn test_verify_proof_with_invalid_1_evaluation_unordered() {
        let data = include_bytes!("../blob");
        let mut proof = generate_proof(data, None, PCS_CONFIG);
        proof.evaluations.swap(0, 1);
        assert!(!verify_proof(proof, None));
    }

    #[test]
    fn test_verify_proof_with_seed() {
        let data = include_bytes!("../blob");
        let proof = generate_proof(data, Some(1), PCS_CONFIG);
        let proof2 = generate_proof(data, Some(2), PCS_CONFIG);
        assert_ne!(proof.evaluations, proof2.evaluations);
        assert!(verify_proof(proof.clone(), Some(1)));
        assert!(verify_proof(proof2.clone(), Some(2)));
        assert!(!verify_proof(proof.clone(), Some(2)));
        assert!(!verify_proof(proof2.clone(), Some(1)));
    }
}
