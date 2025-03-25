use stwo_prover::core::{
    backend::CpuBackend,
    channel::{Blake2sChannel, Channel},
    circle::Coset,
    fields::{
        m31::BaseField,
        qm31::{SecureField, QM31},
    },
    fri::{CirclePolyDegreeBound, FriConfig, FriProof, FriProver, FriVerifier},
    poly::{
        circle::{CircleDomain, CircleEvaluation, CirclePoly, PolyOps, SecureEvaluation},
        BitReversedOrder,
    },
    proof_of_work::GrindOps,
    vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher},
};

use crate::{commit::Commitment, utils};

#[derive(Clone, Debug)]
pub struct Proof {
    pub proof: FriProof<Blake2sMerkleHasher>,
    pub proof_of_work: u64,
    pub log_size_bound: u32,
    pub evaluations: Vec<QM31>,
}

pub const FRI_CONFIG: FriConfig = FriConfig {
    log_blowup_factor: 4,
    log_last_layer_degree_bound: 0,
    n_queries: 20,
};
pub const POW_BITS: u32 = 20;

pub fn generate_proof(data: &[u8]) -> Proof {
    commit_and_generate_proof(data).1
}

pub fn commit_and_generate_proof(data: &[u8]) -> (Commitment, Proof) {
    // Parse bytes to field elements.
    let mut coefficients = utils::bytes_to_felt_le(data);
    let channel = &mut Blake2sChannel::default();
    // The polynomial should have 2**n coefficients.
    let log_next_pow_of_2 = (coefficients.len() as f64).log2().ceil() as u32;
    // Pad with 0s
    coefficients.resize(1 << log_next_pow_of_2, BaseField::from_u32_unchecked(0));
    let polynomial = CirclePoly::<CpuBackend>::new(coefficients.clone());
    let coset = Coset::half_odds(polynomial.log_size() + FRI_CONFIG.log_blowup_factor - 1);
    let domain = CircleDomain::new(coset);
    let twiddles = CpuBackend::precompute_twiddles(coset);
    let evaluations: CircleEvaluation<CpuBackend, BaseField, BitReversedOrder> =
        polynomial.evaluate_with_twiddles(domain, &twiddles);
    let secure_evaluations: [SecureEvaluation<CpuBackend, BitReversedOrder>; 1] =
        [SecureEvaluation::<CpuBackend, BitReversedOrder>::new(
            domain,
            evaluations.into_iter().map(SecureField::from).collect(),
        )];

    let fri_prover = FriProver::<CpuBackend, Blake2sMerkleChannel>::commit(
        channel,
        FRI_CONFIG,
        &secure_evaluations,
        &twiddles,
    );
    let proof_of_work = CpuBackend::grind(channel, POW_BITS);
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
            log_size_bound: log_next_pow_of_2,
            evaluations,
        },
    )
}

pub fn verify_proof(proof: Proof) -> bool {
    let channel = &mut Blake2sChannel::default();
    let Ok(mut fri_verifier) = FriVerifier::<Blake2sMerkleChannel>::commit(
        channel,
        FRI_CONFIG,
        proof.proof,
        vec![CirclePolyDegreeBound::new(proof.log_size_bound)],
    ) else {
        return false;
    };
    channel.mix_u64(proof.proof_of_work);
    if channel.trailing_zeros() < POW_BITS {
        return false;
    }
    let queries = fri_verifier.sample_query_positions(channel);
    assert!(queries.keys().len() == 1);
    fri_verifier
        .decommit(vec![proof.evaluations.clone()])
        .is_ok()
}

#[cfg(test)]
mod tests {
    use crate::commit::commit;

    use super::*;

    #[test]
    fn test_generate_proof() {
        let data = include_bytes!("../blob");
        let proof = generate_proof(data);
        assert_ne!(proof.proof.inner_layers.len(), 0);
    }

    #[test]
    fn test_commit_and_generate_proof() {
        let data = include_bytes!("../blob");
        let (commitment, proof) = commit_and_generate_proof(data);
        assert_eq!(commitment, commit(data));
        assert_eq!(proof.proof.first_layer.commitment.0, commitment);
    }
    #[test]
    fn test_verify_proof() {
        let data = include_bytes!("../blob");
        let proof = generate_proof(data);
        assert!(verify_proof(proof));
    }

    #[test]
    fn test_verify_proof_with_invalid_pow() {
        let data = include_bytes!("../blob");
        let mut proof = generate_proof(data);
        proof.proof_of_work += 1;
        assert!(!verify_proof(proof));
    }

    #[test]
    fn test_verify_proof_with_invalid_evaluations() {
        let data = include_bytes!("../blob");
        let mut proof = generate_proof(data);
        proof.evaluations[0] += QM31::from_u32_unchecked(1, 1, 1, 1);
        assert!(!verify_proof(proof));
    }
    #[test]
    fn test_verify_proof_with_invalid_evaluations_order() {
        let data = include_bytes!("../blob");
        let mut proof = generate_proof(data);
        proof.evaluations.reverse();
        assert!(!verify_proof(proof));
    }

    #[test]
    #[should_panic]
    fn test_verify_proof_with_invalid_evaluations_length() {
        let data = include_bytes!("../blob");
        let mut proof = generate_proof(data);
        proof.evaluations.pop();
        assert!(!verify_proof(proof));
    }

    #[test]
    fn test_verify_proof_with_invalid_1_evaluation_unordered() {
        let data = include_bytes!("../blob");
        let mut proof = generate_proof(data);
        proof.evaluations.swap(0, 1);
        assert!(!verify_proof(proof));
    }
}
