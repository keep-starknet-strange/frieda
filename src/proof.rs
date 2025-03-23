use stwo_prover::core::{
    backend::CpuBackend, channel::Blake2sChannel, circle::Coset, fields::{m31::BaseField, qm31::SecureField}, fri::{CirclePolyDegreeBound, FriConfig, FriProof, FriProver, FriVerifier}, pcs::{CommitmentSchemeProof, CommitmentSchemeProver, PcsConfig}, poly::{
        circle::{CanonicCoset, CircleDomain, CircleEvaluation, CirclePoly, PolyOps, SecureEvaluation},
        BitReversedOrder,
    }, vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher}
};

use crate::{commit::Commitment, utils};

pub const FRI_CONFIG: FriConfig = FriConfig {
    log_blowup_factor: 4,
    log_last_layer_degree_bound: 0,
    n_queries: 20,
};
pub const PCS_CONFIG: PcsConfig = PcsConfig {
    pow_bits: 20,
    fri_config: FRI_CONFIG
};

pub fn generate_proof(data: &[u8]) -> CommitmentSchemeProof<Blake2sMerkleHasher>{
    let mut coefficients = utils::bytes_to_felt_le(data);
           let twiddles = CpuBackend::precompute_twiddles(
                CanonicCoset::new(coefficients.len() as u32 + 1 + PCS_CONFIG.fri_config.log_blowup_factor)
                    .circle_domain()
                    .half_coset,
            );

    let prover = CommitmentSchemeProver::new(PCS_CONFIG, &twiddles);
        // Draw OODS point.
        let oods_point = CirclePoint::<SecureField>::get_random_point(channel);

        // Get mask sample points relative to oods point.
        let mut sample_points = component_provers.components().mask_points(oods_point);
        sample_points.push(vec![vec![oods_point]]);
    
    // TODO: check prover.prove_values();
}

pub fn commit_and_generate_proof(data: &[u8]) -> (Commitment, FriProof<Blake2sMerkleHasher>) {
    // Parse bytes to field elements.
    let mut coefficients = utils::bytes_to_felt_le(data);
    let log_blowup_factor = 4;
    // The polynomial should have 2**n coefficients.
    let next_power_of_2 = 1 << (coefficients.len() as f64).log2().ceil() as u32;
    // Pad with 0s
    coefficients.resize(next_power_of_2, BaseField::from_u32_unchecked(0));
    let polynomial = CirclePoly::<CpuBackend>::new(coefficients.clone());
    let coset = Coset::half_odds(polynomial.log_size() + log_blowup_factor - 1);
    let domain = CircleDomain::new(coset);
    let twiddles = CpuBackend::precompute_twiddles(coset);
    let evaluations: CircleEvaluation<CpuBackend, BaseField, BitReversedOrder> =
        polynomial.evaluate_with_twiddles(domain, &twiddles);
    let secure_evaluations: SecureEvaluation<CpuBackend, BitReversedOrder> =
        SecureEvaluation::<CpuBackend, BitReversedOrder>::new(
            domain,
            evaluations.into_iter().map(SecureField::from).collect(),
        );

    // 0 is the degree of the polynomial of the last layer (the polynomial is constant)
    // the polynomial is expanded by 2 ** log_blowup_factor
    // 20 is the number of queries

    let (proof, _queries) = FriProver::<CpuBackend, Blake2sMerkleChannel>::commit(
        &mut Blake2sChannel::default(),
        FRI_CONFIG,
        &[secure_evaluations],
        &twiddles,
    )
    .decommit(&mut Blake2sChannel::default());
    (proof.first_layer.commitment.0, proof)
}

pub fn verify_fri_proof(proof: FriProof<Blake2sMerkleHasher>, evaluations: Vec<SecureField>) -> bool {
    let Ok(mut verifier) = FriVerifier::<Blake2sMerkleChannel>::commit(
        &mut Blake2sChannel::default(),
        FRI_CONFIG,
        proof,
        vec![CirclePolyDegreeBound::new(1)],
    ) else {
        return false;
    };
    let queries = verifier.sample_query_positions(&mut Blake2sChannel::default());
    assert!(queries.keys().len() == 1);
    verifier.decommit(first_layer_query_evals)
    true
}

#[cfg(test)]
mod tests {
    use crate::commit::commit;

    use super::*;

    #[test]
    fn test_generate_proof() {
        let data = include_bytes!("../blob");
        let commitment = commit(data);
        let proof = generate_proof(data);
        assert_eq!(proof.first_layer.commitment.0, commitment);
    }

    #[test]
    fn test_commit_and_generate_proof() {
        let data = include_bytes!("../blob");
        let (commitment, proof) = commit_and_generate_proof(data);
        assert_eq!(commitment, commit(data));
        assert_eq!(proof.first_layer.commitment.0, commitment);
    }
}
