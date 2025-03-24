use stwo_prover::core::{
    backend::CpuBackend,
    channel::{Blake2sChannel, Channel},
    circle::Coset,
    fields::{m31::BaseField, qm31::SecureField},
    fri::{FriConfig, FriProof, FriProver},
    poly::{
        circle::{CircleDomain, CircleEvaluation, CirclePoly, PolyOps, SecureEvaluation},
        BitReversedOrder,
    },
    proof_of_work::GrindOps,
    vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher},
};

use crate::{commit::Commitment, utils};

pub const FRI_CONFIG: FriConfig = FriConfig {
    log_blowup_factor: 4,
    log_last_layer_degree_bound: 0,
    n_queries: 20,
};
pub const POW_BITS: u32 = 20;

pub fn generate_proof(data: &[u8]) -> FriProof<Blake2sMerkleHasher> {
    commit_and_generate_proof(data).1
}

pub fn commit_and_generate_proof(data: &[u8]) -> (Commitment, FriProof<Blake2sMerkleHasher>) {
    // Parse bytes to field elements.
    let mut coefficients = utils::bytes_to_felt_le(data);
    let channel = &mut Blake2sChannel::default();
    // The polynomial should have 2**n coefficients.
    let next_power_of_2 = 1 << (coefficients.len() as f64).log2().ceil() as u32;
    // Pad with 0s
    coefficients.resize(next_power_of_2, BaseField::from_u32_unchecked(0));
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
    let (proof, _queries) = fri_prover.decommit(channel);
    (proof.first_layer.commitment.0, proof)
}

#[cfg(test)]
mod tests {
    use crate::commit::commit;

    use super::*;

    #[test]
    fn test_generate_proof() {
        let data = include_bytes!("../blob");
        let proof = generate_proof(data);
        assert_ne!(proof.inner_layers.len(), 0);
    }

    #[test]
    fn test_commit_and_generate_proof() {
        let data = include_bytes!("../blob");
        let (commitment, proof) = commit_and_generate_proof(data);
        assert_eq!(commitment, commit(data));
        assert_eq!(proof.first_layer.commitment.0, commitment);
    }
}
