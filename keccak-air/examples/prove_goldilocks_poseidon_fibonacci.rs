use std::iter;

use ark_ff::{BigInteger, PrimeField};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{AbstractField, Field, PrimeField64};
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_goldilocks::{DiffusionMatrixGoldilocks, Goldilocks, MdsMatrixGoldilocks};
use p3_keccak_air::{FibonacciAir, FibonacciCols, NUM_FIBONACCI_COLS};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon::Poseidon;
use p3_poseidon2::Poseidon2;
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge, Permutation, PseudoCompressionFunction, TruncatedPermutation};
use p3_uni_stark::{get_log_quotient_degree, prove, verify, StarkConfig, VerificationError};
use p3_util::log2_ceil_usize;
use rand::thread_rng;
use tracing_forest::util::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};
use zkhash::fields::goldilocks::FpGoldiLocks;
use zkhash::poseidon2::poseidon2::Poseidon2 as Poseidon2Ref;
use zkhash::poseidon2::poseidon2_instance_goldilocks::{
    POSEIDON2_GOLDILOCKS_12_PARAMS, POSEIDON2_GOLDILOCKS_8_PARAMS, RC12, RC8,
};

const WIDTH: usize = 8;
const D: u64 = 7;
const ROUNDS_F: usize = 8;
const ROUNDS_P: usize = 22;

fn goldilocks_from_ark_ff(input: FpGoldiLocks) -> Goldilocks {
    let as_bigint = input.into_bigint();
    let mut as_bytes = as_bigint.to_bytes_le();
    as_bytes.resize(8, 0);
    let as_u64 = u64::from_le_bytes(as_bytes[0..8].try_into().unwrap());
    Goldilocks::from_wrapped_u64(as_u64)
}

fn main() -> Result<(), VerificationError> {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .init();

    type Val = Goldilocks;
    type Challenge = BinomialExtensionField<Val, 2>;

    type Perm = Poseidon2<Val, DiffusionMatrixGoldilocks, 8, 7>;
    let round_constants: Vec<[Val; WIDTH]> = RC8
        .iter()
        .map(|vec| {
            vec.iter()
                .cloned()
                .map(goldilocks_from_ark_ff)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        })
        .collect();

    let perm = Perm::new(8, 22, round_constants, DiffusionMatrixGoldilocks);
    let mut state = [
        Val::from_canonical_u64(0),
        Val::from_canonical_u64(0),
        Val::from_canonical_u64(0),
        Val::from_canonical_u64(0),
        Val::from_canonical_u64(0),
        Val::from_canonical_u64(0),
        Val::from_canonical_u64(0),
        Val::from_canonical_u64(0),
    ];
    perm.permute_mut(&mut state);
    dbg!(state);

    type MyHash = PaddingFreeSponge<Perm, 8, 4, 4>;
    let hash = MyHash::new(perm.clone());

    type MyCompress = TruncatedPermutation<Perm, 2, 4, 8>;
    let compress = MyCompress::new(perm.clone());

    type ValMmcs = FieldMerkleTreeMmcs<
        <Val as Field>::Packing,
        <Val as Field>::Packing,
        MyHash,
        MyCompress,
        4,
    >;
    let val_mmcs = ValMmcs::new(hash, compress);

    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    type Dft = Radix2DitParallel;
    let dft = Dft {};

    type Challenger = DuplexChallenger<Val, Perm, 8>;

    // 0..3
    // 3..6
    // 1 1 2
    // 1 2 3
    let trace = RowMajorMatrix {
        values: vec![
            Goldilocks::from_canonical_u64(1u64),
            Goldilocks::from_canonical_u64(1u64),
            Goldilocks::from_canonical_u64(2u64),
            Goldilocks::from_canonical_u64(1u64),
            Goldilocks::from_canonical_u64(2u64),
            Goldilocks::from_canonical_u64(3u64),
        ],
        width: 3,
    };
    let fri_config = FriConfig {
        log_blowup: 1,
        num_queries: 100,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
    dbg!(log2_ceil_usize(trace.height()));
    let pcs = Pcs::new(log2_ceil_usize(trace.height()), dft, val_mmcs, fri_config);

    type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
    let config = MyConfig::new(pcs);

    let mut challenger = Challenger::new(perm.clone());

    let proof = prove::<MyConfig, _>(&config, &FibonacciAir {}, &mut challenger, trace);

    std::fs::write(
        "proof_fibonacci.json",
        serde_json::to_string(&proof).unwrap(),
    )
    .unwrap();

    let mut challenger = Challenger::new(perm);
    verify(&config, &FibonacciAir {}, &mut challenger, &proof).unwrap();
    dbg!(get_log_quotient_degree::<Val, FibonacciAir>(
        &FibonacciAir {}
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn function_name_test() {}
}
