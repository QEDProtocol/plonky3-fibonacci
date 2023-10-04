use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_dft::Radix2DitParallel;
use p3_fri::{FriBasedPcs, FriConfigImpl, FriLdt};
use p3_keccak::Keccak256Hash;
use p3_keccak_air::{generate_trace_rows, KeccakAir};
use p3_ldt::QuotientMmcs;
use p3_mds::coset_mds::CosetMds;
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::{DiffusionMatrixBabybear, Poseidon2};
use p3_symmetric::compression::CompressionFunctionFromHasher;
use p3_symmetric::hasher::SerializingHasher32;
use p3_uni_stark::{prove, verify, StarkConfigImpl, VerificationError};
use rand::{random, thread_rng};
use tracing_forest::util::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

fn main() -> Result<(), VerificationError> {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .init();

    type Val = BabyBear;
    type Domain = Val;
    type Challenge = Val; // TODO

    type MyMds = CosetMds<Val, 16>;
    let mds = MyMds::default();

    type Perm = Poseidon2<Val, MyMds, DiffusionMatrixBabybear, 16, 5>;
    let perm = Perm::new_from_rng(8, 22, mds, DiffusionMatrixBabybear, &mut thread_rng());

    // type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
    // let hash = MyHash::new(perm.clone());
    // type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
    // let compress = MyCompress::new(perm.clone());
    // type MyMmcs = FieldMerkleTreeMmcs<<Val as Field>::Packing, MyHash, MyCompress, 8>;
    // let mmcs = MyMmcs::new(hash, compress);

    type MyHash = SerializingHasher32<Val, Keccak256Hash>;
    let hash = MyHash::new(Keccak256Hash {});
    type MyCompress = CompressionFunctionFromHasher<Val, MyHash, 2, 8>;
    let compress = MyCompress::new(hash);
    type MyMmcs = FieldMerkleTreeMmcs<Val, MyHash, MyCompress, 8>;
    let mmcs = MyMmcs::new(hash, compress);

    type Dft = Radix2DitParallel;
    let dft = Dft {};

    type Challenger = DuplexChallenger<Val, Perm, 16>;

    type Quotient = QuotientMmcs<Domain, Challenge, MyMmcs>;
    type MyFriConfig = FriConfigImpl<Val, Domain, Challenge, Quotient, MyMmcs, Challenger>;
    let fri_config = MyFriConfig::new(40, mmcs.clone());
    let ldt = FriLdt { config: fri_config };

    type Pcs = FriBasedPcs<MyFriConfig, MyMmcs, Dft, Challenger>;
    type MyConfig = StarkConfigImpl<Val, Domain, Challenge, Pcs, Dft, Challenger>;

    let num_hashes = 340;
    let inputs = (0..num_hashes).map(|_| random()).collect::<Vec<_>>();
    let trace = generate_trace_rows::<Val>(inputs);
    let pcs = Pcs::new(dft, 1, mmcs, ldt);
    let config = StarkConfigImpl::new(pcs, Dft {});
    let mut challenger = Challenger::new(perm.clone());
    let proof = prove::<MyConfig, _>(&config, &KeccakAir {}, &mut challenger, trace);

    let mut challenger = Challenger::new(perm);
    verify(&config, &KeccakAir {}, &mut challenger, &proof)
}