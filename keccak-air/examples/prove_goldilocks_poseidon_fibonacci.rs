use std::iter;

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{AbstractField, Field, PrimeField64};
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_goldilocks::Goldilocks;
use p3_keccak_air::{FibonacciAir, FibonacciCols, NUM_FIBONACCI_COLS};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_mds::goldilocks::MdsMatrixGoldilocks;
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon::Poseidon;
use p3_symmetric::{PaddingFreeSponge, Permutation, TruncatedPermutation};
use p3_uni_stark::{prove, verify, StarkConfig, VerificationError};
use p3_util::log2_ceil_usize;
use rand::thread_rng;
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

    type Val = Goldilocks;
    type Challenge = BinomialExtensionField<Val, 2>;

    type Perm = Poseidon<Val, MdsMatrixGoldilocks, 12, 7>;
    let perm = Perm::new(
        4,
        22,
        vec![
            // WARNING: The AVX2 Goldilocks specialization relies on all round constants being in
            // 0..0xfffeeac900011537. If these constants are randomly regenerated, there is a ~.6% chance
            // that this condition will no longer hold.
            //
            // WARNING: If these are changed in any way, then all the
            // implementations of Poseidon must be regenerated. See comments
            // in `poseidon_goldilocks.rs`.
            Val::from_canonical_u64(0xb585f766f2144405),
            Val::from_canonical_u64(0x7746a55f43921ad7),
            Val::from_canonical_u64(0xb2fb0d31cee799b4),
            Val::from_canonical_u64(0x0f6760a4803427d7),
            Val::from_canonical_u64(0xe10d666650f4e012),
            Val::from_canonical_u64(0x8cae14cb07d09bf1),
            Val::from_canonical_u64(0xd438539c95f63e9f),
            Val::from_canonical_u64(0xef781c7ce35b4c3d),
            Val::from_canonical_u64(0xcdc4a239b0c44426),
            Val::from_canonical_u64(0x277fa208bf337bff),
            Val::from_canonical_u64(0xe17653a29da578a1),
            Val::from_canonical_u64(0xc54302f225db2c76),
            Val::from_canonical_u64(0x86287821f722c881),
            Val::from_canonical_u64(0x59cd1a8a41c18e55),
            Val::from_canonical_u64(0xc3b919ad495dc574),
            Val::from_canonical_u64(0xa484c4c5ef6a0781),
            Val::from_canonical_u64(0x308bbd23dc5416cc),
            Val::from_canonical_u64(0x6e4a40c18f30c09c),
            Val::from_canonical_u64(0x9a2eedb70d8f8cfa),
            Val::from_canonical_u64(0xe360c6e0ae486f38),
            Val::from_canonical_u64(0xd5c7718fbfc647fb),
            Val::from_canonical_u64(0xc35eae071903ff0b),
            Val::from_canonical_u64(0x849c2656969c4be7),
            Val::from_canonical_u64(0xc0572c8c08cbbbad),
            Val::from_canonical_u64(0xe9fa634a21de0082),
            Val::from_canonical_u64(0xf56f6d48959a600d),
            Val::from_canonical_u64(0xf7d713e806391165),
            Val::from_canonical_u64(0x8297132b32825daf),
            Val::from_canonical_u64(0xad6805e0e30b2c8a),
            Val::from_canonical_u64(0xac51d9f5fcf8535e),
            Val::from_canonical_u64(0x502ad7dc18c2ad87),
            Val::from_canonical_u64(0x57a1550c110b3041),
            Val::from_canonical_u64(0x66bbd30e6ce0e583),
            Val::from_canonical_u64(0x0da2abef589d644e),
            Val::from_canonical_u64(0xf061274fdb150d61),
            Val::from_canonical_u64(0x28b8ec3ae9c29633),
            Val::from_canonical_u64(0x92a756e67e2b9413),
            Val::from_canonical_u64(0x70e741ebfee96586),
            Val::from_canonical_u64(0x019d5ee2af82ec1c),
            Val::from_canonical_u64(0x6f6f2ed772466352),
            Val::from_canonical_u64(0x7cf416cfe7e14ca1),
            Val::from_canonical_u64(0x61df517b86a46439),
            Val::from_canonical_u64(0x85dc499b11d77b75),
            Val::from_canonical_u64(0x4b959b48b9c10733),
            Val::from_canonical_u64(0xe8be3e5da8043e57),
            Val::from_canonical_u64(0xf5c0bc1de6da8699),
            Val::from_canonical_u64(0x40b12cbf09ef74bf),
            Val::from_canonical_u64(0xa637093ecb2ad631),
            Val::from_canonical_u64(0x3cc3f892184df408),
            Val::from_canonical_u64(0x2e479dc157bf31bb),
            Val::from_canonical_u64(0x6f49de07a6234346),
            Val::from_canonical_u64(0x213ce7bede378d7b),
            Val::from_canonical_u64(0x5b0431345d4dea83),
            Val::from_canonical_u64(0xa2de45780344d6a1),
            Val::from_canonical_u64(0x7103aaf94a7bf308),
            Val::from_canonical_u64(0x5326fc0d97279301),
            Val::from_canonical_u64(0xa9ceb74fec024747),
            Val::from_canonical_u64(0x27f8ec88bb21b1a3),
            Val::from_canonical_u64(0xfceb4fda1ded0893),
            Val::from_canonical_u64(0xfac6ff1346a41675),
            Val::from_canonical_u64(0x7131aa45268d7d8c),
            Val::from_canonical_u64(0x9351036095630f9f),
            Val::from_canonical_u64(0xad535b24afc26bfb),
            Val::from_canonical_u64(0x4627f5c6993e44be),
            Val::from_canonical_u64(0x645cf794b8f1cc58),
            Val::from_canonical_u64(0x241c70ed0af61617),
            Val::from_canonical_u64(0xacb8e076647905f1),
            Val::from_canonical_u64(0x3737e9db4c4f474d),
            Val::from_canonical_u64(0xe7ea5e33e75fffb6),
            Val::from_canonical_u64(0x90dee49fc9bfc23a),
            Val::from_canonical_u64(0xd1b1edf76bc09c92),
            Val::from_canonical_u64(0x0b65481ba645c602),
            Val::from_canonical_u64(0x99ad1aab0814283b),
            Val::from_canonical_u64(0x438a7c91d416ca4d),
            Val::from_canonical_u64(0xb60de3bcc5ea751c),
            Val::from_canonical_u64(0xc99cab6aef6f58bc),
            Val::from_canonical_u64(0x69a5ed92a72ee4ff),
            Val::from_canonical_u64(0x5e7b329c1ed4ad71),
            Val::from_canonical_u64(0x5fc0ac0800144885),
            Val::from_canonical_u64(0x32db829239774eca),
            Val::from_canonical_u64(0x0ade699c5830f310),
            Val::from_canonical_u64(0x7cc5583b10415f21),
            Val::from_canonical_u64(0x85df9ed2e166d64f),
            Val::from_canonical_u64(0x6604df4fee32bcb1),
            Val::from_canonical_u64(0xeb84f608da56ef48),
            Val::from_canonical_u64(0xda608834c40e603d),
            Val::from_canonical_u64(0x8f97fe408061f183),
            Val::from_canonical_u64(0xa93f485c96f37b89),
            Val::from_canonical_u64(0x6704e8ee8f18d563),
            Val::from_canonical_u64(0xcee3e9ac1e072119),
            Val::from_canonical_u64(0x510d0e65e2b470c1),
            Val::from_canonical_u64(0xf6323f486b9038f0),
            Val::from_canonical_u64(0x0b508cdeffa5ceef),
            Val::from_canonical_u64(0xf2417089e4fb3cbd),
            Val::from_canonical_u64(0x60e75c2890d15730),
            Val::from_canonical_u64(0xa6217d8bf660f29c),
            Val::from_canonical_u64(0x7159cd30c3ac118e),
            Val::from_canonical_u64(0x839b4e8fafead540),
            Val::from_canonical_u64(0x0d3f3e5e82920adc),
            Val::from_canonical_u64(0x8f7d83bddee7bba8),
            Val::from_canonical_u64(0x780f2243ea071d06),
            Val::from_canonical_u64(0xeb915845f3de1634),
            Val::from_canonical_u64(0xd19e120d26b6f386),
            Val::from_canonical_u64(0x016ee53a7e5fecc6),
            Val::from_canonical_u64(0xcb5fd54e7933e477),
            Val::from_canonical_u64(0xacb8417879fd449f),
            Val::from_canonical_u64(0x9c22190be7f74732),
            Val::from_canonical_u64(0x5d693c1ba3ba3621),
            Val::from_canonical_u64(0xdcef0797c2b69ec7),
            Val::from_canonical_u64(0x3d639263da827b13),
            Val::from_canonical_u64(0xe273fd971bc8d0e7),
            Val::from_canonical_u64(0x418f02702d227ed5),
            Val::from_canonical_u64(0x8c25fda3b503038c),
            Val::from_canonical_u64(0x2cbaed4daec8c07c),
            Val::from_canonical_u64(0x5f58e6afcdd6ddc2),
            Val::from_canonical_u64(0x284650ac5e1b0eba),
            Val::from_canonical_u64(0x635b337ee819dab5),
            Val::from_canonical_u64(0x9f9a036ed4f2d49f),
            Val::from_canonical_u64(0xb93e260cae5c170e),
            Val::from_canonical_u64(0xb0a7eae879ddb76d),
            Val::from_canonical_u64(0xd0762cbc8ca6570c),
            Val::from_canonical_u64(0x34c6efb812b04bf5),
            Val::from_canonical_u64(0x40bf0ab5fa14c112),
            Val::from_canonical_u64(0xb6b570fc7c5740d3),
            Val::from_canonical_u64(0x5a27b9002de33454),
            Val::from_canonical_u64(0xb1a5b165b6d2b2d2),
            Val::from_canonical_u64(0x8722e0ace9d1be22),
            Val::from_canonical_u64(0x788ee3b37e5680fb),
            Val::from_canonical_u64(0x14a726661551e284),
            Val::from_canonical_u64(0x98b7672f9ef3b419),
            Val::from_canonical_u64(0xbb93ae776bb30e3a),
            Val::from_canonical_u64(0x28fd3b046380f850),
            Val::from_canonical_u64(0x30a4680593258387),
            Val::from_canonical_u64(0x337dc00c61bd9ce1),
            Val::from_canonical_u64(0xd5eca244c7a4ff1d),
            Val::from_canonical_u64(0x7762638264d279bd),
            Val::from_canonical_u64(0xc1e434bedeefd767),
            Val::from_canonical_u64(0x0299351a53b8ec22),
            Val::from_canonical_u64(0xb2d456e4ad251b80),
            Val::from_canonical_u64(0x3e9ed1fda49cea0b),
            Val::from_canonical_u64(0x2972a92ba450bed8),
            Val::from_canonical_u64(0x20216dd77be493de),
            Val::from_canonical_u64(0xadffe8cf28449ec6),
            Val::from_canonical_u64(0x1c4dbb1c4c27d243),
            Val::from_canonical_u64(0x15a16a8a8322d458),
            Val::from_canonical_u64(0x388a128b7fd9a609),
            Val::from_canonical_u64(0x2300e5d6baedf0fb),
            Val::from_canonical_u64(0x2f63aa8647e15104),
            Val::from_canonical_u64(0xf1c36ce86ecec269),
            Val::from_canonical_u64(0x27181125183970c9),
            Val::from_canonical_u64(0xe584029370dca96d),
            Val::from_canonical_u64(0x4d9bbc3e02f1cfb2),
            Val::from_canonical_u64(0xea35bc29692af6f8),
            Val::from_canonical_u64(0x18e21b4beabb4137),
            Val::from_canonical_u64(0x1e3b9fc625b554f4),
            Val::from_canonical_u64(0x25d64362697828fd),
            Val::from_canonical_u64(0x5a3f1bb1c53a9645),
            Val::from_canonical_u64(0xdb7f023869fb8d38),
            Val::from_canonical_u64(0xb462065911d4e1fc),
            Val::from_canonical_u64(0x49c24ae4437d8030),
            Val::from_canonical_u64(0xd793862c112b0566),
            Val::from_canonical_u64(0xaadd1106730d8feb),
            Val::from_canonical_u64(0xc43b6e0e97b0d568),
            Val::from_canonical_u64(0xe29024c18ee6fca2),
            Val::from_canonical_u64(0x5e50c27535b88c66),
            Val::from_canonical_u64(0x10383f20a4ff9a87),
            Val::from_canonical_u64(0x38e8ee9d71a45af8),
            Val::from_canonical_u64(0xdd5118375bf1a9b9),
            Val::from_canonical_u64(0x775005982d74d7f7),
            Val::from_canonical_u64(0x86ab99b4dde6c8b0),
            Val::from_canonical_u64(0xb1204f603f51c080),
            Val::from_canonical_u64(0xef61ac8470250ecf),
            Val::from_canonical_u64(0x1bbcd90f132c603f),
            Val::from_canonical_u64(0x0cd1dabd964db557),
            Val::from_canonical_u64(0x11a3ae5beb9d1ec9),
            Val::from_canonical_u64(0xf755bfeea585d11d),
            Val::from_canonical_u64(0xa3b83250268ea4d7),
            Val::from_canonical_u64(0x516306f4927c93af),
            Val::from_canonical_u64(0xddb4ac49c9efa1da),
            Val::from_canonical_u64(0x64bb6dec369d4418),
            Val::from_canonical_u64(0xf9cc95c22b4c1fcc),
            Val::from_canonical_u64(0x08d37f755f4ae9f6),
            Val::from_canonical_u64(0xeec49b613478675b),
            Val::from_canonical_u64(0xf143933aed25e0b0),
            Val::from_canonical_u64(0xe4c5dd8255dfc622),
            Val::from_canonical_u64(0xe7ad7756f193198e),
            Val::from_canonical_u64(0x92c2318b87fff9cb),
            Val::from_canonical_u64(0x739c25f8fd73596d),
            Val::from_canonical_u64(0x5636cac9f16dfed0),
            Val::from_canonical_u64(0xdd8f909a938e0172),
            Val::from_canonical_u64(0xc6401fe115063f5b),
            Val::from_canonical_u64(0x8ad97b33f1ac1455),
            Val::from_canonical_u64(0x0c49366bb25e8513),
            Val::from_canonical_u64(0x0784d3d2f1698309),
            Val::from_canonical_u64(0x530fb67ea1809a81),
            Val::from_canonical_u64(0x410492299bb01f49),
            Val::from_canonical_u64(0x139542347424b9ac),
            Val::from_canonical_u64(0x9cb0bd5ea1a1115e),
            Val::from_canonical_u64(0x02e3f615c38f49a1),
            Val::from_canonical_u64(0x985d4f4a9c5291ef),
            Val::from_canonical_u64(0x775b9feafdcd26e7),
            Val::from_canonical_u64(0x304265a6384f0f2d),
            Val::from_canonical_u64(0x593664c39773012c),
            Val::from_canonical_u64(0x4f0a2e5fb028f2ce),
            Val::from_canonical_u64(0xdd611f1000c17442),
            Val::from_canonical_u64(0xd8185f9adfea4fd0),
            Val::from_canonical_u64(0xef87139ca9a3ab1e),
            Val::from_canonical_u64(0x3ba71336c34ee133),
            Val::from_canonical_u64(0x7d3a455d56b70238),
            Val::from_canonical_u64(0x660d32e130182684),
            Val::from_canonical_u64(0x297a863f48cd1f43),
            Val::from_canonical_u64(0x90e0a736a751ebb7),
            Val::from_canonical_u64(0x549f80ce550c4fd3),
            Val::from_canonical_u64(0x0f73b2922f38bd64),
            Val::from_canonical_u64(0x16bf1f73fb7a9c3f),
            Val::from_canonical_u64(0x6d1f5a59005bec17),
            Val::from_canonical_u64(0x02ff876fa5ef97c4),
            Val::from_canonical_u64(0xc5cb72a2a51159b0),
            Val::from_canonical_u64(0x8470f39d2d5c900e),
            Val::from_canonical_u64(0x25abb3f1d39fcb76),
            Val::from_canonical_u64(0x23eb8cc9b372442f),
            Val::from_canonical_u64(0xd687ba55c64f6364),
            Val::from_canonical_u64(0xda8d9e90fd8ff158),
            Val::from_canonical_u64(0xe3cbdc7d2fe45ea7),
            Val::from_canonical_u64(0xb9a8c9b3aee52297),
            Val::from_canonical_u64(0xc0d28a5c10960bd3),
            Val::from_canonical_u64(0x45d7ac9b68f71a34),
            Val::from_canonical_u64(0xeeb76e397069e804),
            Val::from_canonical_u64(0x3d06c8bd1514e2d9),
            Val::from_canonical_u64(0x9c9c98207cb10767),
            Val::from_canonical_u64(0x65700b51aedfb5ef),
            Val::from_canonical_u64(0x911f451539869408),
            Val::from_canonical_u64(0x7ae6849fbc3a0ec6),
            Val::from_canonical_u64(0x3bb340eba06afe7e),
            Val::from_canonical_u64(0xb46e9d8b682ea65e),
            Val::from_canonical_u64(0x8dcf22f9a3b34356),
            Val::from_canonical_u64(0x77bdaeda586257a7),
            Val::from_canonical_u64(0xf19e400a5104d20d),
            Val::from_canonical_u64(0xc368a348e46d950f),
            Val::from_canonical_u64(0x9ef1cd60e679f284),
            Val::from_canonical_u64(0xe89cd854d5d01d33),
            Val::from_canonical_u64(0x5cd377dc8bb882a2),
            Val::from_canonical_u64(0xa7b0fb7883eee860),
            Val::from_canonical_u64(0x7684403ec392950d),
            Val::from_canonical_u64(0x5fa3f06f4fed3b52),
            Val::from_canonical_u64(0x8df57ac11bc04831),
            Val::from_canonical_u64(0x2db01efa1e1e1897),
            Val::from_canonical_u64(0x54846de4aadb9ca2),
            Val::from_canonical_u64(0xba6745385893c784),
            Val::from_canonical_u64(0x541d496344d2c75b),
            Val::from_canonical_u64(0xe909678474e687fe),
            Val::from_canonical_u64(0xdfe89923f6c9c2ff),
            Val::from_canonical_u64(0xece5a71e0cfedc75),
            Val::from_canonical_u64(0x5ff98fd5d51fe610),
            Val::from_canonical_u64(0x83e8941918964615),
            Val::from_canonical_u64(0x5922040b47f150c1),
            Val::from_canonical_u64(0xf97d750e3dd94521),
            Val::from_canonical_u64(0x5080d4c2b86f56d7),
            Val::from_canonical_u64(0xa7de115b56c78d70),
            Val::from_canonical_u64(0x6a9242ac87538194),
            Val::from_canonical_u64(0xf7856ef7f9173e44),
            Val::from_canonical_u64(0x2265fc92feb0dc09),
            Val::from_canonical_u64(0x17dfc8e4f7ba8a57),
            Val::from_canonical_u64(0x9001a64209f21db8),
            Val::from_canonical_u64(0x90004c1371b893c5),
            Val::from_canonical_u64(0xb932b7cf752e5545),
            Val::from_canonical_u64(0xa0b1df81b6fe59fc),
            Val::from_canonical_u64(0x8ef1dd26770af2c2),
            Val::from_canonical_u64(0x0541a4f9cfbeed35),
            Val::from_canonical_u64(0x9e61106178bfc530),
            Val::from_canonical_u64(0xb3767e80935d8af2),
            Val::from_canonical_u64(0x0098d5782065af06),
            Val::from_canonical_u64(0x31d191cd5c1466c7),
            Val::from_canonical_u64(0x410fefafa319ac9d),
            Val::from_canonical_u64(0xbdf8f242e316c4ab),
            Val::from_canonical_u64(0x9e8cd55b57637ed0),
            Val::from_canonical_u64(0xde122bebe9a39368),
            Val::from_canonical_u64(0x4d001fd58f002526),
            Val::from_canonical_u64(0xca6637000eb4a9f8),
            Val::from_canonical_u64(0x2f2339d624f91f78),
            Val::from_canonical_u64(0x6d1a7918c80df518),
            Val::from_canonical_u64(0xdf9a4939342308e9),
            Val::from_canonical_u64(0xebc2151ee6c8398c),
            Val::from_canonical_u64(0x03cc2ba8a1116515),
            Val::from_canonical_u64(0xd341d037e840cf83),
            Val::from_canonical_u64(0x387cb5d25af4afcc),
            Val::from_canonical_u64(0xbba2515f22909e87),
            Val::from_canonical_u64(0x7248fe7705f38e47),
            Val::from_canonical_u64(0x4d61e56a525d225a),
            Val::from_canonical_u64(0x262e963c8da05d3d),
            Val::from_canonical_u64(0x59e89b094d220ec2),
            Val::from_canonical_u64(0x055d5b52b78b9c5e),
            Val::from_canonical_u64(0x82b27eb33514ef99),
            Val::from_canonical_u64(0xd30094ca96b7ce7b),
            Val::from_canonical_u64(0xcf5cb381cd0a1535),
            Val::from_canonical_u64(0xfeed4db6919e5a7c),
            Val::from_canonical_u64(0x41703f53753be59f),
            Val::from_canonical_u64(0x5eeea940fcde8b6f),
            Val::from_canonical_u64(0x4cd1f1b175100206),
            Val::from_canonical_u64(0x4a20358574454ec0),
            Val::from_canonical_u64(0x1478d361dbbf9fac),
            Val::from_canonical_u64(0x6f02dc07d141875c),
            Val::from_canonical_u64(0x296a202ed8e556a2),
            Val::from_canonical_u64(0x2afd67999bf32ee5),
            Val::from_canonical_u64(0x7acfd96efa95491d),
            Val::from_canonical_u64(0x6798ba0c0abb2c6d),
            Val::from_canonical_u64(0x34c6f57b26c92122),
            Val::from_canonical_u64(0x5736e1bad206b5de),
            Val::from_canonical_u64(0x20057d2a0056521b),
            Val::from_canonical_u64(0x3dea5bd5d0578bd7),
            Val::from_canonical_u64(0x16e50d897d4634ac),
            Val::from_canonical_u64(0x29bff3ecb9b7a6e3),
            Val::from_canonical_u64(0x475cd3205a3bdcde),
            Val::from_canonical_u64(0x18a42105c31b7e88),
            Val::from_canonical_u64(0x023e7414af663068),
            Val::from_canonical_u64(0x15147108121967d7),
            Val::from_canonical_u64(0xe4a3dff1d7d6fef9),
            Val::from_canonical_u64(0x01a8d1a588085737),
            Val::from_canonical_u64(0x11b4c74eda62beef),
            Val::from_canonical_u64(0xe587cc0d69a73346),
            Val::from_canonical_u64(0x1ff7327017aa2a6e),
            Val::from_canonical_u64(0x594e29c42473d06b),
            Val::from_canonical_u64(0xf6f31db1899b12d5),
            Val::from_canonical_u64(0xc02ac5e47312d3ca),
            Val::from_canonical_u64(0xe70201e960cb78b8),
            Val::from_canonical_u64(0x6f90ff3b6a65f108),
            Val::from_canonical_u64(0x42747a7245e7fa84),
            Val::from_canonical_u64(0xd1f507e43ab749b2),
            Val::from_canonical_u64(0x1c86d265f15750cd),
            Val::from_canonical_u64(0x3996ce73dd832c1c),
            Val::from_canonical_u64(0x8e7fba02983224bd),
            Val::from_canonical_u64(0xba0dec7103255dd4),
            Val::from_canonical_u64(0x9e9cbd781628fc5b),
            Val::from_canonical_u64(0xdae8645996edd6a5),
            Val::from_canonical_u64(0xdebe0853b1a1d378),
            Val::from_canonical_u64(0xa49229d24d014343),
            Val::from_canonical_u64(0x7be5b9ffda905e1c),
            Val::from_canonical_u64(0xa3c95eaec244aa30),
            Val::from_canonical_u64(0x0230bca8f4df0544),
            Val::from_canonical_u64(0x4135c2bebfe148c6),
            Val::from_canonical_u64(0x166fc0cc438a3c72),
            Val::from_canonical_u64(0x3762b59a8ae83efa),
            Val::from_canonical_u64(0xe8928a4c89114750),
            Val::from_canonical_u64(0x2a440b51a4945ee5),
            Val::from_canonical_u64(0x80cefd2b7d99ff83),
            Val::from_canonical_u64(0xbb9879c6e61fd62a),
            Val::from_canonical_u64(0x6e7c8f1a84265034),
            Val::from_canonical_u64(0x164bb2de1bbeddc8),
            Val::from_canonical_u64(0xf3c12fe54d5c653b),
            Val::from_canonical_u64(0x40b9e922ed9771e2),
            Val::from_canonical_u64(0x551f5b0fbe7b1840),
            Val::from_canonical_u64(0x25032aa7c4cb1811),
            Val::from_canonical_u64(0xaaed34074b164346),
            Val::from_canonical_u64(0x8ffd96bbf9c9c81d),
            Val::from_canonical_u64(0x70fc91eb5937085c),
            Val::from_canonical_u64(0x7f795e2a5f915440),
            Val::from_canonical_u64(0x4543d9df5476d3cb),
            Val::from_canonical_u64(0xf172d73e004fc90d),
            Val::from_canonical_u64(0xdfd1c4febcc81238),
            Val::from_canonical_u64(0xbc8dfb627fe558fc),
        ],
        MdsMatrixGoldilocks,
    );
    let mut state = [
        Val::from_canonical_u64(0),
        Val::from_canonical_u64(0),
        Val::from_canonical_u64(0),
        Val::from_canonical_u64(0),
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
    //     12169086110346941909,
    //     1310979608973455208,
    //     6988684882188540706,
    //     7425116217372023609,
    //     4736910505179476847,
    //     17131737408186026035,
    //     11445487377210020291,
    //     5437599147293341628,
    // ]
    // 0x29176100
    // 0xeaa962bd
    // 0xc1fe6c65
    // 0x4d6a3c13
    // 0x0e96a4d1
    // 0x168b3384
    // 0x8b897dc5
    // 0x02820133

    // type MyHash = PaddingFreeSponge<Perm, 8, 4, 4>;
    // let hash = MyHash::new(perm.clone());
    //
    // type MyCompress = TruncatedPermutation<Perm, 2, 4, 8>;
    // let compress = MyCompress::new(perm.clone());
    //
    // type ValMmcs = FieldMerkleTreeMmcs<
    //     <Val as Field>::Packing,
    //     <Val as Field>::Packing,
    //     MyHash,
    //     MyCompress,
    //     4,
    // >;
    // let val_mmcs = ValMmcs::new(hash, compress);
    //
    // type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    // let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    //
    // type Dft = Radix2DitParallel;
    // let dft = Dft {};
    //
    // type Challenger = DuplexChallenger<Val, Perm, 8>;
    //
    // // 0..3
    // // 3..6
    // let trace = RowMajorMatrix {
    //     values: vec![
    //         Goldilocks::from_canonical_u64(1u64),
    //         Goldilocks::from_canonical_u64(1u64),
    //         Goldilocks::from_canonical_u64(2u64),
    //         Goldilocks::from_canonical_u64(1u64),
    //         Goldilocks::from_canonical_u64(2u64),
    //         Goldilocks::from_canonical_u64(3u64),
    //     ],
    //     width: 3,
    // };
    // let fri_config = FriConfig {
    //     log_blowup: 1,
    //     num_queries: 100,
    //     proof_of_work_bits: 16,
    //     mmcs: challenge_mmcs,
    // };
    // type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
    // let pcs = Pcs::new(log2_ceil_usize(trace.height()), dft, val_mmcs, fri_config);
    //
    // type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
    // let config = MyConfig::new(pcs);
    //
    // let mut challenger = Challenger::new(perm.clone());
    //
    // let proof = prove::<MyConfig, _>(&config, &FibonacciAir {}, &mut challenger, trace);
    //
    // std::fs::write(
    //     "proof_fibonacci.json",
    //     serde_json::to_string(&proof).unwrap(),
    // )
    // .unwrap();
    //
    // let mut challenger = Challenger::new(perm);
    // verify(&config, &FibonacciAir {}, &mut challenger, &proof)
    Ok(())
}
