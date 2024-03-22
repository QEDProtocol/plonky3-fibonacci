use std::iter;

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{AbstractField, Field, PrimeField64};
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_goldilocks::{Goldilocks, MdsMatrixGoldilocks};
use p3_keccak_air::{FibonacciAir, FibonacciCols, NUM_FIBONACCI_COLS};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon::Poseidon;
use p3_poseidon2::Poseidon2;
use p3_symmetric::{PaddingFreeSponge, Permutation, TruncatedPermutation};
use p3_uni_stark::{prove, verify, StarkConfig, VerificationError};
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
use ark_ff::BigInteger;

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

    type Perm = Poseidon2<Val, MdsMatrixGoldilocks, 8, 7>;
    let perm = Perm::new(
        4,
        22,
        constants::ROUND_CONSTANTS
            .into_iter()
            .map(|x| {
                x.into_iter()
                    .map(|y| Val::from_canonical_u64(y as u64))
                    .collect()
                    .try_into()
                    .unwrap()
            })
            .collect(),
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
    Ok(())
}

pub mod constants {
    pub const WIDTH: usize = 16;
    pub const DEGREE: usize = 5;
    pub const ROUNDS_F: usize = 8;
    pub const ROUNDS_P: usize = 22;
    pub const ROUNDS: usize = ROUNDS_F + ROUNDS_P;

    pub const MAT_INTERNAL_DIAG_M_1: [u32; WIDTH] = [
        0x0a632d94, 0x6db657b7, 0x56fbdc9e, 0x052b3d8a, 0x33745201, 0x5c03108c, 0x0beba37b,
        0x258c2e8b, 0x12029f39, 0x694909ce, 0x6d231724, 0x21c3b222, 0x3c0904a5, 0x01d6acda,
        0x27705c83, 0x5231c802,
    ];

    pub const ROUND_CONSTANTS: [[u32; WIDTH]; ROUNDS] = [
        [
            96748292, 1951698684, 177396853, 719730562, 640767983, 1390633215, 1716033721,
            1606702601, 1746607367, 1466015491, 1498308946, 831109173, 1029197920, 1969905919,
            83412884, 1911782445,
        ],
        [
            1693593583, 759122502, 1154399525, 1131812921, 1080754908, 53582651, 893583089,
            6411452, 1115338635, 580640471, 1264354339, 842931656, 548879852, 1595288793,
            1562381995, 81826002,
        ],
        [
            262554421, 1563933798, 1440025885, 184445025, 585385439, 1396647410, 1575877922,
            1290587480, 137125468, 765010148, 633675867, 24537442, 560123907, 1895729703,
            541515871, 1783382863,
        ],
        [
            628590563, 1022477421, 1659530405, 245668751, 12194511, 201609705, 286217151, 66943721,
            506306261, 1067433949, 748735911, 1244250808, 606038199, 1169474910, 73007766,
            558938232,
        ],
        [
            1196780786, 1434128522, 747167305, 954807686, 1053214930, 1074411832, 2003528587,
            1570312929, 113576933, 16049344, 1621249812, 1032701597, 351573387, 1827020997,
            888378655, 506925662,
        ],
        [
            36046858, 914260032, 1898863184, 1991566610, 193772436, 1590247392, 99286330,
            502985775, 24413908, 269498914, 1973292656, 891403491, 1845429189, 598730442,
            297276732, 44663898,
        ],
        [
            1492041470, 786445290, 1802048050, 1111591756, 206747992, 762187113, 1991257625,
            927239888, 738050285, 1028870679, 1282466273, 1059053371, 834521354, 138721483,
            1087144882, 1829862410,
        ],
        [
            1864954859, 31630597, 1478942487, 799012923, 496734827, 1507995315, 755421082,
            1361409515, 392099473, 1165187472, 41931879, 7935614, 114353803, 137482145, 1685210312,
            1839717303,
        ],
        [
            883677154, 1074325006, 992175959, 970216228, 1460364169, 1886404479, 1590122901,
            620222276, 466141043, 407687078, 1852516800, 226543855, 979699862, 1163403191,
            1608599874, 1042838527,
        ],
        [
            1765843422, 536205958, 156926519, 1649720295, 1444912244, 1108964957, 384301396,
            201666674, 1662916865, 55629272, 108631393, 1706239958, 140427546, 1626054781,
            992593057, 1431907253,
        ],
        [
            1418914503, 1365856753, 1929449824, 1429155552, 1532376874, 1759208336, 1621094396,
            141133224, 826697382, 1700781391, 1525898403, 652815039, 442484755, 42033470,
            1064289978, 1152335780,
        ],
        [
            1404382774, 186040114, 1462314652, 100675329, 1779573826, 1573808590, 1222428883,
            908929360, 1119462702, 1675039600, 1849567013, 667446787, 753897224, 1896396780,
            1129760413, 1816337955,
        ],
        [
            859661334, 1885578436, 180258337, 308601096, 1585736583, 873516500, 1025033457,
            1035366250, 25646276, 906908602, 1277696101, 772434369, 1793238414, 1505593012,
            654843672, 113854354,
        ],
        [
            1548195514, 364790106, 390914568, 1472049779, 1552596765, 1905886441, 1611959354,
            1639997383, 1410680465, 340857935, 195613559, 139364268, 1434015852, 1764547786,
            55640413, 75369899,
        ],
        [
            104929687, 1459980974, 1831234737, 457139004, 568221707, 98778642, 1553747940,
            778738426, 576325418, 41126132, 700296403, 151213722, 877920014, 546846420, 926528998,
            530203984,
        ],
        [
            178643863, 1301872539, 530414574, 1242280418, 1211740715, 1980406244, 491817402,
            1832532880, 538768466, 50301639, 1352882353, 1449831887, 394746545, 294726285,
            1930169572, 924016661,
        ],
        [
            1619872446, 1209523451, 809116305, 30100013, 641906955, 550981196, 465383811, 87157309,
            93614240, 499042594, 650406041, 213480551, 670242787, 951073977, 1446816067, 339124269,
        ],
        [
            130182653, 742680828, 542600513, 802837101, 1931786340, 31204919, 1709908013,
            925103122, 1627133772, 1374470239, 177883755, 624229761, 209862198, 276092925,
            1820102609, 974546524,
        ],
        [
            1293393192, 221548340, 1188782305, 223782844, 235714646, 296520220, 10135706,
            1265611492, 8872228, 575851471, 1612560780, 1913391015, 1305283056, 578597757,
            188109355, 191192067,
        ],
        [
            1564209905, 140931974, 446421108, 857368568, 1375012945, 1529454825, 306140690,
            842312378, 1246997295, 1011032842, 1915270363, 1218245412, 466048099, 976561834,
            814378556, 13244079,
        ],
        [
            1165280628, 1203983801, 1801474112, 1919627044, 600240215, 773269071, 486685186,
            227516968, 1415023565, 502840102, 199116516, 510217063, 166444818, 1430745893,
            1376516190, 1775891321,
        ],
        [
            1170945922, 1105391877, 261536467, 1401687994, 1022529847, 463180535, 590578957,
            1693070122, 1449787793, 1509644517, 588552318, 65252581, 1683236735, 170064842,
            1650755312, 1643809916,
        ],
        [
            909609977, 1727424722, 1919195219, 161156271, 606677562, 50507667, 907935782, 72353797,
            51998725, 602427891, 1103289512, 246100007, 254855312, 19609159, 1217479, 111611860,
        ],
        [
            53688899, 488834048, 901787194, 349252665, 366091708, 69939011, 111853790, 1181891646,
            1318086382, 521723799, 702443405, 494405064, 1760347557, 618733972, 1672737554,
            1060867760,
        ],
        [
            346535860, 786965546, 997091114, 1035997899, 1210110952, 1018506770, 786202256,
            1479380761, 1536021911, 358993854, 579904113, 1418878879, 1612249888, 199241497,
            31772267, 576898313,
        ],
        [
            1688530738, 1580733335, 430715596, 193004644, 766808308, 615473756, 926857738,
            118674985, 1559012088, 766341588, 1098718697, 1424913749, 211149954, 1108922178,
            1633006641, 1921920263,
        ],
        [
            820046587, 1393386250, 652552654, 218516098, 672377010, 1920315467, 1913164407,
            16260955, 616005899, 384320012, 85788743, 1118558852, 334552276, 207731465, 1772368609,
            566694174,
        ],
        [
            1531664952, 225847443, 1056816357, 95643305, 1425306121, 1299590588, 615850007,
            1863868773, 803582265, 1448710938, 889759878, 1482092434, 1889706578, 1859075947,
            1530411808, 201657663,
        ],
        [
            1105526560, 227810594, 1970403910, 1167649226, 1825360580, 1921630011, 1402085850,
            236687938, 1741815709, 486327260, 1227575720, 1630603458, 968760152, 452777810,
            1982634375, 1756343093,
        ],
        [
            182189574, 583597362, 218463131, 1983609348, 2006408474, 1456716110, 1458697570,
            1593516217, 1963896497, 1102043197, 1659132465, 523504835, 1046028250, 604765413,
            27637326, 1786529155,
        ],
    ];
}
