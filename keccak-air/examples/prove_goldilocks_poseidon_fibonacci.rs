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

    type Perm = Poseidon<Val, MdsMatrixGoldilocks, 8, 7>;
    let perm = Perm::new(
        4,
        22,
        vec![
            Val::from_canonical_u64(13080132714287613952),
            Val::from_canonical_u64(8594738767457295360),
            Val::from_canonical_u64(12896916465481390080),
            Val::from_canonical_u64(1109962092811921408),
            Val::from_canonical_u64(16216730422861946880),
            Val::from_canonical_u64(10137062673499592704),
            Val::from_canonical_u64(15292064466732466176),
            Val::from_canonical_u64(17255573294985990144),
            Val::from_canonical_u64(9667108687426275328),
            Val::from_canonical_u64(6470857420712284160),
            Val::from_canonical_u64(14103331940138338304),
            Val::from_canonical_u64(11854816473550292992),
            Val::from_canonical_u64(3498097497301325312),
            Val::from_canonical_u64(7947235692523864064),
            Val::from_canonical_u64(11110078701231902720),
            Val::from_canonical_u64(16384314112672821248),
            Val::from_canonical_u64(16859897325061799936),
            Val::from_canonical_u64(17685474420222222336),
            Val::from_canonical_u64(17858764734618734592),
            Val::from_canonical_u64(9410011022665867264),
            Val::from_canonical_u64(12495243629579415552),
            Val::from_canonical_u64(12416945298171514880),
            Val::from_canonical_u64(5776666812364270592),
            Val::from_canonical_u64(6314421662864060416),
            Val::from_canonical_u64(10567510598607411200),
            Val::from_canonical_u64(8135543733717918720),
            Val::from_canonical_u64(116353493081713696),
            Val::from_canonical_u64(8029688163494945792),
            Val::from_canonical_u64(9003846637224807424),
            Val::from_canonical_u64(7052445132467233792),
            Val::from_canonical_u64(9645665432288851968),
            Val::from_canonical_u64(5446430061030868992),
            Val::from_canonical_u64(4378616569090929664),
            Val::from_canonical_u64(3334807502817538560),
            Val::from_canonical_u64(8019184735943345152),
            Val::from_canonical_u64(2395043908812246528),
            Val::from_canonical_u64(6558421058331732992),
            Val::from_canonical_u64(11735894060727326720),
            Val::from_canonical_u64(8143540538889204736),
            Val::from_canonical_u64(5991753489563751424),
            Val::from_canonical_u64(8156487614120950784),
            Val::from_canonical_u64(10615269510047010816),
            Val::from_canonical_u64(12489426404754221056),
            Val::from_canonical_u64(5055279340069995520),
            Val::from_canonical_u64(7231927319780248576),
            Val::from_canonical_u64(2602078848106763776),
            Val::from_canonical_u64(12445944369334781952),
            Val::from_canonical_u64(3978905923892496384),
            Val::from_canonical_u64(11073536380651186176),
            Val::from_canonical_u64(4866839313097608192),
            Val::from_canonical_u64(13118391689513957376),
            Val::from_canonical_u64(14527674973762312192),
            Val::from_canonical_u64(7612751959265567744),
            Val::from_canonical_u64(6808090907814177792),
            Val::from_canonical_u64(6899703779492644864),
            Val::from_canonical_u64(3664666286336986624),
            Val::from_canonical_u64(16970959813722173440),
            Val::from_canonical_u64(15735726858241466368),
            Val::from_canonical_u64(10347018221892268032),
            Val::from_canonical_u64(12195545878449321984),
            Val::from_canonical_u64(7423314197114049536),
            Val::from_canonical_u64(14908016116973903872),
            Val::from_canonical_u64(5840340122527363072),
            Val::from_canonical_u64(17740311462440613888),
            Val::from_canonical_u64(8167785008538062848),
            Val::from_canonical_u64(9483259819397404672),
            Val::from_canonical_u64(954550221664291584),
            Val::from_canonical_u64(10339565171024312320),
            Val::from_canonical_u64(8651171084286499840),
            Val::from_canonical_u64(16974445528003516416),
            Val::from_canonical_u64(15104530047940620288),
            Val::from_canonical_u64(103271880867179712),
            Val::from_canonical_u64(15919951556166197248),
            Val::from_canonical_u64(4423540216573361152),
            Val::from_canonical_u64(16317664700341473280),
            Val::from_canonical_u64(4723997214951768064),
            Val::from_canonical_u64(10098756619006574592),
            Val::from_canonical_u64(3223149401237667840),
            Val::from_canonical_u64(6870494874300767232),
            Val::from_canonical_u64(2902095711130291712),
            Val::from_canonical_u64(15021242795466053632),
            Val::from_canonical_u64(3802990509227527168),
            Val::from_canonical_u64(4665459515680145408),
            Val::from_canonical_u64(13165553315407675392),
            Val::from_canonical_u64(6496364397926233088),
            Val::from_canonical_u64(12800832566287577088),
            Val::from_canonical_u64(9737592377590267904),
            Val::from_canonical_u64(8687131091302514688),
            Val::from_canonical_u64(3505040783153923072),
            Val::from_canonical_u64(3710332827435113472),
            Val::from_canonical_u64(15414874040873320448),
            Val::from_canonical_u64(8602547649919481856),
            Val::from_canonical_u64(13971349938398812160),
            Val::from_canonical_u64(187239246702636064),
            Val::from_canonical_u64(12886019973971253248),
            Val::from_canonical_u64(4512274763990493696),
            Val::from_canonical_u64(1558644089185031168),
            Val::from_canonical_u64(4074089203264759296),
            Val::from_canonical_u64(2522268501749395456),
            Val::from_canonical_u64(3414760436185256448),
            Val::from_canonical_u64(17420887529146466304),
            Val::from_canonical_u64(2817020417938124800),
            Val::from_canonical_u64(16538346563888261120),
            Val::from_canonical_u64(5592270336833998848),
            Val::from_canonical_u64(6502946837278398464),
            Val::from_canonical_u64(15816362857667989504),
            Val::from_canonical_u64(12997958454165692416),
            Val::from_canonical_u64(5314892854495903744),
            Val::from_canonical_u64(15533907063555688448),
            Val::from_canonical_u64(12312015675698548736),
            Val::from_canonical_u64(14140016464013350912),
            Val::from_canonical_u64(16325589062962839552),
            Val::from_canonical_u64(8597377839806076928),
            Val::from_canonical_u64(9704018824195917824),
            Val::from_canonical_u64(12763288618765762560),
            Val::from_canonical_u64(17249257732622848000),
            Val::from_canonical_u64(1998710993415069696),
            Val::from_canonical_u64(923759906393011584),
            Val::from_canonical_u64(1271051229666811648),
            Val::from_canonical_u64(17822362132088737792),
            Val::from_canonical_u64(17999926471875633152),
            Val::from_canonical_u64(635992114476018176),
            Val::from_canonical_u64(17205047318256576512),
            Val::from_canonical_u64(17384900867876315136),
            Val::from_canonical_u64(16484825562915784704),
            Val::from_canonical_u64(16694130609036138496),
            Val::from_canonical_u64(10575069350371260416),
            Val::from_canonical_u64(8330575162062886912),
            Val::from_canonical_u64(885298637936952576),
            Val::from_canonical_u64(541790758138118912),
            Val::from_canonical_u64(5985203084790373376),
            Val::from_canonical_u64(4685030219775483904),
            Val::from_canonical_u64(1411106851304815104),
            Val::from_canonical_u64(11290732479954096128),
            Val::from_canonical_u64(208280581124868512),
            Val::from_canonical_u64(10979018648467968000),
            Val::from_canonical_u64(15952065508715624448),
            Val::from_canonical_u64(15571300830419767296),
            Val::from_canonical_u64(17259785660502616064),
            Val::from_canonical_u64(4298425495274316288),
            Val::from_canonical_u64(9023601070579319808),
            Val::from_canonical_u64(7353589709321807872),
            Val::from_canonical_u64(2988848909076209664),
            Val::from_canonical_u64(10439527789422045184),
            Val::from_canonical_u64(216040220732135360),
            Val::from_canonical_u64(14252611488623712256),
            Val::from_canonical_u64(9543395466794536960),
            Val::from_canonical_u64(2714461051639811072),
            Val::from_canonical_u64(2588317208781407232),
            Val::from_canonical_u64(15458529123534594048),
            Val::from_canonical_u64(15748417817551040512),
            Val::from_canonical_u64(16414455697114423296),
            Val::from_canonical_u64(4397422800601932288),
            Val::from_canonical_u64(11285062031581972480),
            Val::from_canonical_u64(7309354640676467712),
            Val::from_canonical_u64(10457152817239332864),
            Val::from_canonical_u64(8855911538863247360),
            Val::from_canonical_u64(4301853449821814272),
            Val::from_canonical_u64(13001502396339103744),
            Val::from_canonical_u64(10218424535115579392),
            Val::from_canonical_u64(16761509772042182656),
            Val::from_canonical_u64(6688821660695954432),
            Val::from_canonical_u64(12083434295263160320),
            Val::from_canonical_u64(8540021431714616320),
            Val::from_canonical_u64(6891616215679974400),
            Val::from_canonical_u64(10229217098454812672),
            Val::from_canonical_u64(3292165387203778560),
            Val::from_canonical_u64(6090113424998243328),
            Val::from_canonical_u64(17070233710126620672),
            Val::from_canonical_u64(6915716851370551296),
            Val::from_canonical_u64(9505009849073027072),
            Val::from_canonical_u64(6422700465081896960),
            Val::from_canonical_u64(17977653991560529920),
            Val::from_canonical_u64(5800870252836247552),
            Val::from_canonical_u64(12096124733159346176),
            Val::from_canonical_u64(7679273623392321536),
            Val::from_canonical_u64(10376377187857633280),
            Val::from_canonical_u64(13344930747504285696),
            Val::from_canonical_u64(11579281865160153088),
            Val::from_canonical_u64(10300256980048736256),
            Val::from_canonical_u64(378765236515040576),
            Val::from_canonical_u64(11412420941557254144),
            Val::from_canonical_u64(12931662470734252032),
            Val::from_canonical_u64(43018908376346376),
            Val::from_canonical_u64(16001900718237913088),
            Val::from_canonical_u64(5548469743008097280),
            Val::from_canonical_u64(14584404916672178176),
            Val::from_canonical_u64(3396622135873576960),
            Val::from_canonical_u64(7861729246871155712),
            Val::from_canonical_u64(16112271126908045312),
            Val::from_canonical_u64(16988163966860015616),
            Val::from_canonical_u64(273641680619529504),
            Val::from_canonical_u64(5575990058472514560),
            Val::from_canonical_u64(2751301609188253184),
            Val::from_canonical_u64(6478598528223547392),
            Val::from_canonical_u64(386565553848556608),
            Val::from_canonical_u64(9417729078939938816),
            Val::from_canonical_u64(15204315939835727872),
            Val::from_canonical_u64(14942015033780606976),
            Val::from_canonical_u64(18369423901636581376),
            Val::from_canonical_u64(1475161295215894528),
            Val::from_canonical_u64(7999197814297036800),
            Val::from_canonical_u64(2984233088665867776),
            Val::from_canonical_u64(3097746028144832000),
            Val::from_canonical_u64(8849530863480031232),
            Val::from_canonical_u64(7464920943249009664),
            Val::from_canonical_u64(3802996844641460736),
            Val::from_canonical_u64(6284458522545927168),
            Val::from_canonical_u64(5142217010456550400),
            Val::from_canonical_u64(1775580461722730240),
            Val::from_canonical_u64(161694268822794336),
            Val::from_canonical_u64(1518963253808031744),
            Val::from_canonical_u64(16475258091652710400),
            Val::from_canonical_u64(119575899007375152),
            Val::from_canonical_u64(1275863735937974016),
            Val::from_canonical_u64(16539412514520641536),
            Val::from_canonical_u64(16645869274577729536),
            Val::from_canonical_u64(8039205965509554176),
            Val::from_canonical_u64(4788586935019371520),
            Val::from_canonical_u64(15129007200040077312),
            Val::from_canonical_u64(2055561615223771392),
            Val::from_canonical_u64(4149731103701412864),
            Val::from_canonical_u64(10268130195734145024),
            Val::from_canonical_u64(13406631635880075264),
            Val::from_canonical_u64(8927746344866570240),
            Val::from_canonical_u64(11802068403177695232),
            Val::from_canonical_u64(157833420806751552),
            Val::from_canonical_u64(4698875910749767680),
            Val::from_canonical_u64(1616722774788291584),
            Val::from_canonical_u64(3990951895163747840),
            Val::from_canonical_u64(16758609224720795648),
            Val::from_canonical_u64(3045571693290741248),
            Val::from_canonical_u64(17564372683613562880),
            Val::from_canonical_u64(4664015225343143936),
            Val::from_canonical_u64(6133721340680280064),
            Val::from_canonical_u64(2667022304383014912),
            Val::from_canonical_u64(12316557761857339392),
            Val::from_canonical_u64(10375614850625292288),
            Val::from_canonical_u64(8141542666379134976),
            Val::from_canonical_u64(9185476451083834368),
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
