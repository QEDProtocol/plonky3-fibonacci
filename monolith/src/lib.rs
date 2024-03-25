//! The Monolith permutation, and hash functions built from it.



extern crate alloc;

mod monolith;
mod monolith_mds;
mod util;

pub use monolith::MonolithMersenne31;
pub use monolith_mds::MonolithMdsMatrixMersenne31;
