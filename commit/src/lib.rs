//! A framework for various (not necessarily hiding) cryptographic commitment schemes.



extern crate alloc;

mod adapters;
mod domain;
mod mmcs;
mod pcs;

#[cfg(any(test, feature = "test-utils"))]
pub mod testing;

pub use adapters::*;
pub use domain::*;
pub use mmcs::*;
pub use pcs::*;
