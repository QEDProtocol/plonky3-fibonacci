//! And AIR for the Keccak-f permutation. Assumes the field size is between 2^16 and 2^32.

#![no_std]

extern crate alloc;

mod air;
mod columns;
mod constants;
mod generation;
mod logic;
mod round_flags;
mod fibonacci_air;

pub use air::*;
pub use fibonacci_air::*;
pub use columns::*;
pub use constants::*;
pub use generation::*;

pub const NUM_ROUNDS: usize = 24;
const BITS_PER_LIMB: usize = 16;
pub const U64_LIMBS: usize = 64 / BITS_PER_LIMB;
const RATE_BITS: usize = 1088;
const RATE_LIMBS: usize = RATE_BITS / BITS_PER_LIMB;
