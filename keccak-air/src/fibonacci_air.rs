use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_matrix::MatrixRowSlices;






pub const NUM_FIBONACCI_COLS: usize = 3;

/// Assumes the field size is at least 16 bits.
pub struct FibonacciAir {}

impl<F> BaseAir<F> for FibonacciAir {
    fn width(&self) -> usize {
        NUM_FIBONACCI_COLS
    }
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct FibonacciCols<T> {
    pub a: T,
    pub b: T,
    pub c: T,
}

impl<T> Borrow<FibonacciCols<T>> for [T] {
    fn borrow(&self) -> &FibonacciCols<T> {
        debug_assert_eq!(self.len(), NUM_FIBONACCI_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<FibonacciCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<FibonacciCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut FibonacciCols<T> {
        debug_assert_eq!(self.len(), NUM_FIBONACCI_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<FibonacciCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

impl<AB: AirBuilder> Air<AB> for FibonacciAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &FibonacciCols<AB::Var> = main.row_slice(0).borrow();
        let next: &FibonacciCols<AB::Var> = main.row_slice(1).borrow();

        builder.assert_zero(local.a + local.b - local.c);

        let one = AB::Expr::one();
        builder.when_first_row().assert_eq(one.clone(), local.a);
        builder.when_first_row().assert_eq(one, local.b);

        // 1 1 2
        // 1 2 3
        // 2 3 5
        builder
            .when_transition()
            .assert_eq(next.a, local.b);
        builder
            .when_transition()
            .assert_eq(next.b, local.c);
    }
}
