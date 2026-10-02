// SPDX-License-Identifier: BSD-3-Clause
//
// Derived from the `subtle` crate v2.6.1: https://github.com/dalek-cryptography/subtle
//
// Copyright (c) 2016-2017 Isis Agora Lovecruft, Henry de Valence. All rights reserved.
// Copyright (c) 2016-2024 Isis Agora Lovecruft. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::ops::{BitAnd, BitAndAssign, BitOr, BitXor, Not};

/// The `Choice` struct represents a choice for use in conditional assignment.
///
/// It is a wrapper around a `u8`, which should have the value either `1` (true)
/// or `0` (false).
///
/// The conversion from `u8` to `Choice` passes the value through an optimization
/// barrier, as a best-effort attempt to prevent the compiler from inferring that
/// the `Choice` value is a boolean. This strategy is based on Tim Maclean's
/// [work on `rust-timing-shield`][rust-timing-shield], which attempts to provide
/// a more comprehensive approach for preventing software side-channels in Rust
/// code.
///
/// The `Choice` struct implements operators for AND, OR, XOR, and NOT, to allow
/// combining `Choice` values. These operations do not short-circuit.
///
/// [rust-timing-shield]:
/// https://www.chosenplaintext.ca/open-source/rust-timing-shield/security
#[derive(Copy, Clone, Debug)]
pub struct Choice(u8);

impl Choice {
    /// Unwrap the `Choice` wrapper to reveal the underlying `u8`.
    ///
    /// # Note
    ///
    /// This function only exists as an **escape hatch** for the rare case
    /// where it's not possible to use one of the `subtle`-provided
    /// trait impls.
    ///
    /// **To convert a `Choice` to a `bool`, use the `From` implementation instead.**
    #[inline]
    pub fn unwrap_u8(&self) -> u8 {
        self.0
    }
}

impl From<Choice> for bool {
    /// Convert the `Choice` wrapper into a `bool`, depending on whether
    /// the underlying `u8` was a `0` or a `1`.
    ///
    /// # Note
    ///
    /// This function exists to avoid having higher-level cryptographic protocol
    /// implementations duplicating this pattern.
    ///
    /// The intended use case for this conversion is at the _end_ of a
    /// higher-level primitive implementation: for example, in checking a keyed
    /// MAC, where the verification should happen in constant-time (and thus use
    /// a `Choice`) but it is safe to return a `bool` at the end of the
    /// verification.
    #[inline]
    fn from(source: Choice) -> bool {
        debug_assert!((source.0 == 0u8) | (source.0 == 1u8));
        source.0 != 0
    }
}

impl BitAnd for Choice {
    type Output = Choice;
    #[inline]
    fn bitand(self, rhs: Choice) -> Choice {
        (self.0 & rhs.0).into()
    }
}

impl BitAndAssign for Choice {
    #[inline]
    fn bitand_assign(&mut self, rhs: Choice) {
        *self = *self & rhs;
    }
}

impl BitOr for Choice {
    type Output = Choice;
    #[inline]
    fn bitor(self, rhs: Choice) -> Choice {
        (self.0 | rhs.0).into()
    }
}

impl BitXor for Choice {
    type Output = Choice;
    #[inline]
    fn bitxor(self, rhs: Choice) -> Choice {
        (self.0 ^ rhs.0).into()
    }
}

impl Not for Choice {
    type Output = Choice;
    #[inline]
    fn not(self) -> Choice {
        (1u8 & (!self.0)).into()
    }
}

/// This function is a best-effort attempt to prevent the compiler from knowing
/// anything about the value of the returned `u8`, other than its type.
///
/// Because we want to support stable Rust, we don't have access to inline
/// assembly or test::black_box, so we use the fact that volatile values will
/// never be elided to register values.
///
/// Note: Rust's notion of "volatile" is subject to change over time. While this
/// code may break in a non-destructive way in the future, “constant-time” code
/// is a continually moving target, and this is better than doing nothing.
#[inline(never)]
fn black_box<T: Copy>(input: T) -> T {
    unsafe {
        // Optimization barrier
        //
        // SAFETY:
        //   - &input is not NULL because we own input;
        //   - input is Copy and always live;
        //   - input is always properly aligned.
        core::ptr::read_volatile(&input)
    }
}

impl From<u8> for Choice {
    #[inline]
    fn from(input: u8) -> Choice {
        debug_assert!((input == 0u8) | (input == 1u8));

        // Our goal is to prevent the compiler from inferring that the value held inside the
        // resulting `Choice` struct is really a `bool` instead of a `u8`.
        Choice(black_box(input))
    }
}

/// An `Eq`-like trait that produces a `Choice` instead of a `bool`.
// #[inline] is specified on these function prototypes to signify that they
#[allow(unused_attributes)] // should be in the actual implementation
pub trait ConstantTimeEq {
    /// Determine if two items are equal.
    ///
    /// The `ct_eq` function should execute in constant time.
    ///
    /// # Returns
    ///
    /// * `Choice(1u8)` if `self == other`;
    /// * `Choice(0u8)` if `self != other`.
    #[inline]
    #[allow(unused_attributes)]
    fn ct_eq(&self, other: &Self) -> Choice;
}

impl ConstantTimeEq for Choice {
    #[inline]
    fn ct_eq(&self, rhs: &Choice) -> Choice {
        !(*self ^ *rhs)
    }
}

/// Given the bit-width `$bit_width` and the corresponding primitive
/// unsigned and signed types `$t_u` and `$t_i` respectively, generate
/// an `ConstantTimeEq` implementation.
macro_rules! generate_integer_equal {
    ($t_u:ty, $t_i:ty, $bit_width:expr) => {
        impl ConstantTimeEq for $t_u {
            #[inline]
            fn ct_eq(&self, other: &$t_u) -> Choice {
                // x == 0 if and only if self == other
                let x: $t_u = self ^ other;

                // If x == 0, then x and -x are both equal to zero;
                // otherwise, one or both will have its high bit set.
                let y: $t_u = (x | x.wrapping_neg()) >> ($bit_width - 1);

                // Result is the opposite of the high bit (now shifted to low).
                ((y ^ (1 as $t_u)) as u8).into()
            }
        }
        impl ConstantTimeEq for $t_i {
            #[inline]
            fn ct_eq(&self, other: &$t_i) -> Choice {
                // Bitcast to unsigned and call that implementation.
                (*self as $t_u).ct_eq(&(*other as $t_u))
            }
        }
    };
}

generate_integer_equal!(u8, i8, 8);
generate_integer_equal!(u16, i16, 16);
generate_integer_equal!(u32, i32, 32);
generate_integer_equal!(u64, i64, 64);

/// A type which can be compared in some manner and be determined to be greater
/// than another of the same type.
pub trait ConstantTimeGreater {
    /// Determine whether `self > other`.
    ///
    /// The bitwise-NOT of the return value of this function should be usable to
    /// determine if `self <= other`.
    ///
    /// This function should execute in constant time.
    ///
    /// # Returns
    ///
    /// A `Choice` with a set bit if `self > other`, and with no set bits
    /// otherwise.
    fn ct_gt(&self, other: &Self) -> Choice;
}

macro_rules! generate_unsigned_integer_greater {
    ($t_u: ty, $bit_width: expr) => {
        impl ConstantTimeGreater for $t_u {
            /// Returns Choice::from(1) iff x > y, and Choice::from(0) iff x <= y.
            ///
            /// # Note
            ///
            /// This algoritm would also work for signed integers if we first
            /// flip the top bit, e.g. `let x: u8 = x ^ 0x80`, etc.
            #[inline]
            fn ct_gt(&self, other: &$t_u) -> Choice {
                let gtb = self & !other; // All the bits in self that are greater than their corresponding bits in other.
                let mut ltb = !self & other; // All the bits in self that are less than their corresponding bits in other.
                let mut pow = 1;

                // Less-than operator is okay here because it's dependent on the bit-width.
                while pow < $bit_width {
                    ltb |= ltb >> pow; // Bit-smear the highest set bit to the right.
                    pow += pow;
                }
                let mut bit = gtb & !ltb; // Select the highest set bit.
                let mut pow = 1;

                while pow < $bit_width {
                    bit |= bit >> pow; // Shift it to the right until we end up with either 0 or 1.
                    pow += pow;
                }
                // XXX We should possibly do the above flattening to 0 or 1 in the
                //     Choice constructor rather than making it a debug error?
                Choice::from((bit & 1) as u8)
            }
        }
    };
}

generate_unsigned_integer_greater!(u8, 8);
generate_unsigned_integer_greater!(u16, 16);
generate_unsigned_integer_greater!(u32, 32);
generate_unsigned_integer_greater!(u64, 64);

/// A type which can be compared in some manner and be determined to be less
/// than another of the same type.
pub trait ConstantTimeLess: ConstantTimeEq + ConstantTimeGreater {
    /// Determine whether `self < other`.
    ///
    /// The bitwise-NOT of the return value of this function should be usable to
    /// determine if `self >= other`.
    ///
    /// A default implementation is provided and implemented for the unsigned
    /// integer types.
    ///
    /// This function should execute in constant time.
    ///
    /// # Returns
    ///
    /// A `Choice` with a set bit if `self < other`, and with no set bits
    /// otherwise.

    #[inline]
    fn ct_lt(&self, other: &Self) -> Choice {
        !self.ct_gt(other) & !self.ct_eq(other)
    }
}

impl ConstantTimeLess for u8 {}
impl ConstantTimeLess for u16 {}
impl ConstantTimeLess for u32 {}
impl ConstantTimeLess for u64 {}
