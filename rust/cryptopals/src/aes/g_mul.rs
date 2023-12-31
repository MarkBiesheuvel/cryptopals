const BITMASK_LOWEST_BIT: u8 = 0b00000001;
const BITMASK_HIGHEST_BIT: u8 = 0b10000000;

fn is_bit_set(value: u8, bitmask: u8) -> bool {
    (value & bitmask) == bitmask
}

/// Galois Field (256) Multiplication of two Bytes
pub fn g_mul(mut lhs: u8, mut rhs: u8) -> u8 {
    let mut result = 0;

    // Instead of always looping 8 times for 8 bits, the loop can exit once rhs is 0
    while rhs != 0 {
        let is_rhs_lowest_bit_set = is_bit_set(rhs, BITMASK_LOWEST_BIT);
        let is_lhs_highest_bit_set = is_bit_set(lhs, BITMASK_HIGHEST_BIT);

        // If the lowest bit of rhs is set, XOR the result with the lhs
        if is_rhs_lowest_bit_set {
            result ^= lhs;
        }

        // Left bitshift lhs
        lhs <<= 1;

        // If the highest bit of lhs was set before shifting, XOR lhs with constant
        if is_lhs_highest_bit_set {
            lhs ^= 0x1B;
        }

        // Right bitshift rhs
        rhs >>= 1;
    }

    result
}
