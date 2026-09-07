const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

#[inline]
fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

fn compress(state: &mut [u32; 8], block: &[u8; 64], count: u64, last: bool) {
    let mut words = [0u32; 16];
    for (index, chunk) in block.chunks_exact(4).enumerate() {
        words[index] = u32::from_le_bytes(chunk.try_into().expect("four-byte chunk"));
    }
    let mut work = [0u32; 16];
    work[..8].copy_from_slice(state);
    work[8..].copy_from_slice(&IV);
    work[12] ^= count as u32;
    work[13] ^= (count >> 32) as u32;
    if last {
        work[14] = !work[14];
    }
    for schedule in SIGMA {
        g(
            &mut work,
            0,
            4,
            8,
            12,
            words[schedule[0]],
            words[schedule[1]],
        );
        g(
            &mut work,
            1,
            5,
            9,
            13,
            words[schedule[2]],
            words[schedule[3]],
        );
        g(
            &mut work,
            2,
            6,
            10,
            14,
            words[schedule[4]],
            words[schedule[5]],
        );
        g(
            &mut work,
            3,
            7,
            11,
            15,
            words[schedule[6]],
            words[schedule[7]],
        );
        g(
            &mut work,
            0,
            5,
            10,
            15,
            words[schedule[8]],
            words[schedule[9]],
        );
        g(
            &mut work,
            1,
            6,
            11,
            12,
            words[schedule[10]],
            words[schedule[11]],
        );
        g(
            &mut work,
            2,
            7,
            8,
            13,
            words[schedule[12]],
            words[schedule[13]],
        );
        g(
            &mut work,
            3,
            4,
            9,
            14,
            words[schedule[14]],
            words[schedule[15]],
        );
    }
    for index in 0..8 {
        state[index] ^= work[index] ^ work[index + 8];
    }
}

pub fn blake2s(key: &[u8], message: &[u8], output_length: usize) -> Vec<u8> {
    assert!(key.len() <= 32);
    assert!((1..=32).contains(&output_length));
    let mut state = IV;
    state[0] ^= 0x0101_0000 ^ ((key.len() as u32) << 8) ^ output_length as u32;
    let mut count = 0u64;
    if !key.is_empty() {
        let mut block = [0u8; 64];
        block[..key.len()].copy_from_slice(key);
        count = 64;
        compress(&mut state, &block, count, message.is_empty());
    }
    if key.is_empty() && message.is_empty() {
        compress(&mut state, &[0u8; 64], 0, true);
    } else if !message.is_empty() {
        let mut chunks = message.chunks(64).peekable();
        while let Some(chunk) = chunks.next() {
            let mut block = [0u8; 64];
            block[..chunk.len()].copy_from_slice(chunk);
            count = count.wrapping_add(chunk.len() as u64);
            compress(&mut state, &block, count, chunks.peek().is_none());
        }
    }
    let mut output = Vec::with_capacity(32);
    for word in state {
        output.extend_from_slice(&word.to_le_bytes());
    }
    output.truncate(output_length);
    output
}

#[cfg(test)]
mod tests {
    use super::blake2s;
    use std::fmt::Write;

    fn hex(value: &[u8]) -> String {
        value.iter().fold(String::new(), |mut output, byte| {
            write!(&mut output, "{byte:02x}").expect("write to string");
            output
        })
    }

    #[test]
    fn unkeyed_vectors() {
        assert_eq!(
            hex(&blake2s(b"", b"", 32)),
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
        );
        assert_eq!(
            hex(&blake2s(b"", b"abc", 32)),
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
        );
    }

    #[test]
    fn keyed_variable_length_vectors() {
        assert_eq!(
            hex(&blake2s(b"key", b"message", 16)),
            "2a39cd942393af640e042843bd2326d2"
        );
        assert_eq!(
            hex(&blake2s(&[0x42; 32], b"ph4ntxm", 8)),
            "713a2c55664edb5b"
        );
    }
}
