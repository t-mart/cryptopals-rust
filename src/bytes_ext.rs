pub(crate) trait BytesExt {
    /// Xor self with another slice of bytes
    fn xor<B: AsRef<[u8]>>(&mut self, other: B);

    /// Xor with a single byte `n` times, where `n` is the length of the input
    fn xor_single(&mut self, n: u8);

    /// Xor with a repeating key
    fn xor_repeating_key<B: AsRef<[u8]>>(&mut self, key: B);

    /// Calculate the hamming distance between two slices of bytes
    fn hamming_distance<B: AsRef<[u8]>>(&self, other: B) -> usize;
}

fn assert_same_length(a: &[u8], b: &[u8]) {
    let a_len = a.len();
    let b_len = b.len();
    assert_eq!(a_len, b_len, "Length mismatch: {a_len} != {b_len}");
}

impl BytesExt for [u8] {
    fn xor<B: AsRef<[u8]>>(&mut self, other: B) {
        assert_same_length(self, other.as_ref());

        for (a, b) in self.iter_mut().zip(other.as_ref().iter()) {
            *a ^= b;
        }
    }

    /// Xor each byte with a single byte `n`
    fn xor_single(&mut self, n: u8) {
        for byte in self.iter_mut() {
            *byte ^= n;
        }
    }

    fn xor_repeating_key<B: AsRef<[u8]>>(&mut self, key: B) {
        let key = key.as_ref();
        let mut key_iter = key.iter().cycle();

        for byte in self.iter_mut() {
            *byte ^= key_iter.next().unwrap();
        }
    }

    fn hamming_distance<B: AsRef<[u8]>>(&self, other: B) -> usize {
        assert_same_length(self, other.as_ref());

        self.iter()
            .zip(other.as_ref().iter())
            .map(|(a, b)| (a ^ b).count_ones() as usize)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor() {
        let a: [u8; 1] = [12];
        let b = [21];
        let expected = [25];

        let mut actual = a;
        actual.xor(b);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_hamming_distance() {
        let input = b"this is a test";
        let other = b"wokka wokka!!!";
        let expected = 37;

        let actual = input.hamming_distance(other);
        assert_eq!(actual, expected);
    }
}
