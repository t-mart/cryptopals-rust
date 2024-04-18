pub(crate) trait BytesExt {
    /// Xor self with another slice of bytes
    fn xor<B: AsRef<[u8]>>(&self, other: B) -> Vec<u8>;

    /// Xor with a single byte `n` times, where `n` is the length of the input
    fn xor_single(&self, n: u8) -> Vec<u8>;

    /// Xor with a repeating key
    fn xor_repeating_key<B: AsRef<[u8]>>(&self, key: B) -> Vec<u8>;

    /// Calculate the hamming distance between two slices of bytes
    fn hamming_distance<B: AsRef<[u8]>>(&self, other: B) -> usize;
}

fn assert_same_length<B: AsRef<[u8]>>(a: B, b: B) {
    assert_eq!(
        a.as_ref().len(),
        b.as_ref().len(),
        "Length mismatch: {} != {}",
        a.as_ref().len(),
        b.as_ref().len()
    );
}

impl BytesExt for [u8] {
    /// Xor self with another slice of bytes of equal length
    fn xor<B: AsRef<[u8]>>(&self, other: B) -> Vec<u8> {
        assert_same_length(self, other.as_ref());

        self.iter()
            .zip(other.as_ref().iter())
            .map(|(a, b)| a ^ b)
            .collect()
    }

    /// Xor each byte with a single byte `n`
    fn xor_single(&self, n: u8) -> Vec<u8> {
        self.iter().map(|byte| byte ^ n).collect()
    }

    fn xor_repeating_key<B: AsRef<[u8]>>(&self, key: B) -> Vec<u8> {
        self.iter()
            .zip(key.as_ref().iter().cycle())
            .map(|(input_byte, key_byte)| input_byte ^ key_byte)
            .collect()
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

        let actual = a.xor(b);
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
