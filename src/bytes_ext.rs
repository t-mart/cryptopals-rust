use crate::b64_decode::{B64Sextet, BASE64_DECODE_TABLE};
use core::panic;

pub(crate) const BASE64_ENCODE_TABLE: [u8; 64] =
    *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const BASE64_PAD: u8 = b'=';
const LOW_6_BITS: u8 = 0b0011_1111;

fn map_hex_digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("Invalid hex digit: {}", c as char),
    }
}

// yeesh, this is probably an abuse of a trait at some point because some of these functions
// don't really feel like [u8] methods
pub(crate) trait BytesExt {
    /// Convert a hex string to a Vec<u8>
    fn from_hex_string(s: &str) -> Vec<u8>;

    /// Convert the input to a hex string
    fn to_hex_string(&self, upper: bool) -> String;

    /// Convert a base64 encoded string to a Vec<u8>
    fn from_base64_encoded(s: &str) -> Vec<u8>;

    /// Base64 encode the input to a String
    fn as_base64_encoded(&self) -> String;

    /// Xor self with another slice of bytes
    fn xor(&self, other: &[u8]) -> Vec<u8>;

    /// Xor with a single byte `n` times, where `n` is the length of the input
    fn xor_single(&self, n: u8) -> Vec<u8>;

    /// Xor with a repeating key
    fn xor_repeating_key(&self, key: &[u8]) -> Vec<u8>;

    /// Calculate the hamming distance between two slices of bytes
    fn hamming_distance(&self, other: &[u8]) -> usize;
}

impl BytesExt for [u8] {
    fn to_hex_string(&self, upper: bool) -> String {
        self.iter()
            .flat_map(|byte| {
                let high = byte >> 4;
                let low = byte & 0b0000_1111;
                vec![high, low]
            })
            .map(|nibble| {
                if nibble < 10 {
                    b'0' + nibble
                } else if upper {
                    b'A' + nibble - 10
                } else {
                    b'a' + nibble - 10
                }
            })
            .map(|c| c as char)
            .collect()
    }

    fn from_hex_string(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks_exact(2)
            .map(|pair| map_hex_digit(pair[0]) << 4 | map_hex_digit(pair[1]))
            .collect()
    }

    fn from_base64_encoded(b64: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(b64.len() * 4 / 3);
        let s = b64.chars();
        let mut bit_pos = 0usize;
        let mut pad_count = 0usize;

        for (idx, c) in s.enumerate() {
            assert!(c.is_ascii(), "Invalid bas64 character: {c}");
            match BASE64_DECODE_TABLE[c as usize] {
                B64Sextet::Invalid => panic!("Invalid base64 character: {c}"),
                B64Sextet::Sextet(s) => {
                    if bit_pos == 0 {
                        bit_pos = 6;
                        out.push(s << 2);
                    } else if bit_pos == 6 {
                        *out.last_mut().unwrap() |= s >> 4;
                        out.push(s << 4);
                        bit_pos = 4;
                    } else if bit_pos == 4 {
                        *out.last_mut().unwrap() |= s >> 2;
                        out.push(s << 6);
                        bit_pos = 2;
                    } else {
                        *out.last_mut().unwrap() |= s;
                        bit_pos = 0;
                    }
                }
                B64Sextet::Pad => {
                    assert!(
                        idx == b64.len() - 1 || idx == b64.len() - 2,
                        "Invalid padding position"
                    );
                    pad_count += 1;
                }
            };
        }

        if pad_count > 0 {
            out.pop();
            match pad_count {
                1 => {
                    assert_eq!(bit_pos, 2, "Invalid padding position");
                }
                2 => {
                    assert_eq!(bit_pos, 4, "Invalid padding position");
                }
                _ => unreachable!(),
            }
        }

        out
    }

    fn as_base64_encoded(&self) -> String {
        let mut s = self;
        let mut bit_pos = 0usize;
        let mut out = String::with_capacity((s.len() + 2) / 3 * 4);
        while !s.is_empty() {
            let (consume, idx) = if bit_pos == 0 {
                bit_pos = 6;
                (false, s[0] >> 2)
            } else if bit_pos == 2 {
                bit_pos = 0;
                (true, s[0] & LOW_6_BITS)
            } else {
                let next = if s.len() > 1 { s[1] } else { 0 };
                if bit_pos == 4 {
                    bit_pos = 2;
                    (true, (s[0] << 2 & LOW_6_BITS) | next >> 6)
                } else {
                    // bit_pos == 6
                    bit_pos = 4;
                    (true, (s[0] << 4 & LOW_6_BITS) | next >> 4)
                }
            };
            out.push(BASE64_ENCODE_TABLE[idx as usize] as char);
            if consume {
                s = &s[1..];
            }
        }

        if bit_pos == 2 {
            out.push(BASE64_PAD as char);
        } else if bit_pos == 4 {
            out.extend([BASE64_PAD as char, BASE64_PAD as char]);
        }

        out
    }

    /// Xor self with another slice of bytes of equal length
    fn xor(&self, other: &[u8]) -> Vec<u8> {
        assert_eq!(
            self.len(),
            other.len(),
            "Length mismatch: {} != {}",
            self.len(),
            other.len()
        );

        self.iter().zip(other.iter()).map(|(a, b)| a ^ b).collect()
    }

    /// Xor each byte with a single byte `n`
    fn xor_single(&self, n: u8) -> Vec<u8> {
        self.iter().map(|byte| byte ^ n).collect()
    }

    fn xor_repeating_key(&self, key: &[u8]) -> Vec<u8> {
        self.iter()
            .zip(key.iter().cycle())
            .map(|(input_byte, key_byte)| input_byte ^ key_byte)
            .collect()
    }

    fn hamming_distance(&self, other: &[u8]) -> usize {
        assert_eq!(
            self.len(),
            other.len(),
            "Length mismatch: {} != {}",
            self.len(),
            other.len()
        );

        self.iter()
            .zip(other.iter())
            .map(|(a, b)| (a ^ b).count_ones() as usize)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode() {
        let strs: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"light work.", "bGlnaHQgd29yay4="),
            (b"light work", "bGlnaHQgd29yaw=="),
            (b"light wor", "bGlnaHQgd29y"),
        ];

        for (input, expected) in strs {
            let actual = input.as_base64_encoded();
            assert_eq!(actual, *expected);
        }
    }

    #[test]
    fn test_base64_decode() {
        let strs: &[(&str, &[u8])] = &[
            ("", b""),
            ("bGlnaHQgd29yay4=", b"light work."),
            ("bGlnaHQgd29yaw==", b"light work"),
            ("bGlnaHQgd29y", b"light wor"),
        ];

        for (input, expected) in strs {
            let actual = <[u8]>::from_base64_encoded(input);
            assert_eq!(actual, *expected);
        }
    }

    #[test]
    fn test_xor() {
        let a: [u8; 1] = [12];
        let b = [21];
        let expected = [25];

        let actual = a.xor(&b);
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
