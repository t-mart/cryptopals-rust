const BASE64_ENCODE_TABLE: [u8; 64] =
    *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_PAD: char = '=';
const LOW_6_BITS: u8 = 0b0011_1111;

enum B64Sextet {
    Pad,
    Sextet(u8),
    Invalid,
}

impl B64Sextet {
    fn as_char(&self) -> char {
        match self {
            B64Sextet::Pad => BASE64_PAD,
            B64Sextet::Sextet(n) => BASE64_ENCODE_TABLE[*n as usize] as char,
            B64Sextet::Invalid => unreachable!(),
        }
    }

    fn from_char(c: u8) -> Self {
        match c {
            b'=' => B64Sextet::Pad,
            b'A'..=b'Z' => B64Sextet::Sextet(c - b'A'),
            b'a'..=b'z' => B64Sextet::Sextet(c - b'a' + 26),
            b'0'..=b'9' => B64Sextet::Sextet(c - b'0' + 52),
            b'+' => B64Sextet::Sextet(62),
            b'/' => B64Sextet::Sextet(63),
            _ => B64Sextet::Invalid,
        }
    }
}

pub(crate) fn base64_encode<B: AsRef<[u8]>>(data: B) -> String {
    let mut s = data.as_ref();
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
        out.push(B64Sextet::Sextet(idx).as_char());
        if consume {
            s = &s[1..];
        }
    }

    out.extend(std::iter::repeat(B64Sextet::Pad.as_char()).take({
        // if bit_pos == 2, 1 padding character is needed
        // if bit_pos == 4, 2 padding characters are needed
        // other bit_pos values are impossible
        bit_pos / 2
    }));

    out
}

pub(crate) fn base64_decode<B: AsRef<[u8]>>(data: B) -> Vec<u8> {
    let data = data.as_ref();
    let mut out = Vec::with_capacity(data.len() * 4 / 3);
    let mut bit_pos = 0usize;
    let mut pad_count = 0usize;

    for (idx, byte) in data.iter().enumerate() {
        match B64Sextet::from_char(*byte) {
            B64Sextet::Invalid => panic!("Invalid base64 character: {byte}"),
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
                    idx == data.len() - 1 || idx == data.len() - 2,
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

mod tests {
    #[test]
    fn test_base64_encode() {
        let strs: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"light work.", "bGlnaHQgd29yay4="),
            (b"light work", "bGlnaHQgd29yaw=="),
            (b"light wor", "bGlnaHQgd29y"),
        ];

        for (input, expected) in strs {
            let actual = super::base64_encode(input);
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
            let actual = super::base64_decode(input);
            assert_eq!(actual, *expected);
        }
    }
}
