pub(crate) fn hex_encode<B: AsRef<[u8]>>(data: B, upper: bool) -> String {
    data.as_ref().iter()
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

fn map_to_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("Invalid hex digit: {}", c as char),
    }
}

pub(crate) fn hex_decode<B: AsRef<[u8]>>(data: B) -> Vec<u8> {
    data.as_ref()
        .chunks_exact(2)
        .map(|pair| map_to_nibble(pair[0]) << 4 | map_to_nibble(pair[1]))
        .collect()
}