//! Cryptopals.com challenges
#![warn(clippy::pedantic)]
#![warn(clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]
#![allow(dead_code)]

mod b64;
mod bytes_ext;
mod crypto;
mod hex;

fn collect_lines(s: &str) -> String {
    s.lines().collect::<String>()
}

fn collect_mapped_lines<F>(s: &str, map_fn: F) -> Vec<Vec<u8>>
where
    F: Fn(&str) -> Vec<u8>,
{
    s.lines().map(map_fn).collect::<Vec<_>>()
}

/// Reads contents of path, removes newlines, hex decodes, and returns a Vec<u8>
#[allow(unused_macros)]
macro_rules! hex_decode_from_file {
    ($filename:expr) => {{
        let contents = include_str!($filename);
        crate::hex::hex_decode(crate::collect_lines(contents))
    }};
}

/// Reads contents of path, hex decodes each line (no newlines), and returns a Vec<Vec<u8>>
#[allow(unused_macros)]
macro_rules! hex_decode_lines_from_file {
    ($filename:expr) => {{
        let contents = include_str!($filename);
        crate::collect_mapped_lines(contents, |line| crate::hex::hex_decode(line))
    }};
}

/// Reads contents of path, removes newlines, base64 decodes, and returns a Vec<u8>
#[allow(unused_macros)]
macro_rules! b64_decode_from_file {
    ($filename:expr) => {{
        let contents = include_str!($filename);
        crate::b64::base64_decode(crate::collect_lines(contents))
    }};
}
/// Reads contents of path, base64 decodes each line (no newlines), and returns a Vec<Vec<u8>>
#[allow(unused_macros)]
macro_rules! b64_decode_lines_from_file {
    ($filename:expr) => {{
        let contents = include_str!($filename);
        crate::collect_mapped_lines(contents, |line| crate::b64::base64_decode(line))
    }};
}

/// The challenges.
///
/// Presented as tests for quick verification.
///
/// The code in these tests should be minimal: just set up inputs and expected values, perform the
/// challenge, and assert for correctness. Conversely, the actual implementation should be in the
/// library modules for reuse.
#[cfg(test)]
mod challenges {
    mod set_1 {
        use crate::{
            b64::base64_encode,
            bytes_ext::BytesExt,
            crypto::{aes_128, corpus::Corpus, vigenere},
            hex::{hex_decode, hex_encode},
        };

        #[test]
        fn challenge_1() {
            let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
            let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

            let bytes = hex_decode(input);
            let actual = base64_encode(bytes);

            assert_eq!(actual, expected);
        }

        #[test]
        fn challenge_2() {
            let a = "1c0111001f010100061a024b53535009181c";
            let b = "686974207468652062756c6c277320657965";
            let expected = "746865206b696420646f6e277420706c6179";

            let a = hex_decode(a);
            let b = hex_decode(b);

            let mut actual = a.clone();
            actual.xor(b);
            let actual = hex_encode(actual, false);

            assert_eq!(actual, expected);
        }

        #[test]
        fn challenge_3() {
            let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
            // NOTE: this answer was found after analysis -- the website does not provide it.
            let expected = "Cooking MC's like a pound of bacon";

            let corpus = Corpus::default();
            let bytes = hex_decode(input);

            let score_data = corpus.find_best_single_byte_xor(&bytes);
            assert_eq!(String::from_utf8_lossy(&score_data.decrypted), expected);
        }

        #[test]
        fn challenge_4() {
            let input = hex_decode_lines_from_file!("../data/set-1-challenge-4.txt");
            // NOTE: this answer was found after analysis -- the website does not provide it.
            let expected = "Now that the party is jumping\n";

            let corpus = Corpus::default();
            let score_data = corpus.find_best_of_best_single_byte_xor(&input);
            assert_eq!(String::from_utf8_lossy(&score_data.decrypted), expected);
        }

        #[test]
        fn challenge_5() {
            let input = "Burning 'em, if you ain't quick and nimble\n\
            I go crazy when I hear a cymbal";
            let key = "ICE";
            let expected =
                "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
            a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

            let mut bytes = input.as_bytes().to_vec();
            bytes.xor_repeating_key(key);

            let actual = hex_encode(bytes, false);
            assert_eq!(actual, expected);
        }

        #[test]
        fn challenge_6() {
            let input = b64_decode_from_file!("../data/set-1-challenge-6.txt");
            // NOTE: this answer was found after analysis -- the website does not provide it.
            let expected_key = b"Terminator X: Bring the noise";
            let expected_plaintext =
                include_bytes!("../data/set-1-challenge-6-and-7-decrypted.txt");

            let result = vigenere::crack(&input);
            assert_eq!(result.key, expected_key);
            assert_eq!(result.plaintext, expected_plaintext);
        }

        #[test]
        fn challenge_7() {
            let input = b64_decode_from_file!("../data/set-1-challenge-7.txt");
            let key = b"YELLOW SUBMARINE";
            // NOTE: this answer was found after analysis -- the website does not provide it.
            let expected = include_bytes!("../data/set-1-challenge-6-and-7-decrypted.txt");

            let plaintext = aes_128::decrypt_ecb(&input, key);

            assert_eq!(plaintext, expected);
        }

        #[test]
        fn challenge_8() {
            let input = hex_decode_lines_from_file!("../data/set-1-challenge-8.txt");
            let expected_idx = 132;

            let ecb_encrypted_idx = input
                .iter()
                .position(|ct| aes_128::is_likely_ecb_encrypted(ct))
                .unwrap();

            assert_eq!(ecb_encrypted_idx, expected_idx);
        }
    }

    mod set_2 {
        use crate::{
            b64::base64_decode,
            crypto::{aes_128, gen_random_bytes, oracle},
        };

        #[test]
        fn challenge_9() {
            let input = b"YELLOW SUBMARINE";
            let expected = b"YELLOW SUBMARINE\x04\x04\x04\x04";

            let mut padded = input.to_vec();
            aes_128::pad_pkcs7(&mut padded, 20);

            assert_eq!(padded, *expected);
        }

        #[test]
        fn challenge_10() {
            let input = b64_decode_from_file!("../data/set-2-challenge-10.txt");
            let key = b"YELLOW SUBMARINE";
            let iv = &[0; 16];

            let expected = include_bytes!("../data/set-2-challenge-10-decrypted.txt");
            let plaintext = aes_128::decrypt_cbc(&input, key, iv);

            assert_eq!(plaintext, expected);
        }

        // this test depends on randomness, and should fail at a rate of 1/2^128
        #[test]
        fn challenge_11() {
            let rounds = 1_000;
            for _ in 0..rounds {
                let oracle = oracle::AffixingOracle::new_random();
                let is_ecb_expected = oracle.is_ecb();
                let min_prefix_size = 5; // we know this from problem constraints
                let block_size = 16; // we know this from problem constraints

                let is_ecb_guess = oracle::analyze_if_ecb(&oracle, block_size, min_prefix_size);

                assert_eq!(is_ecb_guess, is_ecb_expected);
            }
        }

        #[test]
        fn challenge_12() {
            let plaintext_suffix = base64_decode(
                "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
                aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
                YnkK",
            );
            let rand_key = gen_random_bytes(16);
            let oracle =
                oracle::AffixingOracle::new_suffixed_ecb(rand_key, plaintext_suffix.clone());

            let decrypted = oracle::crack_unknown_suffix_ecb(&oracle);

            assert_eq!(decrypted, plaintext_suffix);
        }

        #[test]
        fn challenge_13() {
            use crate::crypto::ecb_cut_paste::{promote_to_admin, ProfileOracle};
            let oracle = ProfileOracle::new_random();

            // let profile = promote_to_admin(&oracle);
            // assert!(profile.is_admin());
            
            // I'm stopping here for now.
        }
    }
}

/// This is just for fun: encrypt a Tux (Linux mascot) BMP file with AES-128 ECB to demonstrate its
/// lack of diffusion. This is kind of a famous image (it has been in the "Block Cipher mode of
/// operation" wikipedia page since 2004 at
/// <https://en.wikipedia.org/w/index.php?title=Block_cipher_mode_of_operation&oldid=2191923>, and
/// maybe elsewhere even earlier). Additionally, the [cryptopals challenge
/// #12](https://cryptopals.com/sets/2/challenges/12) mentions
///
/// > Lots of people know that when you encrypt something in ECB mode, you can see penguins through
/// > it.
///
/// BMP was chosen because it (usually?) contains uncompressed contiguous pixel data, which can be
/// encrypted and still decodable by image viewers. Each pixel is just like 32-bit chunks of [R, G,
/// B, A]. The image comes from
/// <https://upload.wikimedia.org/wikipedia/commons/thumb/3/35/Tux.svg/405px-Tux.svg.png>. It's been
/// verified to contain a number of pixels divisible by 16, so the ciphertext output will be
/// unpadded, and then exported as a 32-bit RGBA BMP with GIMP.
///
/// Observation: This could actually be a useful tool for forensic analysis of photographic images.
/// Regions of identical pixels become easily visible, a possible sign of tampering.
#[test]
fn test_tux() {
    let mut tux = include_bytes!("../data/tux.bmp").to_vec();

    // we just want the pixel data. if we muck with the headers/metadata, image viewers will throw
    // up. so, here, we inspect the headers to find where the pixel data starts and its length.
    let pixel_array_start = u32::from_le_bytes((&tux[0xA..0xE]).try_into().unwrap()) as usize;
    let pixel_data_length = u32::from_le_bytes((&tux[0x22..0x26]).try_into().unwrap()) as usize;
    dbg!(pixel_array_start, pixel_data_length);
    let pixel_data = &tux[pixel_array_start..pixel_array_start + pixel_data_length];

    let key = &crate::crypto::gen_random_bytes(16);
    let ciphertext = crate::crypto::aes_128::encrypt_ecb(pixel_data, key);
    tux.splice(
        pixel_array_start..pixel_array_start + pixel_data_length,
        ciphertext,
    );
    std::fs::write("data/tux-aes-128-ecb.bmp", &tux).unwrap();
}
