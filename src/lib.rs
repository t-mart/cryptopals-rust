//! Cryptopals.com challenges
#![warn(clippy::pedantic)]
#![warn(clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]
#![allow(dead_code)]

mod b64_decode;
mod bytes_ext;
mod crypto;

#[cfg(test)]
mod challenges {
    mod set_1 {
        use crate::{
            bytes_ext::BytesExt,
            crypto::{break_vigenere, corpus::Corpus, decrypt_aes_128_ecb, is_ecb_encrypted},
        };

        #[test]
        fn challenge_1() {
            let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
            let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

            let bytes = <[u8]>::from_hex_string(input);
            let actual = bytes.as_base64_encoded();

            assert_eq!(actual, expected);
        }

        #[test]
        fn challenge_2() {
            let a = "1c0111001f010100061a024b53535009181c";
            let b = "686974207468652062756c6c277320657965";
            let expected = "746865206b696420646f6e277420706c6179";

            let a = <[u8]>::from_hex_string(a);
            let b = <[u8]>::from_hex_string(b);

            let actual = a.xor(&b).as_slice().to_hex_string(false);

            assert_eq!(actual, expected);
        }

        // this challenge has no expected answer, so just print the result
        #[test]
        fn challenge_3() {
            let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
            // NOTE: this answer was found after analysis -- the website does not provide it.
            let expected = "Cooking MC's like a pound of bacon";

            let corpus = Corpus::default();
            let bytes = <[u8]>::from_hex_string(input);

            let score_data = corpus.find_best_single_byte_xor(&bytes);
            assert_eq!(String::from_utf8_lossy(&score_data.decrypted), expected);
        }

        #[test]
        fn challenge_4() {
            let input = include_str!("../data/set-1-challenge-4.txt")
                .lines()
                .map(<[u8]>::from_hex_string)
                .collect::<Vec<_>>();
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
            let key = b"ICE";
            let expected =
                "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
            a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

            let bytes = input.as_bytes();
            let xored = bytes.xor_repeating_key(key);

            let actual = xored.as_slice().to_hex_string(false);
            assert_eq!(actual, expected);
        }

        #[test]
        fn challenge_6() {
            let input = include_str!("../data/set-1-challenge-6.txt");
            // NOTE: this answer was found after analysis -- the website does not provide it.
            let expected_key = b"Terminator X: Bring the noise";
            let expected_plaintext = include_bytes!("../data/set-1-challenge-6-and-7-decrypted.txt");

            let b64_encoded = input.lines().collect::<String>();
            let bytes = <[u8]>::from_base64_encoded(&b64_encoded);

            let result = break_vigenere(&bytes);
            assert_eq!(result.key, expected_key);
            assert_eq!(result.plaintext, expected_plaintext);
        }

        #[test]
        fn challenge_7() {
            let input = include_str!("../data/set-1-challenge-7.txt");
            let key = b"YELLOW SUBMARINE";
            // NOTE: this answer was found after analysis -- the website does not provide it.
            let expected = include_bytes!("../data/set-1-challenge-6-and-7-decrypted.txt");

            let b64_encoded = input.lines().collect::<String>();
            let bytes = <[u8]>::from_base64_encoded(&b64_encoded);

            let decrypted = decrypt_aes_128_ecb(&bytes, key);
            
            assert_eq!(decrypted, expected);
        }

        #[test]
        fn challenge_8() {
            let input = include_str!("../data/set-1-challenge-8.txt");
            let expected_idx = 132;

            let ciphertexts = input
                .lines()
                .map(<[u8]>::from_hex_string)
                .collect::<Vec<_>>();

            let ecb_encrypted_idx = ciphertexts
                .iter()
                .position(|ct| is_ecb_encrypted(ct)).unwrap();

            assert_eq!(ecb_encrypted_idx, expected_idx);
        }
    }
}
