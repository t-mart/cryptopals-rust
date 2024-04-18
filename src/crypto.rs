use crate::bytes_ext::BytesExt;

pub(crate) mod corpus {
    use std::collections::HashMap;

    /// A score from `Corpus::find_best_single_byte_xor`. Implements `PartialOrd`, taking into
    /// account only the score.
    #[derive(PartialEq, Eq)]
    pub(crate) struct ScoreData {
        pub(crate) byte: u8,
        pub(crate) score: usize,
        pub(crate) decrypted: Vec<u8>,
    }

    impl Ord for ScoreData {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.score.cmp(&other.score)
        }
    }

    impl PartialOrd for ScoreData {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    impl std::fmt::Debug for ScoreData {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ScoreData")
                .field("byte", &self.byte)
                .field("score", &self.score)
                .field("decrypted", &String::from_utf8_lossy(&self.decrypted))
                .finish()
        }
    }

    use crate::bytes_ext::BytesExt;
    #[derive(Debug)]
    pub(crate) struct Corpus {
        freq: HashMap<char, usize>,
    }

    impl Corpus {
        fn is_english(c: char) -> bool {
            c.is_ascii_alphanumeric() || c.is_ascii_punctuation() || c.is_ascii_whitespace()
        }

        /// Calculate the score of a string based on the frequency of characters in the corpus. Scores
        /// can only be compared to scores from other strings with the same length and same corpus.
        pub(crate) fn score(&self, s: &str) -> usize {
            let (eng_chars, non_eng_chars): (Vec<_>, Vec<_>) =
                s.chars().partition(|c| Corpus::is_english(*c));

            // non-eng chars mean automatic score of 0
            if !non_eng_chars.is_empty() {
                return 0;
            }

            eng_chars
                .iter()
                .map(|c| self.freq.get(c).unwrap_or(&0))
                .sum()
        }

        pub(crate) fn find_best_single_byte_xor(&self, s: &[u8]) -> ScoreData {
            (0..=255)
                .map(|byte| {
                    let decrypted = s.xor_single(byte);
                    let score = self.score(&String::from_utf8_lossy(&decrypted));
                    ScoreData {
                        byte,
                        score,
                        decrypted,
                    }
                })
                .max()
                .unwrap()
        }

        pub(crate) fn find_best_of_best_single_byte_xor<L: AsRef<[u8]>>(
            &self,
            lines: &[L],
        ) -> ScoreData {
            lines
                .iter()
                .map(|line| self.find_best_single_byte_xor(line.as_ref()))
                .max()
                .unwrap()
        }
    }

    impl Default for Corpus {
        fn default() -> Self {
            let text = include_str!("../data/corpus.txt");
            Corpus::from(text)
        }
    }

    impl From<&str> for Corpus {
        /// Create a new `Corpus` from a string
        fn from(s: &str) -> Self {
            let mut freq = HashMap::new();
            for c in s.chars() {
                if Corpus::is_english(c) {
                    *freq.entry(c).or_insert(0) += 1;
                }
            }
            Corpus { freq }
        }
    }
}

pub(crate) struct VigenereResult {
    pub(crate) key: Vec<u8>,
    pub(crate) plaintext: Vec<u8>,
}

impl std::fmt::Debug for VigenereResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VigenereResult")
            .field("key", &String::from_utf8_lossy(&self.key))
            .field("plaintext", &String::from_utf8_lossy(&self.plaintext))
            .finish()
    }
}

pub(crate) fn break_vigenere(ciphertext: &[u8]) -> VigenereResult {
    // The range of key sizes to consider. The challenge suggests 2-40.
    let key_sz_range = 2..=40;

    // The number of blocks to compare amongst each other for minimal hamming distance. Increasing
    // will increase the likelihood of finding the correct key, but will also increase the time
    // taken.
    let key_sz_blocks = 4;

    // The number of top key sizes to consider (sorted by normalized edit distance). Increasing
    // will increase the likelihood of finding the correct key, but will also increase the time
    // taken.
    let top_n_key_szs = 4;

    // corpus will help us find the best key and the best plaintext
    let corpus = corpus::Corpus::default();

    let mut key_szs = key_sz_range
        .map(|key_sz| {
            let blocks = ciphertext
                .chunks_exact(key_sz)
                .take(key_sz_blocks)
                .collect::<Vec<_>>();
            let mut dist_total = 0;

            // "handshakes": n * (n - 1) / 2
            // e.g., for 4 blocks A, B, C, and D, it'd be: AB, AC, AD, BC, BD, CD = 4 * 3 / 2 = 6
            let comparisons = blocks.len() * (blocks.len() - 1) / 2;

            for i in 0..blocks.len() {
                for j in i + 1..blocks.len() {
                    dist_total += blocks[i].hamming_distance(blocks[j]);
                }
            }
            let dist_average = dist_total / comparisons;
            let dist_normalized = dist_average / key_sz;
            (key_sz, dist_normalized)
        })
        .collect::<Vec<_>>();

    // "The KEYSIZE with the smallest normalized edit distance is probably the key"
    key_szs.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
    key_szs.truncate(top_n_key_szs);

    key_szs
        .iter()
        .map(|(key_sz, _)| {
            let mut columns = (0..*key_sz).map(|_| Vec::new()).collect::<Vec<_>>();
            for (i, byte) in ciphertext.iter().enumerate() {
                columns[i % *key_sz].push(*byte);
            }

            let key = columns
                .iter()
                .map(|column| {
                    let score_data = corpus.find_best_single_byte_xor(column);
                    score_data.byte
                })
                .collect::<Vec<_>>();

            let plaintext = ciphertext.xor_repeating_key(&key);

            VigenereResult { key, plaintext }
        })
        .max_by_key(|result| corpus.score(&String::from_utf8_lossy(&result.plaintext)))
        .unwrap()
}

/// Decrypt a block of AES-128-ECB encrypted data. `is_last_block` should be `true` if the block is
/// the last block of the ciphertext -- this is important because it determines if padding should be
/// removed.
pub(crate) fn decrypt_aes_128_ecb_block(
    ciphertext: &[u8],
    key: &[u8],
    iv: Option<&[u8]>,
    is_last_block: bool,
) -> Vec<u8> {
    use openssl::symm::{Cipher, Crypter, Mode};
    let cipher = Cipher::aes_128_ecb();

    // we specifically are not using Crypter's padding and iv support because we want to do it
    // ourselves because we want to learn!
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, None).unwrap();
    decrypter.pad(false);

    let mut plaintext_buf = vec![0; ciphertext.len() + cipher.block_size()];

    let mut count = decrypter.update(ciphertext, &mut plaintext_buf).unwrap();
    count += decrypter.finalize(&mut plaintext_buf[count..]).unwrap();
    plaintext_buf.truncate(count);

    if let Some(iv) = iv {
        plaintext_buf = plaintext_buf.xor(iv);
    }

    if is_last_block {
        unpad_pkcs7(&plaintext_buf)
    } else {
        plaintext_buf
    }
}

fn get_last_block_idx(ciphertext_len: usize, block_size: usize) -> usize {
    (ciphertext_len / block_size - 1) + usize::from(ciphertext_len % block_size != 0)
}

pub(crate) fn decrypt_aes_128_ecb(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    let block_size = 16;
    let last_block_idx = get_last_block_idx(ciphertext.len(), block_size);

    ciphertext
        .chunks(block_size)
        .enumerate()
        .flat_map(|(block_idx, block)| {
            decrypt_aes_128_ecb_block(block, key, None, block_idx == last_block_idx)
        })
        .collect::<Vec<_>>()
}

pub(crate) fn decrypt_aes_128_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let block_size = 16;
    let last_block_idx = get_last_block_idx(ciphertext.len(), block_size);
    let mut prev_block = iv;
    let mut out = Vec::with_capacity(ciphertext.len() + block_size);

    for (block_idx, block) in ciphertext.chunks(block_size).enumerate() {
        let decrypted =
            decrypt_aes_128_ecb_block(block, key, Some(prev_block), block_idx == last_block_idx);
        out.extend_from_slice(&decrypted);
        prev_block = block;
    }

    out
}

pub(crate) fn is_ecb_encrypted(ciphertext: &[u8]) -> bool {
    use std::collections::HashSet;
    let blocks = ciphertext.chunks_exact(16);
    let unique_blocks = blocks.clone().collect::<HashSet<_>>();
    blocks.len() != unique_blocks.len()
}

pub(crate) fn pad_pkcs7<B: AsRef<[u8]>>(data: B, block_size: usize) -> Vec<u8> {
    let data = data.as_ref();
    let pad_len = block_size - data.len() % block_size;
    if pad_len == 0 {
        data.to_vec()
    } else {
        let mut padded = Vec::with_capacity(data.len() + pad_len);
        padded.extend_from_slice(data);
        #[allow(clippy::cast_possible_truncation)]
        padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));
        padded
    }
}

pub(crate) fn unpad_pkcs7(data: &[u8]) -> Vec<u8> {
    let pad_len = data.last().unwrap();

    assert!(data.len() >= usize::from(*pad_len));

    let unpadded_len = data.len() - usize::from(*pad_len);
    assert!(
        data[unpadded_len..].iter().all(|&b| b == *pad_len),
        "invalid padding"
    );

    data[..unpadded_len].to_vec()
}
