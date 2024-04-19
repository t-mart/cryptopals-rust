use crate::bytes_ext::BytesExt;

pub(crate) mod corpus {
    use super::BytesExt;
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
                    let mut decrypted = s.to_vec();
                    decrypted.xor_single(byte);
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
        /// Creates a new corpus from a default English document in the source code.
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

pub(crate) mod vigenere {
    use super::{corpus, BytesExt};

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

    pub(crate) fn crack(ciphertext: &[u8]) -> VigenereResult {
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

                let mut plaintext = ciphertext.to_vec();
                plaintext.xor_repeating_key(&key);

                VigenereResult { key, plaintext }
            })
            .max_by_key(|result| corpus.score(&String::from_utf8_lossy(&result.plaintext)))
            .unwrap()
    }
}

pub(crate) mod aes_128 {
    use super::BytesExt;

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub(crate) enum Cipher {
        Ecb,
        Cbc { iv: Vec<u8> },
    }
    impl Cipher {
        pub(super) fn new_cbc_with_random_iv() -> Self {
            Cipher::Cbc {
                iv: super::gen_random_bytes(16),
            }
        }

        fn new_cbc<IV: AsRef<[u8]>>(iv: IV) -> Self {
            Cipher::Cbc {
                iv: iv.as_ref().to_vec(),
            }
        }
    }

    /// Decrypt a block of AES-128 encrypted data. `is_last_block` should be `true` if the block
    /// is the last block of the ciphertext -- this is important because it determines if padding
    /// should be removed.
    fn decrypt_block(ciphertext: &[u8], key: &[u8], cipher: Cipher) -> Vec<u8> {
        use openssl::symm::{self, Crypter, Mode};

        // always use ECB: we'll handle the IV of CBC ourselves
        let openssl_cipher = symm::Cipher::aes_128_ecb();

        // we specifically are not using Crypter's padding and iv support because we want to do it
        // ourselves because we want to learn!
        let mut decrypter = Crypter::new(openssl_cipher, Mode::Decrypt, key, None).unwrap();
        decrypter.pad(false);

        let mut plaintext_buf = vec![0; ciphertext.len() + openssl_cipher.block_size()];

        let mut count = decrypter.update(ciphertext, &mut plaintext_buf).unwrap();
        // TODO: experiment with removing this line... we're not padding with openssl, so might not need it.
        count += decrypter.finalize(&mut plaintext_buf[count..]).unwrap();
        plaintext_buf.truncate(count);

        if let Cipher::Cbc { iv } = cipher {
            plaintext_buf.xor(iv);
        }

        plaintext_buf
    }

    fn encrypt_block(plaintext: &[u8], key: &[u8], cipher: Cipher) -> Vec<u8> {
        use openssl::symm::{self, Crypter, Mode};

        // always use ECB: we'll handle the IV of CBC ourselves
        let openssl_cipher = symm::Cipher::aes_128_ecb();

        let mut plaintext = plaintext.to_vec();

        if let Cipher::Cbc { iv } = cipher {
            plaintext.xor(iv);
        }

        // we specifically are not using Crypter's padding and iv support because we want to do it
        // ourselves because we want to learn!
        let mut encrypter = Crypter::new(openssl_cipher, Mode::Encrypt, key, None).unwrap();
        encrypter.pad(false);

        let mut ciphertext_buf = vec![0; plaintext.len() + openssl_cipher.block_size()];

        let mut count = encrypter.update(&plaintext, &mut ciphertext_buf).unwrap();
        // TODO: experiment with removing this line... we're not padding with openssl, so might not need it.
        count += encrypter.finalize(&mut ciphertext_buf[count..]).unwrap();
        ciphertext_buf.truncate(count);

        ciphertext_buf
    }

    pub(crate) fn decrypt_ecb(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
        let block_size = openssl::symm::Cipher::aes_128_ecb().block_size();
        let mut plaintext = Vec::with_capacity(ciphertext.len());

        for block in ciphertext.chunks_exact(block_size) {
            let decrypted = decrypt_block(block, key, Cipher::Ecb);
            plaintext.extend_from_slice(&decrypted);
        }

        unpad_pkcs7(&mut plaintext);

        plaintext
    }

    pub(crate) fn decrypt_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
        let block_size = openssl::symm::Cipher::aes_128_cbc().block_size();
        let mut cipher = Cipher::new_cbc(iv);
        let mut plaintext = Vec::with_capacity(ciphertext.len());

        for block in ciphertext.chunks_exact(block_size) {
            let decrypted = decrypt_block(block, key, cipher);
            plaintext.extend_from_slice(&decrypted);
            cipher = Cipher::new_cbc(block);
        }

        unpad_pkcs7(&mut plaintext);

        plaintext
    }

    pub(crate) fn encrypt_ecb(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
        let block_size = openssl::symm::Cipher::aes_128_ecb().block_size();
        let mut ciphertext = Vec::with_capacity(plaintext.len() + block_size);

        let mut padded_plaintext = plaintext.to_vec();
        pad_pkcs7(&mut padded_plaintext, block_size);

        for block in padded_plaintext.chunks_exact(block_size) {
            let ciphertext_block = encrypt_block(block, key, Cipher::Ecb);
            ciphertext.extend_from_slice(&ciphertext_block);
        }

        ciphertext
    }

    pub(crate) fn encrypt_cbc(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
        let block_size = openssl::symm::Cipher::aes_128_cbc().block_size();
        let mut ciphertext = Vec::with_capacity(plaintext.len() + block_size);

        let mut padded_plaintext = plaintext.to_vec();
        pad_pkcs7(&mut padded_plaintext, block_size);

        let mut last_ciphertext_block = iv.to_vec();

        for block in padded_plaintext.chunks_exact(block_size) {
            last_ciphertext_block = encrypt_block(block, key, Cipher::Cbc {
                iv: last_ciphertext_block,
            });
            ciphertext.extend_from_slice(&last_ciphertext_block);
        }

        ciphertext
    }

    /// Determine if a ciphertext is likely encrypted with AES-128-ECB. This is done by checking if
    /// there are any duplicate blocks in the ciphertext.
    ///
    /// If this function returns true, it is likely that the ciphertext is encrypted with
    /// AES-128-ECB. If it returns false, its either not encrypted with AES-128-ECB, the ciphertext
    /// is too short, or the plaintext contained no duplicate blocks.
    pub(crate) fn is_likely_ecb_encrypted(ciphertext: &[u8]) -> bool {
        use std::collections::HashSet;
        let blocks = ciphertext.chunks_exact(16);
        let unique_blocks = blocks.clone().collect::<HashSet<_>>();
        blocks.len() != unique_blocks.len()
    }

    pub(crate) fn pad_pkcs7(data: &mut Vec<u8>, block_size: usize) {
        let pad_len = (block_size - data.len() % block_size) % block_size;
        let pad_len = if pad_len == 0 { block_size } else { pad_len };
        #[allow(clippy::cast_possible_truncation)]
        data.resize(data.len() + pad_len, pad_len as u8);
    }

    pub(crate) fn unpad_pkcs7(data: &mut Vec<u8>) {
        let pad_len = *data
            .last()
            .expect("Data cannot be empty, no padding to remove");

        // Ensure the padding length is realistic, and the data array is not shorter than the padding length
        assert!(
            pad_len as usize <= data.len(),
            "Padding length {} exceeds data length {}",
            pad_len,
            data.len()
        );

        // Calculate the start of the padding
        let unpadded_len = data.len() - pad_len as usize;

        // Verify that all elements in the padding region are equal to the supposed padding length
        assert!(
            data.iter().skip(unpadded_len).all(|&x| x == pad_len),
            "Invalid padding: not all bytes are equal to {pad_len} at the end of the data"
        );

        // Remove the padding
        data.truncate(unpadded_len);
    }
}

pub(crate) fn gen_random_bytes(len: usize) -> Vec<u8> {
    use rand::Rng;
    (0..len).map(|_| rand::thread_rng().gen()).collect()
}

pub(crate) mod oracle {
    use std::vec;

    use super::{
        aes_128::{encrypt_cbc, encrypt_ecb, Cipher},
        gen_random_bytes,
    };

    /// A structure that can encypt data using either AES-128-ECB or AES-128-CBC (with a random IV).
    /// Before encryption, the data is prefixed and suffixed with random bytes.
    pub(crate) struct Oracle {
        cipher: Cipher,
        key: Vec<u8>,
        prefix: Vec<u8>,
        suffix: Vec<u8>,
    }

    impl Oracle {
        pub(crate) fn new_random() -> Self {
            use rand::Rng;
            let mut rng = rand::thread_rng();

            let cipher = if rng.gen_bool(0.5) {
                Cipher::Ecb
            } else {
                Cipher::new_cbc_with_random_iv()
            };

            let rand_prefix_len = rng.gen_range(5..=10);
            let rand_suffix_len = rng.gen_range(5..=10);

            Oracle {
                cipher,
                key: gen_random_bytes(16),
                prefix: gen_random_bytes(rand_prefix_len),
                suffix: gen_random_bytes(rand_suffix_len),
            }
        }

        /// Create a new Secret using ECB with a given key and suffix and empty prefix.
        ///
        /// This is for challenge 12.
        pub(crate) fn new_ecb(key: Vec<u8>, suffix: Vec<u8>) -> Self {
            Oracle {
                cipher: Cipher::Ecb,
                key,
                prefix: Vec::new(),
                suffix,
            }
        }

        /// Return if the oracle is using ECB. This is useful for testing the oracle against
        /// cryptanalyses.
        pub(crate) fn is_ecb(&self) -> bool {
            matches!(self.cipher, Cipher::Ecb)
        }

        fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
            let affixed = [&self.prefix, plaintext, &self.suffix].concat();
            match &self.cipher {
                Cipher::Ecb => encrypt_ecb(&affixed, &self.key),
                Cipher::Cbc { iv } => encrypt_cbc(&affixed, &self.key, iv),
            }
        }
    }

    pub(crate) fn analyze_if_ecb(
        oracle: &Oracle,
        block_size: usize,
        min_prefix_size: usize,
    ) -> bool {
        // we need a minimum of 43 bytes of plaintext to detect the oracle. that will produce at
        // least 3 blocks of ciphertext:
        // - Block 1: at a minimal/worst case, 5 bytes of prefix + 11 bytes of our plaintext
        // - Block 2: 16 bytes of our plaintext
        // - Block 3: 16 bytes of our plaintext
        // - (we don't care about later blocks)
        //
        // because ECB will produce the same ciphertext for the same plaintext, we can detect it by
        // checking if the second and third blocks are the same.
        let message_length = block_size * 3 - min_prefix_size;
        let plaintext = vec![0; message_length];
        let ciphertext = oracle.encrypt(&plaintext);

        let block_size = 16;
        let block_2 = &ciphertext[block_size..block_size * 2];
        let block_3 = &ciphertext[block_size * 2..block_size * 3];

        // do we think it's ECB? if the blocks are equal, then it's super likely ECB
        block_2 == block_3

        // open question: could CBC identical blocks in this way? i.e. false positive? i think it
        // could, but again, super unlikely. if we assume ECB with an IV produces all 128-bit blocks
        // with equal probability (the ideal ciphertext is indistinguishable from randomness), then
        // the probability of this happening is 1 in 2^128 (i think).
    }

    pub(crate) fn crack_ecb(oracle: &Oracle) -> Vec<u8> {
        // first, determine the block size
        let mut block_size_plaintext = Vec::new();
        let mut last_ciphertext_size = None;

        let block_size = 'b: loop {
            block_size_plaintext.push(0);
            let ciphertext = oracle.encrypt(&block_size_plaintext);
            let cur_cipher_size = ciphertext.len();
            match &last_ciphertext_size {
                None => last_ciphertext_size = Some(cur_cipher_size),
                Some(last_size) => {
                    if cur_cipher_size != *last_size {
                        let block_size = cur_cipher_size - *last_size;
                        break 'b block_size;
                    }
                }
            }

            // insurance
            assert!(block_size_plaintext.len() <= 256, "block size not found");
        };

        // then ensure it's ECB (through analysis). pass a 0 min_prefix_size because we know the
        // prefix is empty (from problem constraints)
        assert!(analyze_if_ecb(oracle, block_size, 0), "oracle is not ECB");

        // let mut test_block = vec![0; block_size];
        let mut cracked = Vec::new();

        loop {
            let block_idx = cracked.len() / block_size;
            let fill_size = block_size - (cracked.len() % block_size) - 1;

            let plaintext = vec![0; fill_size];
            let ciphertext = oracle.encrypt(&plaintext);

            let ciphertext_block = ciphertext
                .chunks_exact(block_size)
                .nth(block_idx)
                .unwrap_or_else(|| panic!("couldn't get block with idx {block_idx}"))
                .to_vec();

            let found = (0..=255)
                .map(|byte| {
                    let byte_block_fill_size = if block_idx == 0 { fill_size } else { 0 };
                    let rem = block_size - byte_block_fill_size - 1;
                    let test_byte_block = [
                        vec![0; if block_idx == 0 { fill_size } else { 0 }], // filler bytes
                        cracked[cracked.len() - rem..].to_vec(),
                        vec![byte],
                    ]
                    .concat();
                    let test_ciphertext_block = oracle
                        .encrypt(&test_byte_block)
                        .chunks_exact(block_size)
                        .next()
                        .unwrap()
                        .to_vec();
                    (byte, test_ciphertext_block)
                })
                .find(|(_, test_ciphertext)| *test_ciphertext == ciphertext_block);

            if let Some((byte, _)) = found {
                cracked.push(byte);
            } else {
                break;
            }
        }

        crate::crypto::aes_128::unpad_pkcs7(&mut cracked);

        cracked
    }
}

#[cfg(test)]
mod tests {
    const KEY: &[u8] = b"This is 16 bytes";
    const PLAINTEXTS: &[&[u8]] = &[
        // general
        b"My name is Ozymandias, King of Kings;\n\
        Look on my Works, ye Mighty, and despair!",
        // exactly 1 block
        b"0123456789abcdef",
        // empty
        b"",
    ];

    #[test]
    fn test_ecb_decryption() {
        use openssl::symm::{decrypt, encrypt, Cipher};
        let cipher = Cipher::aes_128_ecb();

        for &plaintext in PLAINTEXTS {
            // first encrypt the plaintext with openssl, so we know that it is correct
            let ciphertext = encrypt(cipher, KEY, None, plaintext).unwrap();

            // now decrypt the ciphertext with our implementation and openssl, and compare
            let expected = decrypt(cipher, KEY, None, &ciphertext).unwrap();
            let actual = super::aes_128::decrypt_ecb(&ciphertext, KEY);

            assert_eq!(
                actual,
                expected,
                r#"plaintext: "{}""#,
                plaintext.escape_ascii()
            );
        }
    }

    #[test]
    fn test_cbc_decryption() {
        use openssl::symm::{decrypt, encrypt, Cipher};
        let cipher = Cipher::aes_128_cbc();

        for &plaintext in PLAINTEXTS {
            // first encrypt the plaintext with openssl, so we know that it is correct
            let iv = super::gen_random_bytes(16);
            let ciphertext = encrypt(cipher, KEY, Some(&iv), plaintext).unwrap();

            // now decrypt the ciphertext with our implementation and openssl, and compare
            let expected = decrypt(cipher, KEY, Some(&iv), &ciphertext).unwrap();
            let actual = super::aes_128::decrypt_cbc(&ciphertext, KEY, &iv);

            assert_eq!(
                actual,
                expected,
                r#"plaintext: "{}""#,
                plaintext.escape_ascii()
            );
        }
    }

    #[test]
    fn test_ecb_encryption() {
        use openssl::symm::{encrypt, Cipher};
        let cipher = Cipher::aes_128_ecb();

        for &plaintext in PLAINTEXTS {
            let expected = encrypt(cipher, KEY, None, plaintext).unwrap();
            let actual = super::aes_128::encrypt_ecb(plaintext, KEY);

            assert_eq!(
                actual,
                expected,
                r#"plaintext: "{}""#,
                plaintext.escape_ascii()
            );
        }
    }

    #[test]
    fn test_cbc_encryption() {
        use openssl::symm::{encrypt, Cipher};
        let cipher = Cipher::aes_128_cbc();

        for &plaintext in PLAINTEXTS {
            // dbg!(plaintext);
            let iv = super::gen_random_bytes(16);
            let expected = encrypt(cipher, KEY, Some(&iv), plaintext).unwrap();
            let actual = super::aes_128::encrypt_cbc(plaintext, KEY, &iv);

            assert_eq!(
                actual,
                expected,
                r#"plaintext: "{}""#,
                plaintext.escape_ascii()
            );
        }
    }
}
