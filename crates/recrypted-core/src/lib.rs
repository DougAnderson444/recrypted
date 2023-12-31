#![doc = include_str!("../README.md")]
// Test the README.md code snippets
#[cfg(doctest)]
pub struct ReadmeDoctests;

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::*;

use ed25519_dalek::{
    Digest, Keypair, PublicKey, Signature, Signer, Verifier, KEYPAIR_LENGTH, PUBLIC_KEY_LENGTH,
    SECRET_KEY_LENGTH,
};

use sha2::{Sha256, Sha512};

use aes_gcm::aead::{AeadInPlace, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or `Aes128Gcm`
use core::ops::{Add, Mul, Sub};
// use hex::FromHex;

use serde::{Deserialize, Serialize};

pub struct Pre {
    x: Scalar,
    pub p: EdwardsPoint,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedMessage {
    tag: Vec<u8>,
    encrypted_key: [u8; 32],
    encrypted_data: Vec<u8>,
    message_checksum: Vec<u8>,
    overall_checksum: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReKey {
    r_1: [u8; 32], //  rG - hG
    r_2: [u8; 32], //  rP = rxG
    r_3: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReEncryptedMessage {
    d_1: [u8; 32], //  Point
    d_2: Vec<u8>,
    d_3: Vec<u8>,
    d_4: [u8; 32], //  Point
    d_5: [u8; 32], //  Point
}

// fn convert_from_hex(s: &str) -> [u8; 32] {
//     let mut input: [u8; 32] = Default::default();
//     match Vec::from_hex(s) {
//         Ok(vec) => {
//             input.copy_from_slice(&vec[..]);
//         }
//         Err(_e) => {
//             // Deal with the error ...
//         }
//     }
//     return input;
// }

fn scalar_from_256_hash(data: &[u8]) -> Scalar {
    let gen_array = Sha256::digest(data); // no specified length
    let mut sized: [u8; 32] = Default::default(); // has to be [0..32]
    sized.copy_from_slice(&gen_array[..]);
    // convert hashed to Scalar
    Scalar::from_bytes_mod_order(sized) // from_bytes_mod_order can handle 256 bit reduction https://doc.dalek.rs/curve25519_dalek/scalar/index.html
}

impl Default for Pre {
    fn default() -> Self {
        let key_pair = generate_keypair();
        Self::new(&key_pair.secret.to_bytes())
    }
}

impl Pre {
    pub fn new(secret: &[u8; 32]) -> Pre {
        let hashed_key = get_hashed_priv_bytes(secret);
        let x = Scalar::from_bytes_mod_order(hashed_key);
        let p = constants::ED25519_BASEPOINT_POINT.mul(x);

        Pre { x, p }
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.p.compress().to_bytes()
    }

    pub fn self_encrypt(&self, msg: &[u8], tag: &[u8]) -> EncryptedMessage {
        // https://doc.dalek.rs/curve25519_dalek/scalar/index.html

        let t: Scalar = Scalar::hash_from_bytes::<Sha512>(&get_random_buf());

        let t_base: EdwardsPoint = constants::ED25519_BASEPOINT_POINT.mul(t);

        // write input message
        let secret_buffer = self.x.to_bytes();
        let concatenated = [tag, &secret_buffer].concat();
        let gen_array = Sha256::digest(&concatenated); // no specified length

        let mut sized: [u8; 32] = Default::default();
        sized.copy_from_slice(&gen_array[..]); // has to be [0..32]

        // convert hashed to Scalar
        let h: Scalar = Scalar::from_bytes_mod_order(sized);
        let h_g: EdwardsPoint = constants::ED25519_BASEPOINT_POINT.mul(h);

        let encrypted_key: [u8; 32] = t_base.add(&h_g).compress().to_bytes();
        let t_bytes: [u8; 32] = t_base.compress().to_bytes();

        //  encrypt msg using key
        let key_hash = sha2::Sha512::digest(&t_bytes);
        let encrypted_data = encrypt_symmetric(msg, &key_hash[..]);

        let mut message_checksum: Vec<u8> = Vec::default();

        message_checksum.extend(sha2::Sha512::digest(&[msg, &t_bytes[..]].concat()));

        let xb: [u8; 32] = self.x.to_bytes();

        let alp: Scalar = Scalar::hash_from_bytes::<Sha512>(&[tag, &xb[..]].concat());

        let prep_checksum = [
            &encrypted_key,      // slice of a [u8]
            &encrypted_data[..], // slice of a vec, so need [..]
            &message_checksum[..],
            &alp.to_bytes(),
        ]
        .concat();

        let mut overall_checksum: Vec<u8> = Vec::default();
        overall_checksum.extend(&sha2::Sha512::digest(&prep_checksum[..]));

        EncryptedMessage {
            tag: tag.to_vec(),
            encrypted_key,
            encrypted_data,
            message_checksum,
            overall_checksum,
        }
    }

    pub fn self_decrypt(&self, msg: &EncryptedMessage) -> Vec<u8> {
        let xb: Vec<u8> = self.x.to_bytes().to_vec();
        let alp: Scalar = Scalar::hash_from_bytes::<Sha512>(&[&msg.tag, &xb[..]].concat());

        let prep_checksum = [
            &msg.encrypted_key,
            &msg.encrypted_data[..],
            &msg.message_checksum[..],
            &alp.to_bytes(),
        ]
        .concat();

        let mut overall_checksum: Vec<u8> = Vec::default();
        overall_checksum.extend(&sha2::Sha512::digest(&prep_checksum[..]));

        assert_eq!(
            overall_checksum, msg.overall_checksum,
            "we are expecting the overall checksums to equal"
        );

        // hash1
        let h: Scalar = scalar_from_256_hash(&[&msg.tag, &xb[..]].concat());
        let h_g: EdwardsPoint = constants::ED25519_BASEPOINT_POINT.mul(h);

        let encrypted_key: EdwardsPoint =
            curve25519_dalek::edwards::CompressedEdwardsY(msg.encrypted_key)
                .decompress()
                .unwrap();
        let t_bytes = encrypted_key.sub(h_g).compress().to_bytes();
        let key = sha2::Sha512::digest(&t_bytes);
        let data = decrypt_symmetric(&msg.encrypted_data, &key);

        // hash3
        // check2
        let mut message_checksum: Vec<u8> = Vec::default();
        message_checksum.extend(sha2::Sha512::digest(&[&data[..], &t_bytes[..]].concat()));

        assert_eq!(
            message_checksum, msg.message_checksum,
            "we are expecting the msg checksums to equal"
        );

        data
    }

    // generateReKey
    pub fn generate_re_key(&self, public_key: &[u8; 32], tag: &[u8]) -> ReKey {
        let p: EdwardsPoint = curve25519_dalek::edwards::CompressedEdwardsY(*public_key)
            .decompress()
            .unwrap(); // self.curve.pointFromBuffer(publicKey);
        let xb: [u8; 32] = self.x.to_bytes();

        let r: Scalar = Scalar::hash_from_bytes::<Sha512>(&get_random_buf());
        let h: Scalar = scalar_from_256_hash(&[&tag, &xb[..]].concat());

        let r3_scalar: Scalar = Scalar::hash_from_bytes::<Sha512>(&[tag, &xb[..]].concat()); // sha512

        ReKey {
            r_1: constants::ED25519_BASEPOINT_POINT
                .mul(r.sub(h))
                .compress()
                .to_bytes(), //  rG - hG
            r_2: p.mul(r).compress().to_bytes(), //  rP = rxG
            r_3: r3_scalar.to_bytes(),
        }
    }

    pub fn re_encrypt(
        public_key: &[u8; 32],
        msg: EncryptedMessage,
        re_key: ReKey,
    ) -> ReEncryptedMessage {
        let prep_checksum = [
            &msg.encrypted_key,
            &msg.encrypted_data[..],   // vec to [u8; 32]
            &msg.message_checksum[..], // vec to [u8; 32]
            &re_key.r_3,
        ]
        .concat();

        let check_1 = sha2::Sha512::digest(&prep_checksum[..]).to_vec();

        if !check_1.eq(&msg.overall_checksum) {
            panic!("Overall Checksum Failure!");
        }

        let p: EdwardsPoint = curve25519_dalek::edwards::CompressedEdwardsY(*public_key)
            .decompress()
            .unwrap();

        let t: Scalar = Scalar::hash_from_bytes::<Sha512>(&get_random_buf());

        let tx_g: EdwardsPoint = p.mul(t); //  tP = txG

        let d_2 = msg.encrypted_data;
        let d_3 = msg.message_checksum;
        let d_4 = re_key.r_2;
        let d_5 = constants::ED25519_BASEPOINT_POINT
            .mul(t)
            .compress()
            .to_bytes(); // tG

        // hash 7 scalarFromHash is sha512
        let bet: Scalar = Scalar::hash_from_bytes::<Sha512>(
            &[&tx_g.compress().to_bytes()[..], &d_2, &d_3, &d_4, &d_5].concat(),
        );

        let r_1: EdwardsPoint = curve25519_dalek::edwards::CompressedEdwardsY(re_key.r_1)
            .decompress()
            .unwrap();

        let encrypted_key = curve25519_dalek::edwards::CompressedEdwardsY(msg.encrypted_key)
            .decompress()
            .unwrap()
            .add(r_1);

        let d_1 = encrypted_key.mul(bet).compress().to_bytes();

        ReEncryptedMessage {
            d_1,
            d_2,
            d_3,
            d_4,
            d_5,
        }
    }

    pub fn re_decrypt(&self, d: &ReEncryptedMessage) -> Vec<u8> {
        let d_1: EdwardsPoint = curve25519_dalek::edwards::CompressedEdwardsY(d.d_1)
            .decompress()
            .unwrap(); // pointFromBuffer
        let d_4: EdwardsPoint = curve25519_dalek::edwards::CompressedEdwardsY(d.d_4)
            .decompress()
            .unwrap(); // pointFromBuffer
        let d_5: EdwardsPoint = curve25519_dalek::edwards::CompressedEdwardsY(d.d_5)
            .decompress()
            .unwrap(); // pointFromBuffer

        let tx_g = d_5.mul(self.x); //  x * D5 = x * tG

        // scalarFromHash is sha512
        let b_inv: Scalar = Scalar::hash_from_bytes::<Sha512>(
            &[
                &tx_g.compress().to_bytes()[..],
                &d.d_2,
                &d.d_3,
                &d.d_4,
                &d.d_5,
            ]
            .concat(),
        )
        .invert();

        let x_inv = self.x.invert();

        let t_1 = d_1.mul(b_inv);
        let t_2 = d_4.mul(x_inv);
        let t_bytes = t_1.sub(t_2).compress().to_bytes();
        let key = sha2::Sha512::digest(&t_bytes);

        let data = decrypt_symmetric(&d.d_2, &key);

        // hash 3
        let check_2 = sha2::Sha512::digest(&[&data[..], &t_bytes[..]].concat()).to_vec();

        if !check_2.eq(&d.d_3) {
            panic!("Overall Checksum Failure!");
        };

        data
    }
}

pub fn encrypt_symmetric(data: &[u8], hashed_key: &[u8]) -> Vec<u8> {
    let mut key = [0u8; 32]; // ensure it's 32 bytes long
    key.copy_from_slice(&hashed_key[0..32]); // take the first 32 here...

    let mut nonce = [0u8; 12]; // take the last 32 + an extra 12 here
    nonce.copy_from_slice(&hashed_key[32..44]);

    encrypt(data, &key, &nonce)
}

pub fn decrypt_symmetric(data: &[u8], hashed_key: &[u8]) -> Vec<u8> {
    let mut key = [0u8; 32]; // ensure it's 32 bytes long
    key.copy_from_slice(&hashed_key[0..32]); // take the first 32 here...

    let mut nonce = [0u8; 12]; // take the last 32 + an extra 12 here
    nonce.copy_from_slice(&hashed_key[32..44]);
    let d = data.to_vec();

    decrypt(&d, &key, &nonce)
}

pub fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    // setup cipher
    let key = Key::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv); // unique per message, equiv to iv (init vector)
                                       // let mut buffer: Vec<u8, 128> = Vec::new(); // Buffer needs 16-bytes overhead for GCM tag
                                       // Buffer needs 16-bytes overhead for GCM tag
                                       // Buffer also needs to be bigger enough to take the ciphertext, which is longer than plaintext data
    let mut buffer = Vec::with_capacity(128);
    buffer.extend_from_slice(data); // b"plaintext message"

    let associated_data = b""; // empty for now

    // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
    cipher
        .encrypt_in_place(nonce, associated_data, &mut buffer)
        .expect("encryption failure!");

    // `buffer` now contains the message ciphertext + GCM tag
    buffer // return the ciphertext buffer
}

pub fn decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let key = Key::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv); // unique per message, equiv to iv (init vector)

    let mut buffer = Vec::with_capacity(128);
    buffer.extend_from_slice(data); // b"plaintext message"

    let associated_data = b""; // empty for now

    cipher
        .decrypt_in_place(nonce, associated_data, &mut buffer)
        .expect("decryption failure!");
    buffer // return plaintext
}

pub fn assert_keypair(keypair: &Keypair) -> bool {
    let message: &[u8] = b"This is a test of the tsunami alert system.";
    let signature: Signature = keypair.sign(message);
    keypair.verify(message, &signature).is_ok()
}

pub fn sign(keypair: &Keypair, message: &[u8]) -> Signature {
    keypair.sign(message)
}

// fn verify(&self, message: &[u8], signature: &ed25519::Signature)
pub fn verify(public_key: PublicKey, message: &[u8], signature: Signature) -> bool {
    public_key.verify(message, &signature).is_ok()
}

pub fn get_hashed_priv_bytes(secret: &[u8; 32]) -> [u8; 32] {
    // let secret = keypair.secret.to_bytes();

    let mut hashed_priv_key: [u8; 32] = [0u8; 32];
    hashed_priv_key.copy_from_slice(&sha2::Sha512::digest(secret)[0..32]);

    hashed_priv_key[0] &= 248;
    hashed_priv_key[31] &= 127;
    hashed_priv_key[31] |= 64;

    let key = Scalar::from_bytes_mod_order(hashed_priv_key);
    let _pubkey = constants::ED25519_BASEPOINT_POINT
        .mul(key)
        .compress()
        .to_bytes();

    // assert_eq!(_pubkey, keypair.public.to_bytes());

    hashed_priv_key
}

pub fn generate_keypair() -> Keypair {
    let mut secret_key_bytes = [0u8; SECRET_KEY_LENGTH];
    getrandom::getrandom(&mut secret_key_bytes).unwrap();
    keypair_from_seed(&secret_key_bytes)
}

pub fn keypair_from_seed(secret_key_bytes: &[u8; SECRET_KEY_LENGTH]) -> ed25519_dalek::Keypair {
    let hashed_priv_key = get_hashed_priv_bytes(secret_key_bytes);
    let key = Scalar::from_bytes_mod_order(hashed_priv_key);
    let public_key: [u8; PUBLIC_KEY_LENGTH] = constants::ED25519_BASEPOINT_POINT
        .mul(key)
        .compress()
        .to_bytes();

    let concat = [&secret_key_bytes[..], &public_key].concat();
    let mut keypair: [u8; KEYPAIR_LENGTH] = [0u8; KEYPAIR_LENGTH];

    keypair.copy_from_slice(&concat[..]);
    let kp = Keypair::from_bytes(&keypair).unwrap();
    assert_keypair(&kp);
    kp
}

pub fn get_random_buf() -> [u8; 32] {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).unwrap();
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recrypt() {
        //  `alice` create new proxy re-encryptor
        let alice_pre = Pre::default();

        // BOB
        let bob_keypair = generate_keypair();
        //  `bob` creates to DE-encrypt
        let bob_pre = Pre::new(&bob_keypair.secret.to_bytes());

        // check to see if match
        assert_eq!(
            bob_pre.p.compress().to_bytes(),
            bob_keypair.public.to_bytes()
        );

        //  `alice` self-encrypts data with a tag
        let data =
            hex_literal::hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let tag = b"TAG";

        let encrypted_message = alice_pre.self_encrypt(&data, tag);
        let decrypted_message = alice_pre.self_decrypt(&encrypted_message);
        assert_eq!(data, &decrypted_message[..]);

        //  `alice` re-keys the file to allow for `bob` to access the data
        let re_key = alice_pre.generate_re_key(&bob_keypair.public.to_bytes(), tag);

        //  `proxy` re-encrypts it for `bob`
        let re_encrypted_message =
            Pre::re_encrypt(&bob_keypair.public.to_bytes(), encrypted_message, re_key); // bob, res, reKey, curve

        //  `bob` decrypts it
        let data_2 = bob_pre.re_decrypt(&re_encrypted_message);
        assert_eq!(data, &data_2[..]);
    }
}
