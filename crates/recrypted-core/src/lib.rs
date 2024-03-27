#![doc = include_str!("../README.md")]
// Test the README.md code snippets
#[cfg(doctest)]
pub struct ReadmeDoctests;

use curve25519_dalek::*;

use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey, KEYPAIR_LENGTH, PUBLIC_KEY_LENGTH,
    SECRET_KEY_LENGTH,
};

use core::ops::{Add, Mul, Sub};
use secrecy::{
    zeroize::{ZeroizeOnDrop, Zeroizing},
    ExposeSecret, Secret, Zeroize,
};
use sha2::{Digest, Sha256, Sha512};
use std::ops::Deref;
// use hex::FromHex;

use serde::{Deserialize, Serialize};

// borrow ecies::symmetric::sym_encrypt for convenience
use ecies::symmetric::{sym_decrypt, sym_encrypt};

pub struct Pre {
    x: Secret<Scalar>,
    pub(crate) p: EdwardsPoint,
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

fn scalar_from_256_hash(data: &[u8]) -> Scalar {
    let gen_array = Sha256::digest(data); // no specified length
    let mut sized: [u8; 32] = Default::default(); // has to be [0..32]
    sized.copy_from_slice(gen_array.as_slice());
    // convert hashed to Scalar
    Scalar::from_bytes_mod_order(sized) // from_bytes_mod_order can handle 256 bit reduction https://doc.dalek.rs/curve25519_dalek/scalar/index.html
}

impl Default for Pre {
    fn default() -> Self {
        let key_pair = generate_keypair();
        Self::new(Zeroizing::new(key_pair.to_bytes()))
    }
}

impl Pre {
    pub fn new(secret: impl Deref<Target = [u8; 32]> + Zeroize + ZeroizeOnDrop) -> Pre {
        let clamped = clamp_secret_bytes(&secret);
        let x = Secret::new(Scalar::from_bytes_mod_order(clamped));
        let p = constants::ED25519_BASEPOINT_POINT.mul(x.expose_secret());

        Pre { x, p }
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.p.compress().to_bytes()
    }

    pub fn self_encrypt(&self, msg: &[u8], tag: &[u8]) -> EncryptedMessage {
        // https://doc.dalek.rs/curve25519_dalek/scalar/index.html

        let t: Scalar = Scalar::hash_from_bytes::<Sha512>(&get_random_buf());

        let mut t_base: EdwardsPoint = constants::ED25519_BASEPOINT_POINT.mul(t);

        // write input message
        let secret_buffer = self.x.expose_secret().to_bytes();
        let concatenated = [tag, &secret_buffer].concat();
        let gen_array = Sha256::digest(concatenated); // no specified length

        let mut sized: [u8; 32] = Default::default();
        sized.copy_from_slice(gen_array.as_slice()); // has to be [0..32]

        // convert hashed to Scalar. Scalar is zeriozed by dalek
        let mut h: Scalar = Scalar::from_bytes_mod_order(sized);
        let mut h_g: EdwardsPoint = constants::ED25519_BASEPOINT_POINT.mul(h);

        let encrypted_key: [u8; 32] = t_base.add(&h_g).compress().to_bytes();
        let t_bytes = Zeroizing::new(t_base.compress().to_bytes());

        //  encrypt msg using key
        let mut key: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        // let key_hash = sha2::Sha512::digest(t_bytes);
        key.extend(&sha2::Sha256::digest(&t_bytes));
        let encrypted_data = sym_encrypt(&key, msg).unwrap();

        let mut message_checksum: Vec<u8> = Vec::default();

        message_checksum.extend(sha2::Sha512::digest([msg, t_bytes.as_ref()].concat()));

        // Clean up sensitive data in memory: Zeroize and drop.
        drop(key);
        drop(t_bytes);
        h.zeroize();
        h_g.zeroize();
        t_base.zeroize();

        let xb: [u8; 32] = self.x.expose_secret().to_bytes();

        let alp: Scalar = Scalar::hash_from_bytes::<Sha512>(&[tag, xb.as_slice()].concat());

        let prep_checksum = [
            &encrypted_key, // slice of a [u8]
            encrypted_data.as_slice(),
            message_checksum.as_slice(),
            &alp.to_bytes(),
        ]
        .concat();

        let mut overall_checksum: Vec<u8> = Vec::default();
        overall_checksum.extend(&sha2::Sha512::digest(prep_checksum.as_slice()));

        EncryptedMessage {
            tag: tag.to_vec(),
            encrypted_key,
            encrypted_data,
            message_checksum,
            overall_checksum,
        }
    }

    pub fn self_decrypt(&self, msg: &EncryptedMessage) -> Vec<u8> {
        let xb: Vec<u8> = self.x.expose_secret().to_bytes().to_vec();
        let alp: Scalar = Scalar::hash_from_bytes::<Sha512>(&[&msg.tag, xb.as_slice()].concat());

        let prep_checksum = [
            &msg.encrypted_key,
            msg.encrypted_data.as_slice(),
            msg.message_checksum.as_slice(),
            &alp.to_bytes(),
        ]
        .concat();

        let mut overall_checksum: Vec<u8> = Vec::default();
        overall_checksum.extend(&sha2::Sha512::digest(prep_checksum.as_slice()));

        assert_eq!(
            overall_checksum, msg.overall_checksum,
            "we are expecting the overall checksums to equal"
        );

        // hash1
        let mut h: Scalar = scalar_from_256_hash(&[&msg.tag, xb.as_slice()].concat());
        let mut h_g: EdwardsPoint = constants::ED25519_BASEPOINT_POINT.mul(h);

        let encrypted_key: EdwardsPoint =
            curve25519_dalek::edwards::CompressedEdwardsY(msg.encrypted_key)
                .decompress()
                .unwrap();
        let t_bytes = Zeroizing::new(encrypted_key.sub(h_g).compress().to_bytes());

        let mut key: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        key.extend(&sha2::Sha256::digest(&t_bytes));
        let data = sym_decrypt(&key, &msg.encrypted_data).unwrap();

        // hash3
        // check2
        let mut message_checksum: Vec<u8> = Vec::default();
        message_checksum.extend(sha2::Sha512::digest(
            [data.as_slice(), t_bytes.as_slice()].concat(),
        ));

        h.zeroize();
        h_g.zeroize();
        drop(key);
        drop(t_bytes);

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
        let xb: [u8; 32] = self.x.expose_secret().to_bytes();

        let r: Scalar = Scalar::hash_from_bytes::<Sha512>(&get_random_buf());
        let h: Scalar = scalar_from_256_hash(&[tag, xb.as_slice()].concat());

        let r3_scalar: Scalar = Scalar::hash_from_bytes::<Sha512>(&[tag, xb.as_slice()].concat()); // sha512

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
            msg.encrypted_data.as_slice(),
            msg.message_checksum.as_slice(),
            &re_key.r_3,
        ]
        .concat();

        let check_1 = sha2::Sha512::digest(prep_checksum.as_slice()).to_vec();

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
            &[
                tx_g.compress().to_bytes().as_slice(),
                &d_2,
                &d_3,
                &d_4,
                &d_5,
            ]
            .concat(),
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

        let tx_g = d_5.mul(self.x.expose_secret()); //  x * D5 = x * tG

        // scalarFromHash is sha512
        let b_inv: Scalar = Scalar::hash_from_bytes::<Sha512>(
            &[
                tx_g.compress().to_bytes().as_slice(),
                &d.d_2,
                &d.d_3,
                &d.d_4,
                &d.d_5,
            ]
            .concat(),
        )
        .invert();

        let t_1 = d_1.mul(b_inv);
        let mut t_2 = d_4.mul(self.x.expose_secret().invert());
        let mut t_bytes = Zeroizing::new(t_1.sub(t_2).compress().to_bytes());

        let mut key = Zeroizing::new(Vec::new());
        key.extend(&sha2::Sha256::digest(&t_bytes));
        let data = sym_decrypt(&key, &d.d_2).unwrap();

        drop(key);

        // hash 3
        let check_2 = sha2::Sha512::digest([data.as_slice(), t_bytes.as_slice()].concat()).to_vec();

        t_bytes.zeroize();
        t_2.zeroize();

        if !check_2.eq(&d.d_3) {
            panic!("Overall Checksum Failure!");
        };

        data
    }
}

pub fn assert_keypair(signing: &SigningKey) -> bool {
    let message: &[u8] = b"This is a test of the tsunami alert system.";
    let signature: Signature = signing.sign(message);
    signing.verify(message, &signature).is_ok()
}

pub fn sign(signing: &SigningKey, message: &[u8]) -> Signature {
    signing.sign(message)
}

// fn verify(&self, message: &[u8], signature: &ed25519::Signature)
pub fn verify(public_key: VerifyingKey, message: &[u8], signature: Signature) -> bool {
    public_key.verify(message, &signature).is_ok()
}

pub fn clamp_secret_bytes(secret: &[u8; 32]) -> [u8; 32] {
    let mut hashed_priv_key: [u8; 32] = [0u8; 32];
    hashed_priv_key.copy_from_slice(&sha2::Sha512::digest(secret)[0..32]);

    // clamping, see: https://docs.rs/curve25519-dalek/4.1.2/src/curve25519_dalek/scalar.rs.html#1386-1391
    hashed_priv_key[0] &= 248;
    hashed_priv_key[31] &= 127;
    hashed_priv_key[31] |= 64;

    // let key = Scalar::from_bytes_mod_order(hashed_priv_key);
    // let _pubkey = constants::ED25519_BASEPOINT_POINT
    //     .mul(key)
    //     .compress()
    //     .to_bytes();
    // assert_eq!(_pubkey, keypair.public.to_bytes());

    hashed_priv_key
}

pub fn generate_keypair() -> SigningKey {
    let mut secret_key_bytes = [0u8; SECRET_KEY_LENGTH];
    getrandom::getrandom(&mut secret_key_bytes).unwrap();
    keypair_from_seed(&secret_key_bytes)
}

pub fn keypair_from_seed(secret_scalar_bytes: &[u8; SECRET_KEY_LENGTH]) -> SigningKey {
    let clamped = clamp_secret_bytes(secret_scalar_bytes);
    let key = Scalar::from_bytes_mod_order(clamped);
    let public_key: [u8; PUBLIC_KEY_LENGTH] = constants::ED25519_BASEPOINT_POINT
        .mul(key)
        .compress()
        .to_bytes();

    let concat = [secret_scalar_bytes.as_slice(), &public_key].concat();
    let mut keypair: [u8; KEYPAIR_LENGTH] = [0u8; KEYPAIR_LENGTH];

    keypair.copy_from_slice(concat.as_slice());
    let kp = SigningKey::from_bytes(secret_scalar_bytes);
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
    pub(super) fn test_recrypt() {
        //  `alice` create new proxy re-encryptor
        let alice_pre = Pre::default();

        // BOB
        let bob_keypair = generate_keypair();
        //  `bob` creates to DE-encrypt
        let bob_pre = Pre::new(Zeroizing::new(bob_keypair.to_bytes()));

        //  `alice` self-encrypts data with a tag
        let data = hex_literal::hex!("deadbeefcafebabe");
        let tag = b"The TAG";

        let encrypted_message = alice_pre.self_encrypt(&data, tag);
        let decrypted_message = alice_pre.self_decrypt(&encrypted_message);
        assert_eq!(data, decrypted_message.as_slice());

        //  `alice` re-keys the file to allow for `bob` to access the data
        let re_key = alice_pre.generate_re_key(&bob_keypair.verifying_key().to_bytes(), tag);

        //  `proxy` re-encrypts it for `bob`
        let re_encrypted_message = Pre::re_encrypt(
            &bob_keypair.verifying_key().to_bytes(),
            encrypted_message,
            re_key,
        ); // bob, res, reKey, curve

        //  `bob` decrypts it
        let data_2 = bob_pre.re_decrypt(&re_encrypted_message);
        assert_eq!(data, data_2.as_slice());
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_wasm() {
        super::tests::test_recrypt();
    }
}
