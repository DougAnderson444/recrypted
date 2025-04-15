#![doc = include_str!("../README.md")]
// Test the README.md code snippets
#[cfg(doctest)]
pub struct ReadmeDoctests;

use curve25519_dalek::*;

use ed25519_dalek::{Signature, Signer, VerifyingKey};
pub use ed25519_dalek::{SigningKey, Verifier};

use core::ops::{Add, Mul, Sub};
use rand_core::OsRng;
pub use secrecy::zeroize::Zeroizing;
use secrecy::{zeroize::ZeroizeOnDrop, Zeroize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::ops::Deref;

// borrow ecies::symmetric::sym_encrypt for convenience
use ecies::symmetric::{sym_decrypt, sym_encrypt};

pub struct Pre {
    secret: SigningKey,
    pub(crate) public: VerifyingKey,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct EncryptedMessage {
    tag: Vec<u8>,
    encrypted_key: [u8; 32],
    encrypted_data: Vec<u8>,
    message_checksum: Vec<u8>,
    overall_checksum: Vec<u8>,
}

impl EncryptedMessage {
    /// Sets the tag
    pub fn with_tag(mut self, tag: &[u8]) -> Self {
        self.tag = tag.to_vec();
        self
    }

    /// Sets the encrypted key
    pub fn with_encrypted_key(mut self, encrypted_key: &[u8; 32]) -> Self {
        self.encrypted_key = *encrypted_key;
        self
    }

    /// Sets the encrypted data
    pub fn with_encrypted_data(mut self, encrypted_data: &[u8]) -> Self {
        self.encrypted_data = encrypted_data.to_vec();
        self
    }

    /// Sets the message checksum
    pub fn with_message_checksum(mut self, message_checksum: &[u8]) -> Self {
        self.message_checksum = message_checksum.to_vec();
        self
    }

    /// Sets the overall checksum
    pub fn with_overall_checksum(mut self, overall_checksum: &[u8]) -> Self {
        self.overall_checksum = overall_checksum.to_vec();
        self
    }

    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    pub fn encrypted_key(&self) -> [u8; 32] {
        self.encrypted_key
    }

    pub fn encrypted_data(&self) -> &[u8] {
        &self.encrypted_data
    }

    pub fn message_checksum(&self) -> &[u8] {
        &self.message_checksum
    }

    pub fn overall_checksum(&self) -> &[u8] {
        &self.overall_checksum
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ReKey {
    r_1: [u8; 32], //  rG - hG
    r_2: [u8; 32], //  rP = rxG
    r_3: [u8; 32],
}

impl ReKey {
    pub fn with_r_1(mut self, r_1: &[u8; 32]) -> Self {
        self.r_1 = *r_1;
        self
    }

    pub fn with_r_2(mut self, r_2: &[u8; 32]) -> Self {
        self.r_2 = *r_2;
        self
    }

    pub fn with_r_3(mut self, r_3: &[u8; 32]) -> Self {
        self.r_3 = *r_3;
        self
    }

    pub fn r_1(&self) -> [u8; 32] {
        self.r_1
    }

    pub fn r_2(&self) -> [u8; 32] {
        self.r_2
    }

    pub fn r_3(&self) -> [u8; 32] {
        self.r_3
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ReEncryptedMessage {
    d_1: [u8; 32], //  Point
    d_2: Vec<u8>,
    d_3: Vec<u8>,
    d_4: [u8; 32], //  Point
    d_5: [u8; 32], //  Point
}

impl ReEncryptedMessage {
    pub fn with_d_1(mut self, d_1: &[u8; 32]) -> Self {
        self.d_1 = *d_1;
        self
    }

    pub fn with_d_2(mut self, d_2: &[u8]) -> Self {
        self.d_2 = d_2.to_vec();
        self
    }

    pub fn with_d_3(mut self, d_3: &[u8]) -> Self {
        self.d_3 = d_3.to_vec();
        self
    }

    pub fn with_d_4(mut self, d_4: &[u8; 32]) -> Self {
        self.d_4 = *d_4;
        self
    }

    pub fn with_d_5(mut self, d_5: &[u8; 32]) -> Self {
        self.d_5 = *d_5;
        self
    }

    pub fn d_1(&self) -> [u8; 32] {
        self.d_1
    }

    pub fn d_2(&self) -> &[u8] {
        &self.d_2
    }

    pub fn d_3(&self) -> &[u8] {
        &self.d_3
    }

    pub fn d_4(&self) -> [u8; 32] {
        self.d_4
    }

    pub fn d_5(&self) -> [u8; 32] {
        self.d_5
    }
}

fn scalar_from_256_hash(data: &[u8]) -> Scalar {
    // from_bytes_mod_order can handle 256 bit reduction https://doc.dalek.rs/curve25519_dalek/scalar/index.html
    Scalar::from_bytes_mod_order(Sha256::digest(data).into())
}

impl Default for Pre {
    fn default() -> Self {
        let signing_key: SigningKey = generate_keypair();
        Self {
            public: signing_key.verifying_key(),
            secret: signing_key,
        }
    }
}

impl Pre {
    /// Create a new Proxy Re-Encryptor from a 32 byte secret key
    pub fn new(secret: impl Deref<Target = [u8; 32]> + Zeroize + ZeroizeOnDrop) -> Pre {
        let signing = SigningKey::from_bytes(&secret);
        let public = signing.verifying_key();
        let secret = signing;

        Pre { secret, public }
    }

    /// Get the public key bytes of this Proxy Re-Encryptor
    pub fn public_key(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Encrypt a message with a tag
    pub fn self_encrypt(&self, msg: &[u8], tag: &[u8]) -> EncryptedMessage {
        // https://doc.dalek.rs/curve25519_dalek/scalar/index.html
        let mut csprng = OsRng;
        let t: Scalar = Scalar::hash_from_bytes::<Sha512>(Scalar::random(&mut csprng).as_bytes());

        let mut t_base: EdwardsPoint = constants::ED25519_BASEPOINT_POINT.mul(t);

        let concatenated = [tag, self.secret.to_scalar().as_bytes()].concat();
        let gen_array = Sha256::digest(concatenated); // no specified length

        let mut sized = Zeroizing::new([0u8; 32]);
        sized.copy_from_slice(gen_array.as_slice());

        // convert hashed to Scalar. Scalar is zeriozed by dalek
        let mut h: Scalar = Scalar::from_bytes_mod_order(*sized);
        let mut h_g: EdwardsPoint = constants::ED25519_BASEPOINT_POINT.mul(h);

        let encrypted_key: [u8; 32] = t_base.add(&h_g).compress().to_bytes();
        let t_bytes = Zeroizing::new(t_base.compress().to_bytes());

        //  encrypt msg using key
        let mut key: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        key.extend(&sha2::Sha256::digest(&t_bytes));
        let encrypted_data = sym_encrypt(&key, msg).unwrap();

        let mut message_checksum: Vec<u8> = Vec::default();

        message_checksum.extend(sha2::Sha512::digest([msg, t_bytes.as_ref()].concat()));

        let mut alp: Scalar =
            Scalar::hash_from_bytes::<Sha512>(&[tag, self.secret.to_scalar().as_bytes()].concat());

        let prep_checksum = [
            &encrypted_key, // slice of a [u8]
            encrypted_data.as_slice(),
            message_checksum.as_slice(),
            &alp.to_bytes(),
        ]
        .concat();

        // Clean up sensitive data in memory: Zeroize Scalars and drop ZeroizeOnDrop types
        drop(key);
        drop(sized);
        drop(t_bytes);
        h.zeroize();
        h_g.zeroize();
        alp.zeroize();
        t_base.zeroize();

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

    /// Decrypt a message that was encrypted with this Proxy Re-Encryptor
    pub fn self_decrypt(&self, msg: &EncryptedMessage) -> Vec<u8> {
        let alp: Scalar = Scalar::hash_from_bytes::<Sha512>(
            &[&msg.tag, self.secret.to_scalar().as_bytes().as_slice()].concat(),
        );

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
        let mut h: Scalar = scalar_from_256_hash(
            &[
                msg.tag.as_slice(),
                self.secret.to_scalar().as_bytes().as_slice(),
            ]
            .concat(),
        );
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

    /// Generate a Re-Key for a given public key and tag
    pub fn generate_re_key(&self, public_key: &[u8; 32], tag: &[u8]) -> ReKey {
        let p: EdwardsPoint = curve25519_dalek::edwards::CompressedEdwardsY(*public_key)
            .decompress()
            .unwrap(); // self.curve.pointFromBuffer(publicKey);

        let mut csprng = OsRng;

        let r: Scalar = Scalar::hash_from_bytes::<Sha512>(Scalar::random(&mut csprng).as_bytes());
        let h: Scalar =
            scalar_from_256_hash(&[tag, self.secret.to_scalar().as_bytes().as_slice()].concat());

        let r3_scalar: Scalar = Scalar::hash_from_bytes::<Sha512>(
            &[tag, self.secret.to_scalar().as_bytes().as_slice()].concat(),
        ); // sha512

        ReKey {
            r_1: constants::ED25519_BASEPOINT_POINT
                .mul(r.sub(h))
                .compress()
                .to_bytes(), //  rG - hG
            r_2: p.mul(r).compress().to_bytes(), //  rP = rxG
            r_3: r3_scalar.to_bytes(),
        }
    }

    /// Decrypt a message that was re-encrypted with this Proxy Re-Encryptor
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

        let tx_g = d_5.mul(self.secret.to_scalar()); //  x * D5 = x * tG

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
        let mut t_2 = d_4.mul(self.secret.to_scalar().invert());
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

/// Allows any entity holding a [ReKey] to Re-Encrypt a message with a given [ReKey] for a given public key
pub fn re_encrypt(
    public_key: &[u8; 32],
    msg: EncryptedMessage,
    re_key: &ReKey,
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

    let mut csprng = OsRng;
    let t: Scalar = Scalar::hash_from_bytes::<Sha512>(Scalar::random(&mut csprng).as_bytes());

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

pub fn generate_keypair() -> SigningKey {
    let mut csprng = OsRng;
    SigningKey::generate(&mut csprng)
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
        let data = hex_literal::hex!("deadbeef");
        let tag = b"The TAG";

        let encrypted_message = alice_pre.self_encrypt(&data, tag);
        let decrypted_message = alice_pre.self_decrypt(&encrypted_message);
        assert_eq!(data, decrypted_message.as_slice());

        //  `alice` re-keys the file to allow for `bob` to access the data
        let re_key = alice_pre.generate_re_key(&bob_keypair.verifying_key().to_bytes(), tag);

        //  `proxy` re-encrypts it for `bob`
        let re_encrypted_message = re_encrypt(
            &bob_keypair.verifying_key().to_bytes(),
            encrypted_message,
            &re_key,
        );

        //  `bob` decrypts it
        let data_2 = bob_pre.re_decrypt(&re_encrypted_message);
        assert_eq!(data, data_2.as_slice());

        // if I change the data but keep the tag the same, we can re-use the re_key
        let new_data = hex_literal::hex!("cafebabe");

        let encrypted_message = alice_pre.self_encrypt(&new_data, tag);
        let decrypted_message = alice_pre.self_decrypt(&encrypted_message);
        assert_eq!(new_data, decrypted_message.as_slice());

        //  `proxy` re-encrypts it for `bob`
        let re_encrypted_message = re_encrypt(
            &bob_keypair.verifying_key().to_bytes(),
            encrypted_message,
            &re_key,
        );

        //  `bob` decrypts it since it has the same tag
        let data_3 = bob_pre.re_decrypt(&re_encrypted_message);
        assert_eq!(new_data, data_3.as_slice());
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
