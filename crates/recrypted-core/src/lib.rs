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

/// Errors from malformed, tampered or mismatched inputs.
///
/// Ciphertexts, re-keys and public keys often come from untrusted parties (for example
/// a storage host or a proxy), so none of the operations in this crate panic on bad input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// 32 bytes that are not a valid compressed Edwards point.
    InvalidPoint,
    /// A checksum did not match: the message was modified, or the re-key or secret key
    /// does not correspond to the message's tag.
    ChecksumMismatch,
    /// Symmetric encryption failed.
    Encryption,
    /// Symmetric decryption failed (wrong key or modified ciphertext).
    Decryption,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::InvalidPoint => "invalid curve point",
            Error::ChecksumMismatch => "checksum mismatch",
            Error::Encryption => "encryption failed",
            Error::Decryption => "decryption failed",
        })
    }
}

impl std::error::Error for Error {}

/// Lets string-error boundaries (such as the wasm component's `result<_, string>`) use `?`.
impl From<Error> for String {
    fn from(error: Error) -> Self {
        error.to_string()
    }
}

fn decompress(bytes: &[u8; 32]) -> Result<EdwardsPoint, Error> {
    curve25519_dalek::edwards::CompressedEdwardsY(*bytes)
        .decompress()
        .ok_or(Error::InvalidPoint)
}

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
    pub fn self_encrypt(&self, msg: &[u8], tag: &[u8]) -> Result<EncryptedMessage, Error> {
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
        let encrypted_data = sym_encrypt(&key, msg);

        let mut message_checksum: Vec<u8> = Vec::default();

        message_checksum.extend(sha2::Sha512::digest([msg, t_bytes.as_ref()].concat()));

        let mut alp: Scalar =
            Scalar::hash_from_bytes::<Sha512>(&[tag, self.secret.to_scalar().as_bytes()].concat());

        let prep_checksum = [
            &encrypted_key, // slice of a [u8]
            encrypted_data.as_deref().unwrap_or_default(),
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

        // Zeroized above, so fail only now.
        let encrypted_data = encrypted_data.ok_or(Error::Encryption)?;

        let mut overall_checksum: Vec<u8> = Vec::default();
        overall_checksum.extend(&sha2::Sha512::digest(prep_checksum.as_slice()));

        Ok(EncryptedMessage {
            tag: tag.to_vec(),
            encrypted_key,
            encrypted_data,
            message_checksum,
            overall_checksum,
        })
    }

    /// Decrypt a message that was encrypted with this Proxy Re-Encryptor
    pub fn self_decrypt(&self, msg: &EncryptedMessage) -> Result<Vec<u8>, Error> {
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

        if overall_checksum != msg.overall_checksum {
            return Err(Error::ChecksumMismatch);
        }
        let encrypted_key = decompress(&msg.encrypted_key)?;

        // hash1
        let mut h: Scalar = scalar_from_256_hash(
            &[
                msg.tag.as_slice(),
                self.secret.to_scalar().as_bytes().as_slice(),
            ]
            .concat(),
        );
        let mut h_g: EdwardsPoint = constants::ED25519_BASEPOINT_POINT.mul(h);

        let t_bytes = Zeroizing::new(encrypted_key.sub(h_g).compress().to_bytes());

        let mut key: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        key.extend(&sha2::Sha256::digest(&t_bytes));
        let data = sym_decrypt(&key, &msg.encrypted_data);

        // hash3
        // check2
        let mut message_checksum: Vec<u8> = Vec::default();
        message_checksum.extend(sha2::Sha512::digest(
            [data.as_deref().unwrap_or_default(), t_bytes.as_slice()].concat(),
        ));

        h.zeroize();
        h_g.zeroize();
        drop(key);
        drop(t_bytes);

        let data = data.ok_or(Error::Decryption)?;
        if message_checksum != msg.message_checksum {
            return Err(Error::ChecksumMismatch);
        }

        Ok(data)
    }

    /// Generate a Re-Key for a given public key and tag
    pub fn generate_re_key(&self, public_key: &[u8; 32], tag: &[u8]) -> Result<ReKey, Error> {
        let p: EdwardsPoint = decompress(public_key)?;

        let mut csprng = OsRng;

        let r: Scalar = Scalar::hash_from_bytes::<Sha512>(Scalar::random(&mut csprng).as_bytes());
        let h: Scalar =
            scalar_from_256_hash(&[tag, self.secret.to_scalar().as_bytes().as_slice()].concat());

        let r3_scalar: Scalar = Scalar::hash_from_bytes::<Sha512>(
            &[tag, self.secret.to_scalar().as_bytes().as_slice()].concat(),
        ); // sha512

        Ok(ReKey {
            r_1: constants::ED25519_BASEPOINT_POINT
                .mul(r.sub(h))
                .compress()
                .to_bytes(), //  rG - hG
            r_2: p.mul(r).compress().to_bytes(), //  rP = rxG
            r_3: r3_scalar.to_bytes(),
        })
    }

    /// Decrypt a message that was re-encrypted with this Proxy Re-Encryptor
    pub fn re_decrypt(&self, d: &ReEncryptedMessage) -> Result<Vec<u8>, Error> {
        let d_1: EdwardsPoint = decompress(&d.d_1)?;
        let d_4: EdwardsPoint = decompress(&d.d_4)?;
        let d_5: EdwardsPoint = decompress(&d.d_5)?;

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
        let data = sym_decrypt(&key, &d.d_2);

        drop(key);

        // hash 3
        let check_2 = sha2::Sha512::digest(
            [data.as_deref().unwrap_or_default(), t_bytes.as_slice()].concat(),
        )
        .to_vec();

        t_bytes.zeroize();
        t_2.zeroize();

        let data = data.ok_or(Error::Decryption)?;
        if !check_2.eq(&d.d_3) {
            return Err(Error::ChecksumMismatch);
        }

        Ok(data)
    }
}

/// Allows any entity holding a [ReKey] to Re-Encrypt a message with a given [ReKey] for a given public key
pub fn re_encrypt(
    public_key: &[u8; 32],
    msg: EncryptedMessage,
    re_key: &ReKey,
) -> Result<ReEncryptedMessage, Error> {
    let prep_checksum = [
        &msg.encrypted_key,
        msg.encrypted_data.as_slice(),
        msg.message_checksum.as_slice(),
        &re_key.r_3,
    ]
    .concat();

    let check_1 = sha2::Sha512::digest(prep_checksum.as_slice()).to_vec();

    // Also fails when `re_key` was issued for a different tag than `msg`'s.
    if !check_1.eq(&msg.overall_checksum) {
        return Err(Error::ChecksumMismatch);
    }

    let p: EdwardsPoint = decompress(public_key)?;
    let r_1: EdwardsPoint = decompress(&re_key.r_1)?;
    let msg_key: EdwardsPoint = decompress(&msg.encrypted_key)?;

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

    let encrypted_key = msg_key.add(r_1);

    let d_1 = encrypted_key.mul(bet).compress().to_bytes();

    Ok(ReEncryptedMessage {
        d_1,
        d_2,
        d_3,
        d_4,
        d_5,
    })
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

    const TAG: &[u8] = b"The TAG";

    fn bob() -> (SigningKey, Pre) {
        let keypair = generate_keypair();
        let pre = Pre::new(Zeroizing::new(keypair.to_bytes()));
        (keypair, pre)
    }

    #[test]
    pub(super) fn test_recrypt() {
        //  `alice` create new proxy re-encryptor
        let alice_pre = Pre::default();

        // BOB
        let (bob_keypair, bob_pre) = bob();
        let bob_public = bob_keypair.verifying_key().to_bytes();

        //  `alice` self-encrypts data with a tag
        let data = hex_literal::hex!("deadbeef");

        let encrypted_message = alice_pre.self_encrypt(&data, TAG).unwrap();
        let decrypted_message = alice_pre.self_decrypt(&encrypted_message).unwrap();
        assert_eq!(data, decrypted_message.as_slice());

        //  `alice` re-keys the file to allow for `bob` to access the data
        let re_key = alice_pre.generate_re_key(&bob_public, TAG).unwrap();

        //  whoever hold the re_key for Bob's publicKey (such as a `proxy` or even Bob himself) can re-encrypt it
        let re_encrypted_message = re_encrypt(&bob_public, encrypted_message, &re_key).unwrap();

        //  `bob` decrypts it
        let data_2 = bob_pre.re_decrypt(&re_encrypted_message).unwrap();
        assert_eq!(data, data_2.as_slice());

        // if I change the data but keep the tag the same, we can re-use the re_key
        let new_data = hex_literal::hex!("cafebabe");

        let encrypted_message = alice_pre.self_encrypt(&new_data, TAG).unwrap();
        let decrypted_message = alice_pre.self_decrypt(&encrypted_message).unwrap();
        assert_eq!(new_data, decrypted_message.as_slice());

        //  `proxy` re-encrypts it for `bob`
        let re_encrypted_message = re_encrypt(&bob_public, encrypted_message, &re_key).unwrap();

        //  `bob` decrypts it since it has the same tag
        let data_3 = bob_pre.re_decrypt(&re_encrypted_message).unwrap();
        assert_eq!(new_data, data_3.as_slice());
    }

    /// A 32-byte string that is not a valid compressed Edwards point (about half of all
    /// `y` values have no matching `x`), found deterministically.
    fn bad_point() -> [u8; 32] {
        (0..=u8::MAX)
            .map(|first| {
                let mut bytes = [0u8; 32];
                bytes[0] = first;
                bytes[1] = 1;
                bytes
            })
            .find(|bytes| decompress(bytes).is_err())
            .expect("some y value is not on the curve")
    }

    #[test]
    fn generate_re_key_rejects_invalid_public_key() {
        let alice = Pre::default();
        assert_eq!(
            alice.generate_re_key(&bad_point(), TAG).unwrap_err(),
            Error::InvalidPoint
        );
    }

    #[test]
    fn re_encrypt_rejects_invalid_public_key() {
        let alice = Pre::default();
        let (bob_keypair, _) = bob();
        let bob_public = bob_keypair.verifying_key().to_bytes();
        let msg = alice.self_encrypt(b"data", TAG).unwrap();
        let re_key = alice.generate_re_key(&bob_public, TAG).unwrap();
        assert_eq!(
            re_encrypt(&bad_point(), msg, &re_key).unwrap_err(),
            Error::InvalidPoint
        );
    }

    #[test]
    fn re_encrypt_rejects_re_key_for_another_tag() {
        let alice = Pre::default();
        let (bob_keypair, _) = bob();
        let bob_public = bob_keypair.verifying_key().to_bytes();
        let msg = alice.self_encrypt(b"data", TAG).unwrap();
        let other_tag_key = alice.generate_re_key(&bob_public, b"other tag").unwrap();
        assert_eq!(
            re_encrypt(&bob_public, msg, &other_tag_key).unwrap_err(),
            Error::ChecksumMismatch
        );
    }

    #[test]
    fn re_encrypt_rejects_re_key_from_another_owner() {
        let alice = Pre::default();
        let mallory = Pre::default();
        let (bob_keypair, _) = bob();
        let bob_public = bob_keypair.verifying_key().to_bytes();
        let msg = alice.self_encrypt(b"data", TAG).unwrap();
        let forged = mallory.generate_re_key(&bob_public, TAG).unwrap();
        assert_eq!(
            re_encrypt(&bob_public, msg, &forged).unwrap_err(),
            Error::ChecksumMismatch
        );
    }

    #[test]
    fn re_encrypt_rejects_malformed_message_points() {
        let alice = Pre::default();
        let (bob_keypair, _) = bob();
        let bob_public = bob_keypair.verifying_key().to_bytes();
        let re_key = alice.generate_re_key(&bob_public, TAG).unwrap();

        // Bad `encrypted_key`: checksum covers it, so recompute the way a forger would.
        let mut msg = alice.self_encrypt(b"data", TAG).unwrap();
        msg.encrypted_key = bad_point();
        assert!(re_encrypt(&bob_public, msg, &re_key).is_err());

        // Bad `r_1` in the re-key.
        let msg = alice.self_encrypt(b"data", TAG).unwrap();
        let bad_re_key = ReKey::default()
            .with_r_1(&bad_point())
            .with_r_2(&re_key.r_2())
            .with_r_3(&re_key.r_3());
        assert_eq!(
            re_encrypt(&bob_public, msg, &bad_re_key).unwrap_err(),
            Error::InvalidPoint
        );
    }

    #[test]
    fn self_decrypt_rejects_tampering() {
        let alice = Pre::default();
        let msg = alice.self_encrypt(b"some data", TAG).unwrap();

        let mut data = EncryptedMessage::default()
            .with_tag(msg.tag())
            .with_encrypted_key(&msg.encrypted_key())
            .with_encrypted_data(msg.encrypted_data())
            .with_message_checksum(msg.message_checksum())
            .with_overall_checksum(msg.overall_checksum());
        data.encrypted_data[0] ^= 1;
        assert_eq!(
            alice.self_decrypt(&data).unwrap_err(),
            Error::ChecksumMismatch
        );

        let wrong_tag = EncryptedMessage::default()
            .with_tag(b"other")
            .with_encrypted_key(&msg.encrypted_key())
            .with_encrypted_data(msg.encrypted_data())
            .with_message_checksum(msg.message_checksum())
            .with_overall_checksum(msg.overall_checksum());
        assert!(alice.self_decrypt(&wrong_tag).is_err());

        // A different owner cannot open it.
        assert!(Pre::default().self_decrypt(&msg).is_err());
    }

    #[test]
    fn self_decrypt_rejects_default_and_garbage_messages() {
        let alice = Pre::default();
        assert!(alice.self_decrypt(&EncryptedMessage::default()).is_err());

        let garbage = EncryptedMessage::default()
            .with_tag(TAG)
            .with_encrypted_key(&bad_point())
            .with_encrypted_data(&[1, 2, 3])
            .with_message_checksum(&[4, 5])
            .with_overall_checksum(&[6]);
        assert!(alice.self_decrypt(&garbage).is_err());
    }

    #[test]
    fn re_decrypt_rejects_invalid_points_and_garbage() {
        let (_, bob_pre) = bob();
        // All-zero points decode, so this fails later, at decryption.
        assert!(bob_pre.re_decrypt(&ReEncryptedMessage::default()).is_err());

        let garbage = ReEncryptedMessage::default()
            .with_d_1(&bad_point())
            .with_d_2(&[1, 2, 3])
            .with_d_3(&[4])
            .with_d_4(&bad_point())
            .with_d_5(&bad_point());
        assert_eq!(
            bob_pre.re_decrypt(&garbage).unwrap_err(),
            Error::InvalidPoint
        );
    }

    #[test]
    fn re_decrypt_rejects_tampering_and_wrong_reader() {
        let alice = Pre::default();
        let (bob_keypair, bob_pre) = bob();
        let (_, carol_pre) = bob();
        let bob_public = bob_keypair.verifying_key().to_bytes();

        let msg = alice.self_encrypt(b"secret", TAG).unwrap();
        let re_key = alice.generate_re_key(&bob_public, TAG).unwrap();
        let re_encrypted = re_encrypt(&bob_public, msg, &re_key).unwrap();

        // Someone other than the intended reader cannot open it.
        assert!(carol_pre.re_decrypt(&re_encrypted).is_err());

        // Modified ciphertext is rejected.
        let mut d_2 = re_encrypted.d_2().to_vec();
        d_2[0] ^= 1;
        let tampered = ReEncryptedMessage::default()
            .with_d_1(&re_encrypted.d_1())
            .with_d_2(&d_2)
            .with_d_3(re_encrypted.d_3())
            .with_d_4(&re_encrypted.d_4())
            .with_d_5(&re_encrypted.d_5());
        assert!(bob_pre.re_decrypt(&tampered).is_err());

        // The untouched message still works.
        assert_eq!(bob_pre.re_decrypt(&re_encrypted).unwrap(), b"secret");
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
