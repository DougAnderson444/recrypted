#[allow(warnings)]
mod bindings;

use bindings::exports::component::recrypted::provider::ReKey;
use bindings::exports::component::recrypted::provider::{
    EncryptedMessage, Guest, GuestRecrypt, ReEncryptedMessage,
};
use bindings::exports::component::recrypted::proxy::Guest as ProxyGuest;

use recrypted_core::{Pre, Zeroizing};
use std::cell::RefCell;

struct Component {
    recryptor: RefCell<Pre>,
}

bindings::export!(Component with_types_in bindings);

impl Guest for Component {
    type Recrypt = Self;
}

/// Copy `bytes` into a 32-byte array, naming `what` in the error.
fn bytes32(bytes: &[u8], what: &str) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| format!("{what} is not 32 bytes"))
}

impl ProxyGuest for Component {
    /// Re-encrypt the data for the given public key with the given re-encription key.
    fn re_encrypt(
        public_key: Vec<u8>,
        data: EncryptedMessage,
        re_key: ReKey,
    ) -> Result<ReEncryptedMessage, String> {
        let public_key = bytes32(&public_key, "Public key")?;
        Ok(recrypted_core::re_encrypt(&public_key, data.try_into()?, &re_key.try_into()?)?.into())
    }
}

impl GuestRecrypt for Component {
    /// Creates a new Proxcryptor instance.
    fn new(secret: Vec<u8>) -> Self {
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(secret.as_slice());

        Component {
            recryptor: RefCell::new(Pre::new(bytes)),
        }
    }

    /// Self-encrypt the data.
    fn self_encrypt(&self, data: Vec<u8>, tag: Vec<u8>) -> Result<EncryptedMessage, String> {
        Ok(self.recryptor.borrow().self_encrypt(&data, &tag)?.into())
    }

    /// Self-decrypt the data.
    fn self_decrypt(&self, data: EncryptedMessage) -> Result<Vec<u8>, String> {
        Ok(self.recryptor.borrow().self_decrypt(&data.try_into()?)?)
    }

    /// Generate a re-encription key.
    fn generate_re_key(&self, recipient: Vec<u8>, tag: Vec<u8>) -> Result<ReKey, String> {
        let recipient = bytes32(&recipient, "Public key")?;
        Ok(self
            .recryptor
            .borrow()
            .generate_re_key(&recipient, &tag)?
            .into())
    }

    /// Re-decrypt the ReEncryptedMessage.
    fn re_decrypt(&self, data: ReEncryptedMessage) -> Result<Vec<u8>, String> {
        Ok(self.recryptor.borrow().re_decrypt(&data.try_into()?)?)
    }
}

impl From<recrypted_core::EncryptedMessage> for EncryptedMessage {
    fn from(message: recrypted_core::EncryptedMessage) -> Self {
        Self {
            tag: message.tag().to_vec(),
            encrypted_key: message.encrypted_key().to_vec(),
            encrypted_data: message.encrypted_data().to_vec(),
            message_checksum: message.message_checksum().to_vec(),
            overall_checksum: message.overall_checksum().to_vec(),
        }
    }
}

impl TryFrom<EncryptedMessage> for recrypted_core::EncryptedMessage {
    type Error = String;

    fn try_from(value: EncryptedMessage) -> Result<Self, Self::Error> {
        Ok(recrypted_core::EncryptedMessage::default()
            .with_tag(&value.tag)
            .with_encrypted_key(&bytes32(&value.encrypted_key, "encrypted_key")?)
            .with_encrypted_data(&value.encrypted_data)
            .with_message_checksum(&value.message_checksum)
            .with_overall_checksum(&value.overall_checksum))
    }
}

impl From<recrypted_core::ReKey> for ReKey {
    fn from(re_key: recrypted_core::ReKey) -> Self {
        Self {
            r_one: re_key.r_1().to_vec(),
            r_two: re_key.r_2().to_vec(),
            r_three: re_key.r_3().to_vec(),
        }
    }
}

impl TryFrom<ReKey> for recrypted_core::ReKey {
    type Error = String;

    fn try_from(value: ReKey) -> Result<Self, Self::Error> {
        Ok(recrypted_core::ReKey::default()
            .with_r_1(&bytes32(&value.r_one, "r_1")?)
            .with_r_2(&bytes32(&value.r_two, "r_2")?)
            .with_r_3(&bytes32(&value.r_three, "r_3")?))
    }
}

impl From<recrypted_core::ReEncryptedMessage> for ReEncryptedMessage {
    fn from(message: recrypted_core::ReEncryptedMessage) -> Self {
        Self {
            d_one: message.d_1().to_vec(),
            d_two: message.d_2().to_vec(),
            d_three: message.d_3().to_vec(),
            d_four: message.d_4().to_vec(),
            d_five: message.d_5().to_vec(),
        }
    }
}

impl TryFrom<ReEncryptedMessage> for recrypted_core::ReEncryptedMessage {
    type Error = String;

    fn try_from(value: ReEncryptedMessage) -> Result<Self, Self::Error> {
        Ok(recrypted_core::ReEncryptedMessage::default()
            .with_d_1(&bytes32(&value.d_one, "d_1")?)
            .with_d_2(&value.d_two)
            .with_d_3(&value.d_three)
            .with_d_4(&bytes32(&value.d_four, "d_4")?)
            .with_d_5(&bytes32(&value.d_five, "d_5")?))
    }
}
