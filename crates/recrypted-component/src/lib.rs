#[allow(warnings)]
mod bindings;

use crate::bindings::exports::component::recrypted::provider::{
    EncryptedMessage, Guest, GuestRecrypt,
};
use recrypted_core::{Pre, Zeroizing};
use std::cell::RefCell;

struct Component {
    recryptor: RefCell<Pre>,
}

bindings::export!(Component with_types_in bindings);

impl Guest for Component {
    type Recrypt = Self;
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
    fn self_encrypt(&self, data: Vec<u8>, tag: Vec<u8>) -> EncryptedMessage {
        self.recryptor.borrow().self_encrypt(&data, &tag).into()
    }

    /// Self-decrypt the data.
    fn self_decrypt(&self, data: EncryptedMessage) -> Result<Vec<u8>, String> {
        Ok(self
            .recryptor
            .borrow()
            .self_decrypt(&(data.try_into().map_err(|_| "Invalid Encrypted Message")?)))
    }
}

impl From<recrypted_core::EncryptedMessage> for EncryptedMessage {
    fn from(message: recrypted_core::EncryptedMessage) -> Self {
        Self {
            tag: message.tag,
            encrypted_key: message.encrypted_key.to_vec(),
            encrypted_data: message.encrypted_data,
            message_checksum: message.message_checksum,
            overall_checksum: message.overall_checksum,
        }
    }
}

impl TryFrom<EncryptedMessage> for recrypted_core::EncryptedMessage {
    type Error = ();

    fn try_from(value: EncryptedMessage) -> Result<Self, Self::Error> {
        Ok(Self {
            tag: value.tag,
            encrypted_key: value.encrypted_key.try_into().map_err(|_| ())?,
            encrypted_data: value.encrypted_data,
            message_checksum: value.message_checksum,
            overall_checksum: value.overall_checksum,
        })
    }
}
