# Recrypted

Encrypt and decrypt your data using your Ed25519 keypair. Uses transform encryption to that allows others to access the data without decrypting it in the access process. Allow a semi-trusted third party to re-encypt the keys on your behalf without that 3rd party ever seeing the plaintext data.

## Why?

- **Privacy**: Only you or your delegates can decrypt your data.
- **Key Management**: Symmetric keys are deterministically derived from your Ed25519 key. One key ot rule them all.
- **Secure Sharing**: Share your data with others without exposing the plaintext first
- **Secure Delegation**: Allow others to gate access without giving them the ability to decrypt it.

For example, say you want a server to allow access to a file for certain users only under certain conditions (payment, time, etc.). You can set your re-encryption policy to only issue the re-encrypted key if those conditions are met.

Re-encryption is based on a `tag`, so you can grant access to a series of files by using the same tag for all of them.

## Transform Re-encryption (Homomorphic Encryption)

Transform Re-encryption is a homomorphic encryption scheme that allows users to transform ciphertexts from one key to another without decrypting the ciphertexts. This is useful for delegating decryption rights to other users, or for changing the encryption key without re-encrypting all the data.

## Rust Workspace

Written in 100% pure `Rust`.

Workspace composed of:

- [x] [recrypted-core](crates/recrypted-core/README.md) - The core library for the Transform Re-encryption scheme.
- [x] [recrypted-component](crates/recrypted-component/README.md) - The bindings for [Wasm Interface Types Component](https://component-model.bytecodealliance.org/introduction.html) so the core library can be run anywhere [`wasmtime`](https://github.com/bytecodealliance/wasmtime) runs (Rust, JS, ...)

