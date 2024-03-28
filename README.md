# Recrypted

## Transform Re-encryption (Homomorphic Encryption)

Transform Re-encryption is a homomorphic encryption scheme that allows users to transform ciphertexts from one key to another without decrypting the ciphertexts. This is useful for delegating decryption rights to other users, or for changing the encryption key without re-encrypting all the data.

Written in 100% pure `Rust`.

Workspace composed of:

- [x] [recrypted-core](crates/recrypted-core/README.md) - The core library for the Transform Re-encryption scheme.
- [x] [recrypted-component](crates/recrypted-component/README.md) - The bindings for [Wasm Interface Types Component](https://component-model.bytecodealliance.org/introduction.html) so the core library can be run anywhere [`wasmtime`](https://github.com/bytecodealliance/wasmtime) runs (Rust, JS, ...)

