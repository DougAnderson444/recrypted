# Recrypted-Core

The core library for the Recrypted project.

## Usage

```rust
use recrypted_core::*;
use secrecy::zeroize::Zeroizing;

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
assert_eq!(data, &decrypted_message[..]);

//  `alice` re-keys the file to allow for `bob` to access the data
let re_key = alice_pre.generate_re_key(&bob_keypair.verifying_key().to_bytes(), tag);

//  `proxy` re-encrypts it for `bob`
let re_encrypted_message = re_encrypt(
    &bob_keypair.verifying_key().to_bytes(),
    encrypted_message,
    re_key,
); // bob, res, reKey, curve

//  `bob` decrypts it
let data_2 = bob_pre.re_decrypt(&re_encrypted_message);
assert_eq!(data, data_2.as_slice());
```

## [Tests](https://doc.rust-lang.org/cargo/commands/cargo-test.html)

Using [just](https://just.systems/):

```bash
just test
```

Or, using cargo:

```bash
cargo test
```

For wasm-bindgen tests:

```bash
wasm-pack test --node
```

## References

Self-Encryption/Proxy Re-encryption

This is an implementation of the SE-PRE scheme of
"Sharing of Encrypted files in Blockchain Made Simpler" (https://eprint.iacr.org/2019/418.pdf),
compatible with the implementation in `https://github.com/0chain/gosdk`

> Proxy re–encryption schemes are cryptosystems which allow third parties (proxies) to alter a ciphertext which has been encrypted for one party, so that it may be decrypted by another.
