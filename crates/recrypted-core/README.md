# Recrypted-Core

The core library for the Recrypted project.

## Usage

```rust
    use recrypted_core::*;

    //  `alice` create new proxy re-encryptor
    let alice_pre = Pre::default();

    // BOB
    let bob_keypair = generate_keypair();
    //  `bob` creates to DE-encrypt
    let bob_pre = Pre::new(&bob_keypair.to_bytes());

    // check to see if match
    assert_eq!(
        bob_pre.p.compress().to_bytes(),
        bob_keypair.verifying_key().to_bytes()
    );

    //  `alice` self-encrypts data with a tag
    let data =
        hex_literal::hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let tag = b"TAG";

    let encrypted_message = alice_pre.self_encrypt(&data, tag);
    let decrypted_message = alice_pre.self_decrypt(&encrypted_message);
    assert_eq!(data, &decrypted_message[..]);

    //  `alice` re-keys the file to allow for `bob` to access the data
    let re_key = alice_pre.generate_re_key(&bob_keypair.verifying_key().to_bytes(), tag);

    //  `proxy` re-encrypts it for `bob`
    let re_encrypted_message =
        Pre::re_encrypt(&bob_keypair.verifying_key().to_bytes(), encrypted_message, re_key); // bob, res, reKey, curve

    //  `bob` decrypts it
    let data_2 = bob_pre.re_decrypt(&re_encrypted_message);
    assert_eq!(data, &data_2[..]);
```

## Tests

```bash
cargo test
```

wasm-bindgen tests

```bash
wasm-pack test --node
```

