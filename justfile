test:
  cd crates/recrypted-core && wasm-pack test --node
  cargo test --all-features --all-targets
