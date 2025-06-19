test: test-component
  cd crates/recrypted-core && wasm-pack test --node
  cargo test --all-features --all-targets

test-component:
  cd crates/recrypted-component && cargo component build
  cargo test
