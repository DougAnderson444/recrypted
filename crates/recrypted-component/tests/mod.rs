//! A module to test the recrypted component.
mod bindgen {
    // name of the world in the .wit file
    wasmtime::component::bindgen!("recryptor");
}

use std::{
    env,
    path::{Path, PathBuf},
};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiView};

struct MyCtx {
    table: ResourceTable,
    wasi: WasiCtx,
}

impl WasiView for MyCtx {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi
    }
}

/// Utility function to get the workspace dir
pub fn workspace_dir() -> PathBuf {
    let output = std::process::Command::new(env!("CARGO"))
        .arg("locate-project")
        .arg("--workspace")
        .arg("--message-format=plain")
        .output()
        .unwrap()
        .stdout;
    let cargo_path = Path::new(std::str::from_utf8(&output).unwrap().trim());
    cargo_path.parent().unwrap().to_path_buf()
}

#[cfg(test)]
mod wit_tests {

    use rand_core::OsRng;
    use recrypted_core::SigningKey;

    use super::*;

    #[test]
    fn test_roundtrip() {
        let pkg_name = std::env::var("CARGO_PKG_NAME").unwrap().replace('-', "_");
        let workspace = workspace_dir();
        let wasm_path = format!("target/wasm32-wasi/debug/{}.wasm", pkg_name);
        let wasm_path = workspace.join(wasm_path);

        let mut config = Config::new();
        config.cache_config_load_default().unwrap();
        config.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Enable);
        config.wasm_component_model(true);

        let engine = Engine::new(&config).unwrap();
        let component = Component::from_file(&engine, wasm_path).unwrap();

        let mut linker = Linker::new(&engine);
        // link imports like get_seed to our instantiation
        // bindgen::Recryptor::add_to_linker(&mut linker, |state: &mut MyCtx| state).unwrap();
        // link the WASI imports to our instantiation
        wasmtime_wasi::command::sync::add_to_linker(&mut linker).unwrap();

        let table = ResourceTable::new();
        let wasi: WasiCtx = WasiCtxBuilder::new().inherit_stdout().args(&[""]).build();
        let state = MyCtx { table, wasi };

        let mut store = Store::new(&engine, state);

        let (bindings, _) =
            bindgen::Recryptor::instantiate(&mut store, &component, &linker).unwrap();

        // use bindings to self_encrypt and self_decrypt
        let data = b"Hello, World!".to_vec();
        let tag = b"tag".to_vec();
        let signing_key = SigningKey::generate(&mut OsRng);

        let provider = bindings
            .component_recrypted_provider()
            .recrypt()
            .call_constructor(&mut store, signing_key.as_bytes())
            .unwrap();

        let encr_msg = bindings
            .component_recrypted_provider()
            .recrypt()
            .call_self_encrypt(&mut store, provider, &data, &tag)
            .unwrap();

        let decrypted_msg = bindings
            .component_recrypted_provider()
            .recrypt()
            .call_self_decrypt(&mut store, provider, &encr_msg)
            .unwrap()
            .unwrap();

        assert_eq!(data, decrypted_msg);

        // Now let proxy re-encrypt the message for Bob
        let bob = SigningKey::generate(&mut OsRng);

        // generate a ReKey for this tag
        let re_key = bindings
            .component_recrypted_provider()
            .recrypt()
            .call_generate_re_key(
                &mut store,
                provider,
                bob.verifying_key().as_bytes().as_slice(),
                &tag,
            )
            .unwrap()
            .unwrap();

        let re_encr_msg = bindings
            .component_recrypted_proxy()
            .call_re_encrypt(
                &mut store,
                bob.verifying_key().as_bytes(),
                &encr_msg,
                &re_key,
            )
            .unwrap()
            .unwrap();

        // Now let Bob decrypt the message
        let bob_provider = bindings
            .component_recrypted_provider()
            .recrypt()
            .call_constructor(&mut store, bob.as_bytes())
            .unwrap();

        let bob_decrypted_msg = bindings
            .component_recrypted_provider()
            .recrypt()
            .call_re_decrypt(&mut store, bob_provider, &re_encr_msg)
            .unwrap()
            .unwrap();

        assert_eq!(data, bob_decrypted_msg);
    }
}
