//! UniTether GUI backend: Tauri commands bridging the unilink core
//! crates (discovery, pairing, tunnel, proxy) to the Svelte front-end.

mod devices;
mod session;

use std::sync::Mutex;
use tauri::State;

pub struct AppState {
    pub session: Mutex<session::Session>,
}

#[tauri::command]
fn list_devices(state: State<AppState>) -> Result<Vec<devices::DeviceInfo>, String> {
    devices::scan(&state)
}

#[tauri::command]
fn connect(
    state: State<AppState>,
    address: String,
    port: u16,
    pair_blob: Option<String>,
) -> Result<String, String> {
    let mut s = state.session.lock().map_err(|e| e.to_string())?;
    s.connect(&address, port, pair_blob.as_deref())
}

#[tauri::command]
fn disconnect(state: State<AppState>) -> Result<(), String> {
    let mut s = state.session.lock().map_err(|e| e.to_string())?;
    s.disconnect()
}

#[tauri::command]
fn tunnel_config(
    state: State<AppState>,
    ipv4: bool,
    ipv6: bool,
    dns_v4: String,
    custom_dns: Vec<String>,
) -> Result<(), String> {
    let s = state.session.lock().map_err(|e| e.to_string())?;
    s.update_tunnel(ipv4, ipv6, &dns_v4, &custom_dns)
}

#[tauri::command]
fn proxy_config(
    state: State<AppState>,
    http: Option<String>,
    socks: Option<String>,
    bypass: Vec<String>,
) -> Result<(), String> {
    let s = state.session.lock().map_err(|e| e.to_string())?;
    s.update_proxy(http, socks, bypass)
}

#[tauri::command]
fn get_stats(state: State<AppState>) -> Result<serde_json::Value, String> {
    let s = state.session.lock().map_err(|e| e.to_string())?;
    Ok(serde_json::to_value(s.stats())?)
}

#[tauri::command]
fn get_pairing(state: State<AppState>) -> Result<String, String> {
    let s = state.session.lock().map_err(|e| e.to_string())?;
    Ok(s.pairing_blob())
}

#[tauri::command]
fn set_language(_app: tauri::AppHandle, _lang: String) -> Result<(), String> {
    // Front-end driven i18n; persisted via tauri-plugin-store on disk.
    Ok(())
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState { session: Mutex::new(session::Session::new()) })
        .invoke_handler(tauri::generate_handler![
            list_devices, connect, disconnect, tunnel_config, proxy_config,
            get_stats, get_pairing, set_language
        ])
        .setup(|app, _handle| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory)
                .ok();
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running UniTether GUI");
}
