#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::io::Write;
use tauri::{Manager, Emitter, Runtime, State, AppHandle, WindowEvent};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::async_runtime::{self, Mutex};
use tokio::process::{Child, Command};
use tokio::io::{AsyncBufReadExt, BufReader};
use serde::{Serialize, Deserialize};

// Autostart plugin
use tauri_plugin_autostart::MacosLauncher;
use tauri_plugin_autostart::ManagerExt;
use tauri_plugin_dialog::DialogExt;

struct AppState {
    agent_process: Arc<Mutex<Option<Child>>>,
    is_connected: Arc<AtomicBool>,
    agent_alive: Arc<AtomicBool>,
    /// Set to true when the agent logs "handshake complete" (real WS connection).
    ws_connected: Arc<AtomicBool>,
    /// Set to true when the agent detects another daemon is already running.
    existing_daemon: Arc<AtomicBool>,
    first_connection_registered: Arc<AtomicBool>,
}

#[derive(Serialize, Deserialize, Clone)]
struct SetupConfig {
    workspace_path: String,
    control_plane_url: String,
    auth_token: String,
    start_on_boot: bool,
}

#[derive(Serialize, Deserialize, Clone)]
struct ConnectionStatus {
    connected: bool,
    first_time: bool,
}

#[tauri::command]
async fn select_folder(app: AppHandle) -> Result<Option<String>, String> {
    let dialog = app.dialog();
    let folder_path = dialog
        .file()
        .blocking_pick_folder();
    
    if let Some(ref p) = folder_path {
        let path_str = p.to_string();
        if is_filesystem_root(&path_str) {
            return Err("Cannot use a drive root as workspace. Please select a subfolder.".to_string());
        }
    }

    Ok(folder_path.map(|p| p.to_string()))
}

/// Returns true if the path is a filesystem root (e.g. "C:\", "E:\", "/").
fn is_filesystem_root(path: &str) -> bool {
    let trimmed = path.trim();
    // Unix root
    if trimmed == "/" {
        return true;
    }
    // Windows drive root: "C:", "C:\", "C:/"
    let bytes = trimmed.as_bytes();
    if bytes.len() >= 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2..].iter().all(|&b| b == b'\\' || b == b'/')
    {
        return true;
    }
    false
}

#[tauri::command]
async fn save_setup_config(
    app: AppHandle,
    _state: State<'_, AppState>,
    config: SetupConfig,
) -> Result<(), String> {
    // Save config to app data directory
    let app_data = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let config_path = app_data.join("config.json");
    
    let config_json = serde_json::to_string(&config).map_err(|e| e.to_string())?;
    tokio::fs::write(&config_path, config_json).await.map_err(|e| e.to_string())?;
    
    // Configure autostart based on user preference
    let autostart_manager = app.autolaunch();
    if config.start_on_boot {
        autostart_manager.enable().map_err(|e| e.to_string())?;
    } else {
        autostart_manager.disable().map_err(|e| e.to_string())?;
    }
    
    Ok(())
}

#[tauri::command]
async fn load_setup_config(app: AppHandle) -> Result<Option<SetupConfig>, String> {
    let app_data = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let config_path = app_data.join("config.json");
    
    match tokio::fs::read_to_string(&config_path).await {
        Ok(content) => {
            let config: SetupConfig = serde_json::from_str(&content).map_err(|e| e.to_string())?;
            Ok(Some(config))
        }
        Err(_) => Ok(None),
    }
}

#[tauri::command]
async fn start_agent_daemon(
    app: AppHandle,
    state: State<'_, AppState>,
    config: SetupConfig,
) -> Result<(), String> {
    start_agent_daemon_inner(app, &state, config).await
}

async fn start_agent_daemon_inner(
    app: AppHandle,
    state: &AppState,
    config: SetupConfig,
) -> Result<(), String> {
    let mut agent_process = state.agent_process.lock().await;
    
    if agent_process.is_some() {
        return Err("Agent daemon is already running".to_string());
    }

    // Validate workspace path
    if is_filesystem_root(&config.workspace_path) {
        return Err("Cannot use a drive root as workspace. Please select a subfolder.".to_string());
    }
    
    // Determine sidecar binary based on platform
    let binary_name = get_sidecar_binary_name();
    let sidecar_path = app
        .path()
        .resolve(&format!("sidecar/{}", binary_name), tauri::path::BaseDirectory::Resource)
        .map_err(|e| e.to_string())?;
    
    // Create .env file for the agent
    let env_content = format!(
        r#"CONTROL_PLANE_URL={}
AGENT_AUTH_TOKEN={}
AGENT_PROJECT_ROOT={}
RUNTIME_MODE=ui-box
"#,
        config.control_plane_url,
        config.auth_token,
        config.workspace_path
    );
    
    let env_path = std::path::Path::new(&config.workspace_path).join(".env");
    tokio::fs::create_dir_all(&config.workspace_path).await.map_err(|e| e.to_string())?;
    tokio::fs::write(&env_path, env_content).await.map_err(|e| e.to_string())?;
    
    // Start the agent process
    let child = Command::new(&sidecar_path)
        .current_dir(&config.workspace_path)
        .env("CONTROL_PLANE_URL", &config.control_plane_url)
        .env("AGENT_AUTH_TOKEN", &config.auth_token)
        .env("AGENT_PROJECT_ROOT", &config.workspace_path)
        .env("RUNTIME_MODE", "ui-box")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start agent: {}", e))?;
    
    let pid = child.id().unwrap_or(0);
    *agent_process = Some(child);

    // Mark agent as alive, reset ws_connected and existing_daemon flags
    state.agent_alive.store(true, Ordering::SeqCst);
    state.ws_connected.store(false, Ordering::SeqCst);
    state.existing_daemon.store(false, Ordering::SeqCst);
    
    // Spawn stdout reader — parses for "handshake complete" and "another daemon" detection
    let app_clone = app.clone();
    let ws_connected_stdout = state.ws_connected.clone();
    let existing_daemon_stdout = state.existing_daemon.clone();
    if let Some(stdout) = agent_process.as_mut().unwrap().stdout.take() {
        let reader = BufReader::new(stdout);
        async_runtime::spawn(async move {
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                // Detect successful WebSocket handshake from agent logs
                if line.contains("handshake complete") {
                    ws_connected_stdout.store(true, Ordering::SeqCst);
                }
                // Detect "another daemon is already running" — existing daemon is handling things
                if line.contains("another daemon is already running") {
                    existing_daemon_stdout.store(true, Ordering::SeqCst);
                }
                app_clone.emit("agent-log", format!("[stdout] {}", line)).ok();
            }
        });
    }
    
    let app_clone = app.clone();
    if let Some(stderr) = agent_process.as_mut().unwrap().stderr.take() {
        let reader = BufReader::new(stderr);
        async_runtime::spawn(async move {
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                app_clone.emit("agent-log", format!("[stderr] {}", line)).ok();
            }
        });
    }

    // Drop the lock so the exit-monitor task can acquire it
    drop(agent_process);
    
    // Spawn process exit monitor — detects crashes and emits agent-exit
    let agent_proc_arc = state.agent_process.clone();
    let agent_alive = state.agent_alive.clone();
    let ws_connected_exit = state.ws_connected.clone();
    let is_connected = state.is_connected.clone();
    let existing_daemon_exit = state.existing_daemon.clone();
    let first_registered_exit = state.first_connection_registered.clone();
    let app_clone = app.clone();
    async_runtime::spawn(async move {
        // Poll until the process exits
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            let mut guard = agent_proc_arc.lock().await;
            if let Some(ref mut child) = *guard {
                match child.try_wait() {
                    Ok(Some(exit_status)) => {
                        // Process has exited
                        let code = exit_status.code().unwrap_or(-1);
                        *guard = None;

                        // Special case: another daemon is already running and process
                        // exited cleanly (code 0). The existing daemon is already
                        // connected, so treat this as a successful connection.
                        if code == 0 && existing_daemon_exit.load(Ordering::SeqCst) {
                            agent_alive.store(false, Ordering::SeqCst);
                            // Keep is_connected true — the existing daemon handles it
                            is_connected.store(true, Ordering::SeqCst);
                            ws_connected_exit.store(true, Ordering::SeqCst);

                            if !first_registered_exit.load(Ordering::SeqCst) {
                                first_registered_exit.store(true, Ordering::SeqCst);
                            }

                            app_clone.emit("agent-log", format!(
                                "[system] Another agent daemon is already running (exit code {}). Using existing connection.",
                                code
                            )).ok();
                            app_clone.emit("connection-status", ConnectionStatus {
                                connected: true,
                                first_time: false,
                            }).ok();
                            break;
                        }

                        agent_alive.store(false, Ordering::SeqCst);
                        ws_connected_exit.store(false, Ordering::SeqCst);
                        is_connected.store(false, Ordering::SeqCst);
                        app_clone.emit("agent-exit", code).ok();
                        app_clone.emit("agent-log", format!("[system] Agent process exited with code {}", code)).ok();
                        break;
                    }
                    Ok(None) => {
                        // Still running
                    }
                    Err(e) => {
                        agent_alive.store(false, Ordering::SeqCst);
                        ws_connected_exit.store(false, Ordering::SeqCst);
                        is_connected.store(false, Ordering::SeqCst);
                        *guard = None;
                        app_clone.emit("agent-exit", -1).ok();
                        app_clone.emit("agent-log", format!("[system] Error checking agent status: {}", e)).ok();
                        break;
                    }
                }
            } else {
                // Process was already cleaned up (e.g. by stop_agent_daemon)
                break;
            }
        }
    });

    // Connection check — poll for real WS handshake with 15s timeout
    let agent_alive_check = state.agent_alive.clone();
    let ws_connected_check = state.ws_connected.clone();
    let is_connected_check = state.is_connected.clone();
    let first_registered = state.first_connection_registered.clone();
    let app_clone = app.clone();
    
    async_runtime::spawn(async move {
        // Poll every 500ms for up to 15 seconds for the handshake to complete
        let max_polls = 30; // 30 * 500ms = 15s
        let mut connected = false;
        for _ in 0..max_polls {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            // Process died — exit-monitor will handle it
            if !agent_alive_check.load(Ordering::SeqCst) {
                return;
            }

            // Agent logged "handshake complete" — real connection
            if ws_connected_check.load(Ordering::SeqCst) {
                connected = true;
                break;
            }
        }

        if !connected {
            // Timed out waiting for handshake — report failure
            app_clone.emit("connection-status", ConnectionStatus {
                connected: false,
                first_time: false,
            }).ok();
            return;
        }

        is_connected_check.store(true, Ordering::SeqCst);
        
        // Register on first successful connection if not already done
        if !first_registered.load(Ordering::SeqCst) {
            first_registered.store(true, Ordering::SeqCst);
            
            // Load config and check if autostart should be enabled
            if let Ok(Some(config)) = load_config_from_disk(&app_clone).await {
                if config.start_on_boot {
                    let autostart_manager = app_clone.autolaunch();
                    let _ = autostart_manager.enable();
                    
                    app_clone.emit("autostart-registered", true).ok();
                }
            }
        }
        
        app_clone.emit("connection-status", ConnectionStatus {
            connected: true,
            first_time: !first_registered.load(Ordering::SeqCst),
        }).ok();
    });
    
    app.emit("agent-started", pid).ok();
    
    Ok(())
}

#[tauri::command]
async fn stop_agent_daemon(
    state: State<'_, AppState>,
) -> Result<(), String> {
    stop_agent_daemon_inner(&state).await
}

async fn stop_agent_daemon_inner(
    state: &AppState,
) -> Result<(), String> {
    let mut agent_process = state.agent_process.lock().await;
    
    if let Some(mut child) = agent_process.take() {
        let _ = child.kill().await;
        state.agent_alive.store(false, Ordering::SeqCst);
        state.ws_connected.store(false, Ordering::SeqCst);
        state.is_connected.store(false, Ordering::SeqCst);
        Ok(())
    } else {
        Err("Agent daemon is not running".to_string())
    }
}

#[tauri::command]
async fn check_autostart_status(app: AppHandle) -> Result<bool, String> {
    let autostart_manager = app.autolaunch();
    autostart_manager.is_enabled().map_err(|e| e.to_string())
}

#[tauri::command]
async fn toggle_autostart(
    app: AppHandle,
    enabled: bool,
) -> Result<(), String> {
    let autostart_manager = app.autolaunch();
    
    if enabled {
        autostart_manager.enable().map_err(|e| e.to_string())?;
    } else {
        autostart_manager.disable().map_err(|e| e.to_string())?;
    }
    
    Ok(())
}

#[tauri::command]
async fn is_first_run(app: AppHandle) -> Result<bool, String> {
    let app_data = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let config_path = app_data.join("config.json");
    
    match tokio::fs::metadata(&config_path).await {
        Ok(_) => Ok(false),
        Err(_) => Ok(true),
    }
}

fn get_sidecar_binary_name() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "codemantle-agent.exe"
    }
    #[cfg(target_os = "macos")]
    {
        "codemantle-agent-macos"
    }
    #[cfg(target_os = "linux")]
    {
        "codemantle-agent-linux"
    }
}

async fn load_config_from_disk(app: &AppHandle) -> Result<Option<SetupConfig>, String> {
    let app_data = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let config_path = app_data.join("config.json");
    
    match tokio::fs::read_to_string(&config_path).await {
        Ok(content) => {
            let config: SetupConfig = serde_json::from_str(&content).map_err(|e| e.to_string())?;
            Ok(Some(config))
        }
        Err(_) => Ok(None),
    }
}

fn setup_tray(app: &AppHandle) -> Result<TrayIcon<tauri::Wry>, Box<dyn std::error::Error>> {
    let show_item = MenuItem::with_id(app, "show", "Show CodeMantle", true, None::<&str>)?;
    let settings_item = MenuItem::with_id(app, "settings", "Settings", true, None::<&str>)?;
    let separator1 = PredefinedMenuItem::separator(app)?;
    let start_agent_item = MenuItem::with_id(app, "start-agent", "Start Agent", true, None::<&str>)?;
    let stop_agent_item = MenuItem::with_id(app, "stop-agent", "Stop Agent", true, None::<&str>)?;
    let separator2 = PredefinedMenuItem::separator(app)?;
    let hide_item = MenuItem::with_id(app, "hide", "Hide to Tray", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    
    let menu = Menu::with_items(app, &[
        &show_item,
        &settings_item,
        &separator1,
        &start_agent_item,
        &stop_agent_item,
        &separator2,
        &hide_item,
        &quit_item,
    ])?;
    
    let mut builder = TrayIconBuilder::new()
        .menu(&menu)
        .tooltip("CodeMantle Agent")
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { .. } = event {
                let app = tray.app_handle();
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
        })
        .on_menu_event(|app, event| {
            match event.id.as_ref() {
                "show" => {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
                "settings" => {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                        let _ = window.emit("open-settings", true);
                    }
                }
                "start-agent" => {
                    let app_handle = app.clone();
                    async_runtime::spawn(async move {
                        // Load saved config and start the agent
                        if let Ok(Some(config)) = load_config_from_disk(&app_handle).await {
                            let state = app_handle.state::<AppState>();
                            match start_agent_daemon_inner(app_handle.clone(), &state, config).await {
                                Ok(()) => {
                                    app_handle.emit("agent-log", "[system] Agent started from tray".to_string()).ok();
                                }
                                Err(e) => {
                                    app_handle.emit("agent-log", format!("[system] Failed to start agent: {}", e)).ok();
                                }
                            }
                        } else {
                            app_handle.emit("agent-log", "[system] No saved config found. Please configure in Settings first.".to_string()).ok();
                        }
                    });
                }
                "stop-agent" => {
                    let app_handle = app.clone();
                    async_runtime::spawn(async move {
                        let state = app_handle.state::<AppState>();
                        match stop_agent_daemon_inner(&state).await {
                            Ok(()) => {
                                app_handle.emit("agent-log", "[system] Agent stopped from tray".to_string()).ok();
                            }
                            Err(e) => {
                                app_handle.emit("agent-log", format!("[system] Failed to stop agent: {}", e)).ok();
                            }
                        }
                    });
                }
                "hide" => {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.hide();
                    }
                }
                "quit" => {
                    // Stop agent before quitting
                    let app_handle = app.clone();
                    async_runtime::spawn(async move {
                        let state = app_handle.state::<AppState>();
                        let _ = stop_agent_daemon_inner(&state).await;
                        app_handle.exit(0);
                    });
                }
                _ => {}
            }
        });

    // Only set icon if one is available — avoids panic on missing icon
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }

    let tray = builder.build(app)?;
    
    Ok(tray)
}

fn log_step(msg: &str) {
    let log_path = std::env::temp_dir().join("codemantle-startup.log");
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        let _ = writeln!(file, "[{}] {}", chrono_now(), msg);
    }
}

fn chrono_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}", now.as_secs(), now.subsec_millis())
}

fn main() {
    // Log panics to a file so we can debug release builds
    std::panic::set_hook(Box::new(|info| {
        let log_path = std::env::temp_dir().join("codemantle-crash.log");
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            let _ = writeln!(file, "PANIC: {}", info);
            if let Some(location) = info.location() {
                let _ = writeln!(file, "  at {}:{}:{}", location.file(), location.line(), location.column());
            }
        }
    }));

    log_step("main() entered");

    log_step("creating tauri builder");
    let builder = tauri::Builder::default();

    log_step("adding autostart plugin");
    let builder = builder.plugin(tauri_plugin_autostart::init(
        MacosLauncher::LaunchAgent,
        Some(vec!["--minimized"]),
    ));

    log_step("adding dialog plugin");
    let builder = builder.plugin(tauri_plugin_dialog::init());

    log_step("adding shell plugin");
    let builder = builder.plugin(tauri_plugin_shell::init());

    log_step("adding updater plugin");
    let builder = builder.plugin(tauri_plugin_updater::Builder::new().build());

    log_step("adding managed state");
    let builder = builder.manage(AppState {
        agent_process: Arc::new(Mutex::new(None)),
        is_connected: Arc::new(AtomicBool::new(false)),
        agent_alive: Arc::new(AtomicBool::new(false)),
        ws_connected: Arc::new(AtomicBool::new(false)),
        existing_daemon: Arc::new(AtomicBool::new(false)),
        first_connection_registered: Arc::new(AtomicBool::new(false)),
    });

    log_step("adding setup hook");
    let builder = builder.setup(|app| {
        log_step("setup() entered");

        // Setup system tray (non-fatal — app still works without it)
        log_step("setting up tray");
        match setup_tray(app.handle()) {
            Ok(_tray) => log_step("tray setup OK"),
            Err(e) => {
                log_step(&format!("tray setup FAILED: {}", e));
                eprintln!("Warning: Failed to setup system tray: {}", e);
            }
        }

        // Check if this is a first run
        log_step("spawning first-run check");
        let app_handle = app.handle().clone();
        async_runtime::spawn(async move {
            if let Ok(true) = is_first_run(app_handle.clone()).await {
                // First run - show setup wizard
                app_handle.emit("show-setup-wizard", true).ok();
            }
        });

        // Check if launched with --minimized flag (from autostart)
        let args: Vec<String> = std::env::args().collect();
        if args.contains(&"--minimized".to_string()) {
            log_step("minimized flag detected, hiding window");
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.hide();
            }
        }

        log_step("setup() completed");
        Ok(())
    });

    // Intercept window close — hide to tray instead of quitting
    log_step("adding window event handler");
    let builder = builder.on_window_event(|window, event| {
        if let WindowEvent::CloseRequested { api, .. } = event {
            // Prevent the window from actually closing; hide it instead
            api.prevent_close();
            let _ = window.hide();
        }
    });

    log_step("adding invoke handler");
    let builder = builder.invoke_handler(tauri::generate_handler![
        select_folder,
        save_setup_config,
        load_setup_config,
        start_agent_daemon,
        stop_agent_daemon,
        check_autostart_status,
        toggle_autostart,
        is_first_run,
    ]);

    log_step("calling .run()");
    match builder.run(tauri::generate_context!()) {
        Ok(_) => log_step("app exited normally"),
        Err(e) => {
            let err_msg = e.to_string();
            log_step(&format!("app .run() returned error: {}", err_msg));

            // Detect WebView2 missing — the most common cause of instant crash on Windows
            let is_webview2_error = err_msg.contains("WebView2")
                || err_msg.contains("webview2")
                || err_msg.contains("EdgeWebView")
                || err_msg.contains("HRESULT")
                || err_msg.contains("0x80070002");

            if is_webview2_error {
                log_step("detected WebView2 runtime missing or failed to initialize");
                #[cfg(target_os = "windows")]
                {
                    // Show a native message box so the user knows what went wrong
                    use std::ffi::OsStr;
                    use std::os::windows::ffi::OsStrExt;
                    let text: Vec<u16> = OsStr::new(
                        "CodeMantle requires the Microsoft Edge WebView2 Runtime.\n\n\
                         Please install it from:\n\
                         https://developer.microsoft.com/en-us/microsoft-edge/webview2/\n\n\
                         After installing WebView2, restart CodeMantle."
                    ).encode_wide().chain(Some(0)).collect();
                    let caption: Vec<u16> = OsStr::new("CodeMantle — Missing WebView2")
                        .encode_wide().chain(Some(0)).collect();
                    unsafe {
                        #[link(name = "user32")]
                        extern "system" {
                            fn MessageBoxW(hwnd: *mut std::ffi::c_void, text: *const u16, caption: *const u16, utype: u32) -> i32;
                        }
                        MessageBoxW(std::ptr::null_mut(), text.as_ptr(), caption.as_ptr(), 0x10 /* MB_ICONERROR */);
                    }
                }
            }

            eprintln!("error while running tauri application: {}", e);
            std::process::exit(1);
        }
    }
}
