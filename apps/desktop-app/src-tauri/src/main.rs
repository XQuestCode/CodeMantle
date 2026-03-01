#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{Manager, Emitter, Runtime, State, AppHandle};
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
    
    Ok(folder_path.map(|p| p.to_string()))
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
    let mut agent_process = state.agent_process.lock().await;
    
    if agent_process.is_some() {
        return Err("Agent daemon is already running".to_string());
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
    
    // Spawn log readers
    let app_clone = app.clone();
    if let Some(stdout) = agent_process.as_mut().unwrap().stdout.take() {
        let reader = BufReader::new(stdout);
        async_runtime::spawn(async move {
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
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
    
    // Monitor connection status
    let is_connected = state.is_connected.clone();
    let first_registered = state.first_connection_registered.clone();
    let app_clone = app.clone();
    
    async_runtime::spawn(async move {
        // Simulate connection check - in real implementation, this would check WebSocket status
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        
        is_connected.store(true, Ordering::SeqCst);
        
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
    let mut agent_process = state.agent_process.lock().await;
    
    if let Some(mut child) = agent_process.take() {
        let _ = child.kill().await;
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

fn setup_tray<R: Runtime>(app: &AppHandle<R>) -> Result<TrayIcon<R>, Box<dyn std::error::Error>> {
    let show_item = MenuItem::with_id(app, "show", "Show CodeMantle", true, None::<&str>)?;
    let hide_item = MenuItem::with_id(app, "hide", "Hide to Tray", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    
    let menu = Menu::with_items(app, &[&show_item, &hide_item, &separator, &quit_item])?;
    
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
                "hide" => {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.hide();
                    }
                }
                "quit" => {
                    app.exit(0);
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

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec!["--minimized"]),
        ))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(AppState {
            agent_process: Arc::new(Mutex::new(None)),
            is_connected: Arc::new(AtomicBool::new(false)),
            first_connection_registered: Arc::new(AtomicBool::new(false)),
        })
        .setup(|app| {
            // Setup system tray (non-fatal — app still works without it)
            match setup_tray(app.handle()) {
                Ok(_tray) => {},
                Err(e) => eprintln!("Warning: Failed to setup system tray: {}", e),
            }
            
            // Check if this is a first run
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
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
            
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            select_folder,
            save_setup_config,
            load_setup_config,
            start_agent_daemon,
            stop_agent_daemon,
            check_autostart_status,
            toggle_autostart,
            is_first_run,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
