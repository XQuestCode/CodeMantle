#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::io::Write;
use tauri::{Manager, Emitter, State, AppHandle, WindowEvent};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, TrayIcon, TrayIconBuilder, TrayIconEvent};
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
    #[cfg(target_os = "windows")]
    agent_job: Arc<Mutex<Option<usize>>>,
    is_connected: Arc<AtomicBool>,
    agent_alive: Arc<AtomicBool>,
    /// Set to true when the agent logs "handshake complete" (real WS connection).
    ws_connected: Arc<AtomicBool>,
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

async fn kill_orphaned_daemon() {
    let lock_path = std::env::temp_dir().join("codemantle-agent-daemon.lock.json");
    let lock_content = match tokio::fs::read_to_string(&lock_path).await {
        Ok(content) => content,
        Err(_) => return,
    };

    let lock_json: serde_json::Value = match serde_json::from_str(&lock_content) {
        Ok(parsed) => parsed,
        Err(e) => {
            log_step(&format!("failed to parse daemon lock file: {}", e));
            let _ = tokio::fs::remove_file(&lock_path).await;
            log_step("cleaned up stale lock file");
            return;
        }
    };

    let Some(pid_raw) = lock_json.get("pid").and_then(|v| v.as_u64()) else {
        let _ = tokio::fs::remove_file(&lock_path).await;
        log_step("cleaned up stale lock file");
        return;
    };

    let Ok(pid) = u32::try_from(pid_raw) else {
        let _ = tokio::fs::remove_file(&lock_path).await;
        log_step("cleaned up stale lock file");
        return;
    };

    if pid == 0 {
        let _ = tokio::fs::remove_file(&lock_path).await;
        log_step("cleaned up stale lock file");
        return;
    }

    #[cfg(target_os = "windows")]
    let mut alive = is_pid_alive_windows(pid);
    #[cfg(not(target_os = "windows"))]
    let mut alive = is_pid_alive_unix(pid).await;

    if alive {
        log_step(&format!("killing orphaned daemon pid={}", pid));
        #[cfg(target_os = "windows")]
        {
            if !kill_pid_windows(pid) {
                log_step(&format!("failed to terminate orphaned daemon pid={}", pid));
            }
            alive = is_pid_alive_windows(pid);
        }
        #[cfg(not(target_os = "windows"))]
        {
            if !kill_pid_unix(pid).await {
                log_step(&format!("failed to terminate orphaned daemon pid={}", pid));
            }
            alive = is_pid_alive_unix(pid).await;
        }
    }

    if !alive {
        let _ = tokio::fs::remove_file(&lock_path).await;
        log_step("cleaned up stale lock file");
    }
}

#[cfg(target_os = "windows")]
fn is_pid_alive_windows(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return false;
        }
        CloseHandle(handle);
        true
    }
}

#[cfg(target_os = "windows")]
fn kill_pid_windows(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    };

    unsafe {
        let handle = OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        );
        if handle.is_null() {
            return false;
        }
        let ok = TerminateProcess(handle, 1) != 0;
        CloseHandle(handle);
        ok
    }
}

#[cfg(not(target_os = "windows"))]
async fn is_pid_alive_unix(pid: u32) -> bool {
    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .await
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(not(target_os = "windows"))]
async fn kill_pid_unix(pid: u32) -> bool {
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .await;

    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    if !is_pid_alive_unix(pid).await {
        return true;
    }

    let _ = Command::new("kill")
        .arg("-KILL")
        .arg(pid.to_string())
        .status()
        .await;

    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    !is_pid_alive_unix(pid).await
}

#[cfg(target_os = "windows")]
async fn attach_process_to_job(state: &AppState, pid: u32) -> Result<(), String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    };
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE};

    if pid == 0 {
        return Err("Agent process pid is invalid".to_string());
    }

    let job_value = unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            return Err("Failed to create Windows Job Object".to_string());
        }

        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        let configured = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &limits as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        if configured == 0 {
            CloseHandle(job);
            return Err("Failed to configure Windows Job Object".to_string());
        }

        let process = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid);
        if process.is_null() {
            CloseHandle(job);
            return Err(format!("Failed to open child process handle for pid {}", pid));
        }

        let assigned = AssignProcessToJobObject(job, process);
        CloseHandle(process);
        if assigned == 0 {
            CloseHandle(job);
            return Err(format!("Failed to assign child pid {} to Job Object", pid));
        }

        job as usize
    };

    let mut job_guard = state.agent_job.lock().await;
    if let Some(existing_job) = job_guard.take() {
        unsafe {
            CloseHandle(existing_job as windows_sys::Win32::Foundation::HANDLE);
        }
    }
    *job_guard = Some(job_value);

    Ok(())
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
    tokio::fs::create_dir_all(&app_data).await.map_err(|e| e.to_string())?;
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
    start_agent_daemon_inner(app, state.inner(), config).await
}

async fn start_agent_daemon_inner(
    app: AppHandle,
    state: &AppState,
    config: SetupConfig,
) -> Result<(), String> {
    let agent_process = state.agent_process.lock().await;
    
    if agent_process.is_some() {
        return Err("Agent daemon is already running".to_string());
    }
    drop(agent_process);

    kill_orphaned_daemon().await;

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
    let sidecar_path = prepare_runtime_sidecar_path(&app, binary_name).await?;
    
    let resolved_opencode_path = resolve_opencode_binary_path_with_version()
        .await
        .map(|(path, _version)| path);

    // Create .env file for the agent
    let mut env_content = format!(
        r#"CONTROL_PLANE_URL={}
AGENT_AUTH_TOKEN={}
AGENT_PROJECT_ROOT={}
RUNTIME_MODE=ui-box
"#,
        config.control_plane_url,
        config.auth_token,
        config.workspace_path
    );

    if let Some(ref opencode_path) = resolved_opencode_path {
        env_content.push_str(&format!("OPENCODE_COMMAND={}\n", opencode_path));
    }
    
    let env_path = std::path::Path::new(&config.workspace_path).join(".env");
    tokio::fs::create_dir_all(&config.workspace_path).await.map_err(|e| e.to_string())?;
    tokio::fs::write(&env_path, env_content).await.map_err(|e| e.to_string())?;
    
    // Start the agent process
    let app_version = env!("CARGO_PKG_VERSION");
    let mut command = Command::new(&sidecar_path);
    command
        .current_dir(&config.workspace_path)
        .env("CONTROL_PLANE_URL", &config.control_plane_url)
        .env("AGENT_AUTH_TOKEN", &config.auth_token)
        .env("AGENT_PROJECT_ROOT", &config.workspace_path)
        .env("AGENT_VERSION", app_version)
        .env("RUNTIME_MODE", "ui-box")
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(ref opencode_path) = resolved_opencode_path {
        command.env("OPENCODE_COMMAND", opencode_path);
    }

    #[cfg(target_os = "windows")]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = command
        .spawn()
        .map_err(|e| format!("Failed to start agent: {}", e))?;
    
    let pid = child.id().unwrap_or(0);

    #[cfg(target_os = "windows")]
    if let Err(e) = attach_process_to_job(state, pid).await {
        let _ = child.kill().await;
        return Err(e);
    }

    *agent_process = Some(child);

    // Mark agent as alive and reset ws_connected
    state.agent_alive.store(true, Ordering::SeqCst);
    state.ws_connected.store(false, Ordering::SeqCst);
    
    // Spawn stdout reader — parses for "handshake complete"
    let app_clone = app.clone();
    let ws_connected_stdout = state.ws_connected.clone();
    if let Some(stdout) = agent_process.as_mut().unwrap().stdout.take() {
        let reader = BufReader::new(stdout);
        async_runtime::spawn(async move {
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                // Detect successful WebSocket handshake from agent logs
                if line.contains("handshake complete") {
                    ws_connected_stdout.store(true, Ordering::SeqCst);
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
    stop_agent_daemon_inner(state.inner()).await
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

        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::Foundation::CloseHandle;

            let mut agent_job = state.agent_job.lock().await;
            if let Some(job) = agent_job.take() {
                unsafe {
                    CloseHandle(job as windows_sys::Win32::Foundation::HANDLE);
                }
            }
        }

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
        autostart_manager.enable().map_err(|e| {
            format!("Failed to enable launch on startup: {}. On some systems this may require running the app as administrator.", e)
        })?;
    } else {
        autostart_manager.disable().map_err(|e| {
            format!("Failed to disable launch on startup: {}. On some systems this may require running the app as administrator.", e)
        })?;
    }
    
    // Verify the change actually took effect
    let actual = autostart_manager.is_enabled().unwrap_or(false);
    if actual != enabled {
        return Err(format!(
            "Autostart toggle did not take effect (expected {}, got {}). \
             This can happen if another program or group policy is preventing changes to startup entries. \
             Try running CodeMantle as administrator.",
            enabled, actual
        ));
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

#[tauri::command]
fn get_app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct DependencyInfo {
    name: String,
    installed: bool,
    version: Option<String>,
    path: Option<String>,
    error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct InstallProgress {
    dependency: String,
    stage: String,
    message: String,
    done: bool,
    success: bool,
}

/// Extract a version number like "2.43.0" or "0.5.1" from a string.
/// Finds the first occurrence of `\d+\.\d+(\.\d+)?` without needing a regex crate.
fn extract_version_number(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // Find a digit that starts a version-like pattern
        if chars[i].is_ascii_digit() {
            let start = i;
            // Consume digits (major)
            while i < len && chars[i].is_ascii_digit() {
                i += 1;
            }
            // Require a dot
            if i < len && chars[i] == '.' {
                i += 1;
                // Require at least one digit (minor)
                if i < len && chars[i].is_ascii_digit() {
                    while i < len && chars[i].is_ascii_digit() {
                        i += 1;
                    }
                    // Optional third segment (.patch)
                    if i < len && chars[i] == '.' {
                        let dot_pos = i;
                        i += 1;
                        if i < len && chars[i].is_ascii_digit() {
                            while i < len && chars[i].is_ascii_digit() {
                                i += 1;
                            }
                        } else {
                            // Dot not followed by digit — don't include it
                            i = dot_pos;
                        }
                    }
                    return Some(chars[start..i].iter().collect());
                }
            }
        }
        i += 1;
    }
    None
}

/// Probe a single command by running `<cmd> --version` and optionally `where`/`which` to find its path.
async fn probe_command(name: &str) -> DependencyInfo {
    let version_result = Command::new(name)
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await;

    match version_result {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let combined = format!("{}{}", stdout, stderr);

            // Extract version number (e.g. "2.43.0" or "0.5.1") without regex dependency
            let version = extract_version_number(&combined);

            // Find binary path
            let path_cmd = if cfg!(target_os = "windows") { "where" } else { "which" };
            let path = Command::new(path_cmd)
                .arg(name)
                .output()
                .await
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).lines().next().unwrap_or("").trim().to_string())
                .filter(|s| !s.is_empty());

            DependencyInfo {
                name: name.to_string(),
                installed: true,
                version,
                path,
                error: None,
            }
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            DependencyInfo {
                name: name.to_string(),
                installed: false,
                version: None,
                path: None,
                error: Some(if stderr.is_empty() {
                    format!("Exit code {}", output.status.code().unwrap_or(-1))
                } else {
                    stderr.trim().to_string()
                }),
            }
        }
        Err(e) => DependencyInfo {
            name: name.to_string(),
            installed: false,
            version: None,
            path: None,
            error: Some(e.to_string()),
        },
    }
}

async fn probe_command_path(path: &std::path::Path) -> Option<Option<String>> {
    let output = Command::new(path)
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{}{}", stdout, stderr);
    Some(extract_version_number(&combined))
}

fn parse_command_stdout_path(output: &[u8]) -> Option<String> {
    let line = String::from_utf8_lossy(output)
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    if line.is_empty() {
        None
    } else {
        Some(line)
    }
}

fn opencode_candidate_filenames() -> Vec<&'static str> {
    if cfg!(target_os = "windows") {
        vec!["opencode.cmd", "opencode.exe", "opencode"]
    } else {
        vec!["opencode"]
    }
}

async fn resolve_opencode_binary_path_with_version() -> Option<(String, Option<String>)> {
    // 1) CodeMantle-managed install location (~/.codemantle/bin)
    let home = dirs_next_home();
    let ext = if cfg!(target_os = "windows") { ".exe" } else { "" };
    let custom_path = std::path::PathBuf::from(&home)
        .join(".codemantle")
        .join("bin")
        .join(format!("opencode{}", ext));

    if let Some(version) = probe_command_path(&custom_path).await {
        return Some((custom_path.to_string_lossy().to_string(), version));
    }

    // 2) PATH detection (works when desktop environment inherits shell PATH)
    let info = probe_command("opencode").await;
    if info.installed {
        if let Some(path) = info.path {
            return Some((path, info.version));
        }
    }

    // 3) npm global installation paths (common when PATH is not inherited by GUI apps)
    let mut candidate_dirs: Vec<std::path::PathBuf> = Vec::new();

    let npm_bin_output = Command::new("npm")
        .args(["bin", "-g"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await;
    if let Ok(output) = npm_bin_output {
        if output.status.success() {
            if let Some(bin_dir) = parse_command_stdout_path(&output.stdout) {
                candidate_dirs.push(std::path::PathBuf::from(bin_dir));
            }
        }
    }

    let npm_prefix_output = Command::new("npm")
        .args(["config", "get", "prefix"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await;
    if let Ok(output) = npm_prefix_output {
        if output.status.success() {
            if let Some(prefix_dir) = parse_command_stdout_path(&output.stdout) {
                let prefix_path = std::path::PathBuf::from(&prefix_dir);
                candidate_dirs.push(prefix_path.clone());
                candidate_dirs.push(prefix_path.join("bin"));
            }
        }
    }

    let names = opencode_candidate_filenames();
    for dir in candidate_dirs {
        for name in &names {
            let candidate_path = dir.join(name);
            if let Some(version) = probe_command_path(&candidate_path).await {
                return Some((candidate_path.to_string_lossy().to_string(), version));
            }
        }
    }

    None
}

#[tauri::command]
async fn check_dependencies() -> Result<Vec<DependencyInfo>, String> {
    let git_info = probe_command("git").await;
    let opencode_info = if let Some((path, version)) = resolve_opencode_binary_path_with_version().await {
        DependencyInfo {
            name: "opencode".to_string(),
            installed: true,
            version,
            path: Some(path),
            error: None,
        }
    } else {
        DependencyInfo {
            name: "opencode".to_string(),
            installed: false,
            version: None,
            path: None,
            error: Some("OpenCode not found on PATH, npm global install, or ~/.codemantle/bin".to_string()),
        }
    };

    Ok(vec![git_info, opencode_info])
}

/// Install a dependency using platform-specific package managers.
/// Emits `dependency-install-progress` events to the frontend.
#[tauri::command]
async fn install_dependency(
    app: AppHandle,
    name: String,
) -> Result<(), String> {
    let dep_name = name.clone();
    let emit_progress = move |stage: &str, message: &str, done: bool, success: bool| {
        let _ = app.emit("dependency-install-progress", InstallProgress {
            dependency: dep_name.clone(),
            stage: stage.to_string(),
            message: message.to_string(),
            done,
            success,
        });
    };

    let emit_progress: Arc<dyn Fn(&str, &str, bool, bool) + Send + Sync> = Arc::new(emit_progress);

    match name.as_str() {
        "git" => install_git(emit_progress.clone()).await,
        "opencode" => install_opencode(emit_progress.clone()).await,
        _ => Err(format!("Unknown dependency: {}", name)),
    }
}

async fn install_git(
    emit: Arc<dyn Fn(&str, &str, bool, bool) + Send + Sync>,
) -> Result<(), String> {
    emit("starting", "Installing git...", false, false);

    #[cfg(target_os = "windows")]
    {
        emit("downloading", "Installing git via winget...", false, false);
        let output = Command::new("winget")
            .args(["install", "--id", "Git.Git", "-e", "--source", "winget", "--silent", "--accept-package-agreements", "--accept-source-agreements"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| format!("Failed to run winget: {}. Please install git manually from https://git-scm.com", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let combined = format!("{}\n{}", stdout, stderr);

            // winget may fail if already installed — check
            if combined.contains("already installed") || combined.contains("No applicable update found") {
                emit("complete", "Git is already installed", true, true);
                return Ok(());
            }

            emit("error", &format!("winget install failed: {}", combined.trim()), true, false);
            return Err(format!("Failed to install git via winget: {}", combined.trim()));
        }

        emit("complete", "Git installed successfully via winget", true, true);
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        emit("downloading", "Installing git via Homebrew...", false, false);
        let output = Command::new("brew")
            .args(["install", "git"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| format!("Failed to run brew: {}. Please install Homebrew first (https://brew.sh) or install git manually.", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            emit("error", &format!("brew install failed: {}", stderr.trim()), true, false);
            return Err(format!("Failed to install git via Homebrew: {}", stderr.trim()));
        }

        emit("complete", "Git installed successfully via Homebrew", true, true);
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        // Try apt-get first (Debian/Ubuntu), then dnf (Fedora), then yum
        emit("downloading", "Installing git via package manager...", false, false);

        let apt_output = Command::new("sudo")
            .args(["apt-get", "install", "-y", "git"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await;

        if let Ok(output) = apt_output {
            if output.status.success() {
                emit("complete", "Git installed successfully via apt-get", true, true);
                return Ok(());
            }
        }

        let dnf_output = Command::new("sudo")
            .args(["dnf", "install", "-y", "git"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await;

        if let Ok(output) = dnf_output {
            if output.status.success() {
                emit("complete", "Git installed successfully via dnf", true, true);
                return Ok(());
            }
        }

        emit("error", "Could not install git. Please install manually: sudo apt-get install git", true, false);
        return Err("Failed to install git via apt-get or dnf. Please install manually.".to_string());
    }

    #[allow(unreachable_code)]
    {
        emit("error", "Unsupported platform for automatic git installation", true, false);
        Err("Unsupported platform for automatic git installation".to_string())
    }
}

async fn install_opencode(
    emit: Arc<dyn Fn(&str, &str, bool, bool) + Send + Sync>,
) -> Result<(), String> {
    emit("starting", "Installing opencode...", false, false);

    #[cfg(target_os = "windows")]
    {
        emit("downloading", "Installing opencode via winget...", false, false);
        let output = Command::new("winget")
            .args(["install", "-e", "--id", "SST.opencode", "--silent", "--accept-package-agreements", "--accept-source-agreements"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| format!("Failed to run winget: {}", e))?;

        if output.status.success() {
            emit("complete", "OpenCode installed successfully via winget", true, true);
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let combined = format!("{}\n{}", stdout, stderr);

        if combined.contains("already installed") || combined.contains("No applicable update found") {
            emit("complete", "OpenCode is already installed", true, true);
            return Ok(());
        }

        // Fallback: try downloading binary directly from GitHub releases
        emit("downloading", "winget failed, downloading opencode binary from GitHub...", false, false);
        return install_opencode_from_github(emit.clone()).await;
    }

    #[cfg(target_os = "macos")]
    {
        emit("downloading", "Installing opencode via Homebrew...", false, false);
        let output = Command::new("brew")
            .args(["install", "anomalyco/tap/opencode"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| format!("Failed to run brew: {}", e))?;

        if output.status.success() {
            emit("complete", "OpenCode installed successfully via Homebrew", true, true);
            return Ok(());
        }

        // Fallback to GitHub binary download
        emit("downloading", "Homebrew failed, downloading opencode binary from GitHub...", false, false);
        return install_opencode_from_github(emit.clone()).await;
    }

    #[cfg(target_os = "linux")]
    {
        // Use the official install script
        emit("downloading", "Installing opencode via install script...", false, false);
        let output = Command::new("bash")
            .args(["-c", "curl -fsSL https://opencode.ai/install | bash"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| format!("Failed to run install script: {}", e))?;

        if output.status.success() {
            emit("complete", "OpenCode installed successfully", true, true);
            return Ok(());
        }

        // Fallback to GitHub binary download
        emit("downloading", "Install script failed, downloading opencode binary from GitHub...", false, false);
        return install_opencode_from_github(emit.clone()).await;
    }

    #[allow(unreachable_code)]
    {
        emit("error", "Unsupported platform for automatic opencode installation", true, false);
        Err("Unsupported platform".to_string())
    }
}

/// Download opencode binary directly from GitHub releases into ~/.codemantle/bin/
async fn install_opencode_from_github(
    emit: Arc<dyn Fn(&str, &str, bool, bool) + Send + Sync>,
) -> Result<(), String> {
    let (os_name, ext) = if cfg!(target_os = "windows") {
        ("windows", ".exe")
    } else if cfg!(target_os = "macos") {
        ("darwin", "")
    } else {
        ("linux", "")
    };

    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x64"
    };

    let asset_name = format!("opencode-{}-{}{}", os_name, arch, ext);
    let zip_name = format!("opencode-{}-{}.zip", os_name, arch);

    emit("downloading", &format!("Downloading {} from GitHub releases...", asset_name), false, false);

    // Resolve install directory
    let home = dirs_next_home();
    let bin_dir = std::path::PathBuf::from(&home).join(".codemantle").join("bin");
    tokio::fs::create_dir_all(&bin_dir).await.map_err(|e| format!("Failed to create bin dir: {}", e))?;

    let binary_path = bin_dir.join(format!("opencode{}", ext));

    // Try downloading the zip from latest release
    let download_url = format!(
        "https://github.com/anomalyco/opencode/releases/latest/download/{}",
        zip_name
    );

    let zip_path = bin_dir.join(&zip_name);

    // Use curl/powershell to download (available on all platforms without extra deps)
    #[cfg(target_os = "windows")]
    {
        let download_output = Command::new("powershell")
            .args([
                "-NoProfile", "-Command",
                &format!(
                    "Invoke-WebRequest -Uri '{}' -OutFile '{}' -UseBasicParsing",
                    download_url,
                    zip_path.display()
                ),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| format!("Failed to download opencode: {}", e))?;

        if !download_output.status.success() {
            let stderr = String::from_utf8_lossy(&download_output.stderr);
            emit("error", &format!("Download failed: {}", stderr.trim()), true, false);
            return Err(format!("Failed to download opencode: {}", stderr.trim()));
        }

        // Extract zip
        emit("installing", "Extracting opencode...", false, false);
        let extract_output = Command::new("powershell")
            .args([
                "-NoProfile", "-Command",
                &format!(
                    "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
                    zip_path.display(),
                    bin_dir.display()
                ),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| format!("Failed to extract: {}", e))?;

        if !extract_output.status.success() {
            let stderr = String::from_utf8_lossy(&extract_output.stderr);
            emit("error", &format!("Extraction failed: {}", stderr.trim()), true, false);
            return Err(format!("Failed to extract opencode: {}", stderr.trim()));
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let download_output = Command::new("curl")
            .args(["-fsSL", "-o", &zip_path.to_string_lossy(), &download_url])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| format!("Failed to download opencode: {}", e))?;

        if !download_output.status.success() {
            let stderr = String::from_utf8_lossy(&download_output.stderr);
            emit("error", &format!("Download failed: {}", stderr.trim()), true, false);
            return Err(format!("Failed to download opencode: {}", stderr.trim()));
        }

        // Extract zip
        emit("installing", "Extracting opencode...", false, false);
        let extract_output = Command::new("unzip")
            .args(["-o", &zip_path.to_string_lossy(), "-d", &bin_dir.to_string_lossy()])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| format!("Failed to extract: {}", e))?;

        if !extract_output.status.success() {
            let stderr = String::from_utf8_lossy(&extract_output.stderr);
            emit("error", &format!("Extraction failed: {}", stderr.trim()), true, false);
            return Err(format!("Failed to extract opencode: {}", stderr.trim()));
        }

        // Make executable
        let _ = Command::new("chmod")
            .args(["+x", &binary_path.to_string_lossy()])
            .output()
            .await;
    }

    // Clean up zip file
    let _ = tokio::fs::remove_file(&zip_path).await;

    // Verify the binary works
    let verify = Command::new(&binary_path)
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await;

    match verify {
        Ok(output) if output.status.success() => {
            emit("complete", &format!("OpenCode installed to {}", binary_path.display()), true, true);
            Ok(())
        }
        _ => {
            emit("error", "Downloaded binary failed verification. Please install opencode manually.", true, false);
            Err("OpenCode binary verification failed".to_string())
        }
    }
}

/// Get the user's home directory path as a String.
fn dirs_next_home() -> String {
    #[cfg(target_os = "windows")]
    {
        std::env::var("USERPROFILE")
            .unwrap_or_else(|_| std::env::var("HOMEDRIVE").unwrap_or_default() + &std::env::var("HOMEPATH").unwrap_or_default())
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string())
    }
}

/// Get the resolved path to the opencode binary (checks ~/.codemantle/bin/ first, then PATH).
#[tauri::command]
async fn get_opencode_binary_path() -> Result<Option<String>, String> {
    Ok(resolve_opencode_binary_path_with_version()
        .await
        .map(|(path, _version)| path))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_version_number_parses_common_versions() {
        assert_eq!(extract_version_number("opencode 0.5.1"), Some("0.5.1".to_string()));
        assert_eq!(extract_version_number("git version 2.47"), Some("2.47".to_string()));
    }

    #[test]
    fn parse_command_stdout_path_trims_first_line() {
        let output = b"C:\\Users\\me\\AppData\\Roaming\\npm\\opencode.cmd\r\nC:\\other\\opencode.cmd\r\n";
        assert_eq!(
            parse_command_stdout_path(output),
            Some("C:\\Users\\me\\AppData\\Roaming\\npm\\opencode.cmd".to_string())
        );
    }

    #[test]
    fn opencode_candidate_filenames_includes_windows_wrappers() {
        let names = opencode_candidate_filenames();
        #[cfg(target_os = "windows")]
        assert!(names.contains(&"opencode.cmd"));

        #[cfg(not(target_os = "windows"))]
        assert_eq!(names, vec!["opencode"]);
    }
}

async fn prepare_runtime_sidecar_path(app: &AppHandle, binary_name: &str) -> Result<std::path::PathBuf, String> {
    let source_path = app
        .path()
        .resolve(&format!("sidecar/{}", binary_name), tauri::path::BaseDirectory::Resource)
        .map_err(|e| e.to_string())?;

    let app_data = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let runtime_dir = app_data.join("sidecar-runtime");
    tokio::fs::create_dir_all(&runtime_dir).await.map_err(|e| e.to_string())?;

    cleanup_runtime_sidecars(&runtime_dir, binary_name).await;

    let runtime_file_name = runtime_sidecar_file_name(binary_name);
    let runtime_path = runtime_dir.join(runtime_file_name);
    tokio::fs::copy(&source_path, &runtime_path)
        .await
        .map_err(|e| format!("Failed to prepare runtime sidecar: {}", e))?;

    Ok(runtime_path)
}

async fn cleanup_runtime_sidecars(runtime_dir: &std::path::Path, binary_name: &str) {
    let prefix = runtime_sidecar_prefix(binary_name);
    let mut entries = match tokio::fs::read_dir(runtime_dir).await {
        Ok(entries) => entries,
        Err(_) => return,
    };

    while let Ok(Some(entry)) = entries.next_entry().await {
        let file_name = entry.file_name().to_string_lossy().to_string();
        if !file_name.starts_with(&prefix) {
            continue;
        }
        let _ = tokio::fs::remove_file(entry.path()).await;
    }
}

fn runtime_sidecar_prefix(binary_name: &str) -> String {
    #[cfg(target_os = "windows")]
    {
        return format!("{}-", binary_name.trim_end_matches(".exe"));
    }

    #[cfg(not(target_os = "windows"))]
    {
        return format!("{}-", binary_name);
    }
}

fn runtime_sidecar_file_name(binary_name: &str) -> String {
    let timestamp = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_millis(),
        Err(_) => 0,
    };

    #[cfg(target_os = "windows")]
    {
        return format!("{}-{}.exe", binary_name.trim_end_matches(".exe"), timestamp);
    }

    #[cfg(not(target_os = "windows"))]
    {
        return format!("{}-{}", binary_name, timestamp);
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
            if let TrayIconEvent::Click { button: MouseButton::Left, .. } = event {
                let app = tray.app_handle();
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.unminimize();
                    let _ = window.set_focus();
                }
            }
        })
        .on_menu_event(|app, event| {
            match event.id.as_ref() {
                "show" => {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.unminimize();
                        let _ = window.set_focus();
                    }
                }
                "settings" => {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.unminimize();
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
                            match start_agent_daemon_inner(app_handle.clone(), state.inner(), config).await {
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
                        match stop_agent_daemon_inner(state.inner()).await {
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
                        let _ = stop_agent_daemon_inner(state.inner()).await;
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

    log_step(&format!("CodeMantle desktop v{}", env!("CARGO_PKG_VERSION")));
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

    log_step("adding single-instance plugin");
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.show();
            let _ = window.unminimize();
            let _ = window.set_focus();
        }
    }));

    log_step("adding managed state");
    let builder = builder.manage(AppState {
        agent_process: Arc::new(Mutex::new(None)),
        #[cfg(target_os = "windows")]
        agent_job: Arc::new(Mutex::new(None)),
        is_connected: Arc::new(AtomicBool::new(false)),
        agent_alive: Arc::new(AtomicBool::new(false)),
        ws_connected: Arc::new(AtomicBool::new(false)),
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
        let is_minimized = args.contains(&"--minimized".to_string());
        if is_minimized {
            log_step("minimized flag detected, hiding window");
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.hide();
            }
        }

        // Auto-start agent on boot when launched with --minimized
        // (i.e. the OS autostart mechanism triggered the launch)
        if is_minimized {
            log_step("auto-starting agent daemon (launched via autostart)");
            let app_handle = app.handle().clone();
            async_runtime::spawn(async move {
                match load_config_from_disk(&app_handle).await {
                    Ok(Some(config)) => {
                        let state = app_handle.state::<AppState>();
                        match start_agent_daemon_inner(app_handle.clone(), state.inner(), config).await {
                            Ok(()) => {
                                log_step("auto-start: agent daemon started successfully");
                                app_handle.emit("agent-log", "[system] Agent auto-started on boot".to_string()).ok();
                            }
                            Err(e) => {
                                log_step(&format!("auto-start: failed to start agent: {}", e));
                                app_handle.emit("agent-log", format!("[system] Auto-start failed: {}", e)).ok();
                            }
                        }
                    }
                    Ok(None) => {
                        log_step("auto-start: no saved config found, skipping");
                    }
                    Err(e) => {
                        log_step(&format!("auto-start: failed to load config: {}", e));
                    }
                }
            });
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
        get_app_version,
        check_dependencies,
        install_dependency,
        get_opencode_binary_path,
    ]);

    log_step("calling .build() and .run()");
    match builder.build(tauri::generate_context!()) {
        Ok(app) => {
            app.run(|app_handle, event| {
                if let tauri::RunEvent::Exit = event {
                    let state = app_handle.state::<AppState>();
                    let agent_proc = state.inner().agent_process.clone();
                    #[cfg(target_os = "windows")]
                    let agent_job = state.inner().agent_job.clone();

                    tauri::async_runtime::block_on(async move {
                        let mut guard = agent_proc.lock().await;
                        if let Some(mut child) = guard.take() {
                            let _ = child.kill().await;
                        }

                        #[cfg(target_os = "windows")]
                        {
                            use windows_sys::Win32::Foundation::CloseHandle;

                            let mut job_guard = agent_job.lock().await;
                            if let Some(job) = job_guard.take() {
                                unsafe {
                                    CloseHandle(job as windows_sys::Win32::Foundation::HANDLE);
                                }
                            }
                        }
                    });
                }
            });
            log_step("app exited normally");
        }
        Err(e) => {
            let err_msg = e.to_string();
            log_step(&format!("app .build() returned error: {}", err_msg));

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
