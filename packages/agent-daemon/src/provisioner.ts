import { spawn, type ChildProcess } from "node:child_process";
import { mkdir, writeFile, readFile, access, chmod, unlink, rename } from "node:fs/promises";
import { constants } from "node:fs";
import os from "node:os";
import path from "node:path";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";
import Enquirer from "enquirer";

const { prompt } = Enquirer;

export type DependencyType = "git" | "opencode";
export type SetupPhase = "probe" | "install" | "configure" | "complete";
export type RuntimeMode = "headless" | "ui-box";

export interface ProvisionerConfig {
  workspacePath: string;
  controlPlaneUrl: string;
  authToken: string;
  runtimeMode: RuntimeMode;
  startOnBoot: boolean;
}

export interface DependencyStatus {
  type: DependencyType;
  installed: boolean;
  version?: string | undefined;
  path?: string | undefined;
  error?: string | undefined;
}

export interface SetupProgressEvent {
  phase: SetupPhase;
  step: string;
  status: "running" | "success" | "error";
  progress: number;
  message?: string;
}

export interface StartOnBootConfig {
  enabled: boolean;
  serviceName: string;
  platform: NodeJS.Platform;
}

export type ProvisionerCallback = (event: SetupProgressEvent) => void;

export class Provisioner {
  private callbacks: ProvisionerCallback[] = [];
  private config: ProvisionerConfig | null = null;

  onProgress(callback: ProvisionerCallback): void {
    this.callbacks.push(callback);
  }

  private emitProgress(event: SetupProgressEvent): void {
    for (const callback of this.callbacks) {
      try {
        callback(event);
      } catch {
      }
    }
  }

  async probeDependencies(): Promise<DependencyStatus[]> {
    this.emitProgress({
      phase: "probe",
      step: "dependency_probe",
      status: "running",
      progress: 0,
      message: "Checking dependencies...",
    });

    const results: DependencyStatus[] = [];

    const gitStatus = await this.checkCommand("git", ["--version"]);
    results.push({
      type: "git",
      installed: gitStatus.ok,
      version: gitStatus.version,
      path: gitStatus.path,
      error: gitStatus.error,
    });

    this.emitProgress({
      phase: "probe",
      step: "dependency_probe",
      status: "running",
      progress: 50,
      message: `Git ${gitStatus.ok ? "found" : "not found"}`,
    });

    const opencodeStatus = await this.checkCommand("opencode", ["--version"]);
    results.push({
      type: "opencode",
      installed: opencodeStatus.ok,
      version: opencodeStatus.version,
      path: opencodeStatus.path,
      error: opencodeStatus.error,
    });

    const allInstalled = results.every((r) => r.installed);
    this.emitProgress({
      phase: "probe",
      step: "dependency_probe",
      status: allInstalled ? "success" : "error",
      progress: 100,
      message: allInstalled
        ? "All dependencies found"
        : `Missing: ${results.filter((r) => !r.installed).map((r) => r.type).join(", ")}`,
    });

    return results;
  }

  private async checkCommand(command: string, args: string[]): Promise<{
    ok: boolean;
    version?: string | undefined;
    path?: string | undefined;
    error?: string | undefined;
  }> {
    try {
      const { stdout, stderr, code } = await this.execCommand(command, args, 10000);
      if (code !== 0) {
        return { ok: false, error: stderr || `Exit code ${code}` };
      }

      const versionMatch = stdout.match(/(\d+\.\d+(?:\.\d+)?)/);
      const version = versionMatch ? versionMatch[1] : undefined;

      const whichCmd = process.platform === "win32" ? "where" : "which";
      const { stdout: pathOutput } = await this.execCommand(whichCmd, [command], 5000).catch(() => ({ stdout: "" }));
      const commandPath = pathOutput.trim().split("\n")[0];

      return { ok: true, version, path: commandPath || undefined };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error.message : "Command not found",
      };
    }
  }

  private async execCommand(
    command: string,
    args: string[],
    timeoutMs: number,
  ): Promise<{ stdout: string; stderr: string; code: number | null }> {
    return new Promise((resolve, reject) => {
      const child = spawn(command, args, {
        stdio: ["ignore", "pipe", "pipe"],
        shell: process.platform === "win32",
      });

      let stdout = "";
      let stderr = "";

      const timer = setTimeout(() => {
        child.kill();
        reject(new Error("timeout"));
      }, timeoutMs);

      child.stdout?.on("data", (data) => {
        stdout += data.toString();
      });

      child.stderr?.on("data", (data) => {
        stderr += data.toString();
      });

      child.on("close", (code) => {
        clearTimeout(timer);
        resolve({ stdout, stderr, code });
      });

      child.on("error", (error) => {
        clearTimeout(timer);
        reject(error);
      });
    });
  }

  async runInteractiveSetup(mode: RuntimeMode = "headless"): Promise<ProvisionerConfig> {
    console.log("\n" + "=".repeat(60));
    console.log("CodeMantle Agent Setup");
    console.log("=".repeat(60) + "\n");

    this.emitProgress({
      phase: "configure",
      step: "interactive_setup",
      status: "running",
      progress: 0,
      message: "Starting interactive setup",
    });

    const isTty = process.stdin.isTTY && process.stdout.isTTY;

    let workspacePath: string;
    let controlPlaneUrl: string;
    let authToken: string;
    let startOnBoot = false;

    if (isTty && mode === "headless") {
      const workspaceResponse = await prompt<{ path: string }>({
        type: "input",
        name: "path",
        message: "Workspace path (where projects will be stored):",
        initial: process.cwd(),
      });
      workspacePath = path.resolve(workspaceResponse.path);

      this.emitProgress({
        phase: "configure",
        step: "workspace_path",
        status: "success",
        progress: 25,
        message: `Workspace: ${workspacePath}`,
      });

      const urlResponse = await prompt<{ url: string }>({
        type: "input",
        name: "url",
        message: "Control Plane URL:",
        initial: "wss://codemantle.cloud/ws",
      });
      controlPlaneUrl = urlResponse.url;

      this.emitProgress({
        phase: "configure",
        step: "control_plane_url",
        status: "success",
        progress: 50,
        message: `Control Plane: ${controlPlaneUrl}`,
      });

      const tokenResponse = await prompt<{ token: string }>({
        type: "password",
        name: "token",
        message: "Agent Auth Token:",
      });
      authToken = tokenResponse.token;

      this.emitProgress({
        phase: "configure",
        step: "auth_token",
        status: "success",
        progress: 75,
        message: "Auth token configured",
      });

      const bootResponse = await prompt<{ boot: boolean }>({
        type: "confirm",
        name: "boot",
        message: "Start agent automatically on system boot?",
        initial: false,
      });
      startOnBoot = bootResponse.boot;

      this.emitProgress({
        phase: "configure",
        step: "start_on_boot",
        status: "success",
        progress: 90,
        message: `Auto-start: ${startOnBoot ? "enabled" : "disabled"}`,
      });
    } else {
      workspacePath = process.cwd();
      controlPlaneUrl = process.env.CONTROL_PLANE_URL || "";
      authToken = process.env.AGENT_AUTH_TOKEN || "";

      if (!controlPlaneUrl || !authToken) {
        throw new Error("Missing required environment variables: CONTROL_PLANE_URL, AGENT_AUTH_TOKEN");
      }

      this.emitProgress({
        phase: "configure",
        step: "env_config",
        status: "success",
        progress: 50,
        message: "Using environment configuration",
      });
    }

    await mkdir(workspacePath, { recursive: true });

    const config: ProvisionerConfig = {
      workspacePath,
      controlPlaneUrl,
      authToken,
      runtimeMode: mode,
      startOnBoot,
    };

    this.config = config;

    await this.saveEnvFile(config);

    if (startOnBoot) {
      await this.configureStartOnBoot(config);
    }

    this.emitProgress({
      phase: "complete",
      step: "setup_complete",
      status: "success",
      progress: 100,
      message: "Setup complete! Run 'codemantle-agent' to start.",
    });

    console.log("\n" + "=".repeat(60));
    console.log("Setup Complete!");
    console.log("=".repeat(60));
    console.log(`Workspace: ${workspacePath}`);
    console.log(`Control Plane: ${controlPlaneUrl}`);
    console.log(`Auto-start: ${startOnBoot ? "enabled" : "disabled"}`);
    console.log("\nRun 'codemantle-agent' to start the agent daemon.");
    console.log("=".repeat(60) + "\n");

    return config;
  }

  async runUiBoxSetup(workspacePath: string, controlPlaneUrl: string, authToken: string, startOnBoot: boolean): Promise<ProvisionerConfig> {
    this.emitProgress({
      phase: "configure",
      step: "ui_box_setup",
      status: "running",
      progress: 0,
      message: "Starting UI-box setup",
    });

    await mkdir(workspacePath, { recursive: true });

    const config: ProvisionerConfig = {
      workspacePath,
      controlPlaneUrl,
      authToken,
      runtimeMode: "ui-box",
      startOnBoot,
    };

    this.config = config;

    this.emitProgress({
      phase: "configure",
      step: "ui_box_setup",
      status: "running",
      progress: 50,
      message: "Saving configuration",
    });

    await this.saveEnvFile(config);

    if (startOnBoot) {
      this.emitProgress({
        phase: "configure",
        step: "start_on_boot",
        status: "running",
        progress: 75,
        message: "Configuring auto-start",
      });
      await this.configureStartOnBoot(config);
    }

    this.emitProgress({
      phase: "complete",
      step: "setup_complete",
      status: "success",
      progress: 100,
      message: "UI-box setup complete",
    });

    return config;
  }

  private async saveEnvFile(config: ProvisionerConfig): Promise<void> {
    const envPath = path.join(config.workspacePath, ".env");

    const envContent = `# CodeMantle Agent Configuration
# Generated by codemantle-agent setup

# Control Plane connection
CONTROL_PLANE_URL=${config.controlPlaneUrl}
AGENT_AUTH_TOKEN=${config.authToken}

# Workspace configuration
AGENT_PROJECT_ROOT=${config.workspacePath}

# Runtime mode (headless or ui-box)
RUNTIME_MODE=${config.runtimeMode}

# OpenCode settings
OPENCODE_COMMAND=opencode
OPENCODE_HOST=127.0.0.1
OPENCODE_START_PORT=4096
OPENCODE_PROVIDER_ID=openai
OPENCODE_MODEL_ID=gpt-5.3-codex
`;

    await mkdir(config.workspacePath, { recursive: true });
    await writeFile(envPath, envContent, { mode: 0o600 });

    const gitignorePath = path.join(config.workspacePath, ".gitignore");
    try {
      const current = await readFile(gitignorePath, "utf8").catch(() => "");
      if (!current.includes(".env")) {
        const separator = current.endsWith("\n") ? "" : "\n";
        await writeFile(gitignorePath, `${current}${separator}.env\n`, "utf8");
      }
    } catch {
    }
  }

  async configureStartOnBoot(config: ProvisionerConfig): Promise<boolean> {
    const platform = os.platform();
    const serviceName = "codemantle-agent";

    this.emitProgress({
      phase: "configure",
      step: "start_on_boot",
      status: "running",
      progress: 0,
      message: `Configuring auto-start for ${platform}`,
    });

    try {
      if (platform === "win32") {
        return await this.configureWindowsService(config, serviceName);
      } else if (platform === "darwin") {
        return await this.configureMacOSLaunchAgent(config, serviceName);
      } else if (platform === "linux") {
        return await this.configureLinuxSystemd(config, serviceName);
      }

      this.emitProgress({
        phase: "configure",
        step: "start_on_boot",
        status: "error",
        progress: 100,
        message: `Auto-start not supported on ${platform}`,
      });
      return false;
    } catch (error) {
      this.emitProgress({
        phase: "configure",
        step: "start_on_boot",
        status: "error",
        progress: 100,
        message: error instanceof Error ? error.message : "Failed to configure auto-start",
      });
      return false;
    }
  }

  private async configureWindowsService(config: ProvisionerConfig, serviceName: string): Promise<boolean> {
    this.emitProgress({
      phase: "configure",
      step: "windows_service",
      status: "running",
      progress: 25,
      message: "Creating Windows scheduled task",
    });

    const scriptPath = path.join(config.workspacePath, ".codemantle", "start-agent.bat");
    await mkdir(path.dirname(scriptPath), { recursive: true });

    const batchContent = `@echo off
cd /d "${config.workspacePath}"
start /min codemantle-agent.exe
`;
    await writeFile(scriptPath, batchContent);

    const { code } = await this.execCommand(
      "schtasks",
      [
        "/Create",
        "/TN", serviceName,
        "/TR", `"${scriptPath}"`,
        "/SC", "ONLOGON",
        "/RL", "HIGHEST",
        "/F",
      ],
      30000,
    );

    const success = code === 0;
    this.emitProgress({
      phase: "configure",
      step: "windows_service",
      status: success ? "success" : "error",
      progress: 100,
      message: success
        ? "Windows scheduled task created"
        : "Failed to create Windows scheduled task",
    });

    return success;
  }

  private async configureMacOSLaunchAgent(config: ProvisionerConfig, serviceName: string): Promise<boolean> {
    this.emitProgress({
      phase: "configure",
      step: "macos_launchagent",
      status: "running",
      progress: 25,
      message: "Creating macOS LaunchAgent",
    });

    const plistPath = path.join(
      os.homedir(),
      "Library",
      "LaunchAgents",
      `com.codemantle.${serviceName}.plist`,
    );

    const scriptPath = path.join(config.workspacePath, ".codemantle", "start-agent.sh");
    await mkdir(path.dirname(scriptPath), { recursive: true });

    const scriptContent = `#!/bin/bash
cd "${config.workspacePath}"
export PATH="/usr/local/bin:$PATH"
"${process.execPath}" codemantle-agent
`;
    await writeFile(scriptPath, scriptContent);
    await chmod(scriptPath, 0o755);

    const plistContent = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.codemantle.${serviceName}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${scriptPath}</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${config.workspacePath}</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${config.workspacePath}/.codemantle/agent.log</string>
  <key>StandardErrorPath</key>
  <string>${config.workspacePath}/.codemantle/agent.error.log</string>
</dict>
</plist>
`;

    await writeFile(plistPath, plistContent);

    await this.execCommand("launchctl", ["unload", plistPath], 5000).catch(() => {});
    const { code } = await this.execCommand("launchctl", ["load", plistPath], 10000);

    const success = code === 0;
    this.emitProgress({
      phase: "configure",
      step: "macos_launchagent",
      status: success ? "success" : "error",
      progress: 100,
      message: success ? "macOS LaunchAgent created and loaded" : "Failed to load LaunchAgent",
    });

    return success;
  }

  private async configureLinuxSystemd(config: ProvisionerConfig, serviceName: string): Promise<boolean> {
    this.emitProgress({
      phase: "configure",
      step: "linux_systemd",
      status: "running",
      progress: 25,
      message: "Creating systemd service",
    });

    const servicePath = `/etc/systemd/system/${serviceName}.service`;

    const serviceContent = `[Unit]
Description=CodeMantle Agent Daemon
After=network.target

[Service]
Type=simple
User=${os.userInfo().username}
WorkingDirectory=${config.workspacePath}
Environment="PATH=/usr/local/bin:/usr/bin:/bin"
ExecStart=${process.execPath} codemantle-agent
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
`;

    const tempPath = path.join(os.tmpdir(), `${serviceName}.service`);
    await writeFile(tempPath, serviceContent);

    const { code: copyCode } = await this.execCommand("sudo", ["cp", tempPath, servicePath], 10000);
    if (copyCode !== 0) {
      this.emitProgress({
        phase: "configure",
        step: "linux_systemd",
        status: "error",
        progress: 100,
        message: "Failed to copy service file (sudo required)",
      });
      return false;
    }

    await this.execCommand("sudo", ["systemctl", "daemon-reload"], 10000);
    const { code: enableCode } = await this.execCommand(
      "sudo",
      ["systemctl", "enable", serviceName],
      10000,
    );

    const success = enableCode === 0;
    this.emitProgress({
      phase: "configure",
      step: "linux_systemd",
      status: success ? "success" : "error",
      progress: 100,
      message: success ? "systemd service created and enabled" : "Failed to enable systemd service",
    });

    return success;
  }

  async removeStartOnBoot(serviceName = "codemantle-agent"): Promise<boolean> {
    const platform = os.platform();

    try {
      if (platform === "win32") {
        const { code } = await this.execCommand("schtasks", ["/Delete", "/TN", serviceName, "/F"], 30000);
        return code === 0;
      } else if (platform === "darwin") {
        const plistPath = path.join(
          os.homedir(),
          "Library",
          "LaunchAgents",
          `com.codemantle.${serviceName}.plist`,
        );
        await this.execCommand("launchctl", ["unload", plistPath], 5000).catch(() => {});
        await unlink(plistPath).catch(() => {});
        return true;
      } else if (platform === "linux") {
        await this.execCommand("sudo", ["systemctl", "disable", serviceName], 10000);
        await this.execCommand("sudo", ["rm", `/etc/systemd/system/${serviceName}.service`], 10000);
        await this.execCommand("sudo", ["systemctl", "daemon-reload"], 10000);
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }

  getConfig(): ProvisionerConfig | null {
    return this.config;
  }
}

export async function runSetupWizard(mode: RuntimeMode = "headless"): Promise<ProvisionerConfig> {
  const provisioner = new Provisioner();
  return provisioner.runInteractiveSetup(mode);
}

export async function runDependencyProbe(): Promise<DependencyStatus[]> {
  const provisioner = new Provisioner();
  return provisioner.probeDependencies();
}

export async function runUiBoxSetupFromTauri(
  workspacePath: string,
  controlPlaneUrl: string,
  authToken: string,
  startOnBoot: boolean,
): Promise<ProvisionerConfig> {
  const provisioner = new Provisioner();
  return provisioner.runUiBoxSetup(workspacePath, controlPlaneUrl, authToken, startOnBoot);
}
