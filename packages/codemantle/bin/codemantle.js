#!/usr/bin/env node

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));

const AGENT_BIN_SPEC = "@codemantle/agent-daemon/bin/codemantle-agent.js";
const PANEL_BIN_SPEC = "@codemantle/panel/bin/codemantle-panel.js";

const args = process.argv.slice(2);

if (args.length === 0 || args[0] === "--help" || args[0] === "-h" || args[0] === "help") {
  printHelp();
  process.exit(0);
}

void route(args).then((code) => {
  process.exit(code);
}).catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`codemantle error: ${message}\n`);
  process.exit(1);
});

async function route(inputArgs) {
  if (inputArgs[0] === "agent" || inputArgs.includes("--agent")) {
    const forwarded = normalizeForwardedArgs(inputArgs, "agent", "--agent");
    return runAgent(forwarded);
  }

  if (inputArgs[0] === "panel" || inputArgs.includes("--panel")) {
    const forwarded = normalizeForwardedArgs(inputArgs, "panel", "--panel");
    return runPanel(forwarded);
  }

  if (inputArgs[0] === "setup") {
    return runSetup(inputArgs.slice(1));
  }

  throw new Error(`unknown command: ${inputArgs[0]}`);
}

async function runSetup(inputArgs) {
  const target = inputArgs[0] ?? "all";

  if (target === "agent") {
    return runAgent(["--setup", ...inputArgs.slice(1)]);
  }

  if (target === "panel") {
    return runPanel(["init", ...inputArgs.slice(1)]);
  }

  if (target !== "all") {
    throw new Error(`unknown setup target: ${target}`);
  }

  const panelCode = await runPanel(["init", ...inputArgs.slice(1)]);
  if (panelCode !== 0) {
    return panelCode;
  }
  return runAgent(["--setup"]);
}

function runAgent(forwardedArgs) {
  if (hasHelpRequest(forwardedArgs)) {
    printAgentHelp();
    return Promise.resolve(0);
  }
  const argsToRun = forwardedArgs.length > 0 ? forwardedArgs : ["--setup"];
  return runPackageBin(AGENT_BIN_SPEC, argsToRun);
}

function runPanel(forwardedArgs) {
  const argsToRun = forwardedArgs.length > 0 ? forwardedArgs : ["start"];
  return runPackageBin(PANEL_BIN_SPEC, argsToRun);
}

function normalizeForwardedArgs(inputArgs, commandToken, flagToken) {
  const out = [];
  for (let index = 0; index < inputArgs.length; index += 1) {
    const token = inputArgs[index];
    if (!token) {
      continue;
    }
    if (token === commandToken || token === flagToken) {
      continue;
    }
    out.push(token);
  }
  return out;
}

function hasHelpRequest(inputArgs) {
  return inputArgs.includes("--help") || inputArgs.includes("-h") || inputArgs.includes("help");
}

async function runPackageBin(specifier, forwardedArgs) {
  const resolved = resolvePackageMetadata(specifier);
  const childEnv = {
    ...process.env,
    ...(resolved.packageVersion && !process.env.npm_package_version
      ? { npm_package_version: resolved.packageVersion }
      : {}),
  };

  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [resolved.binPath, ...forwardedArgs], {
      stdio: "inherit",
      env: childEnv,
    });

    child.on("error", (error) => {
      reject(error);
    });

    child.on("exit", (code, signal) => {
      if (signal) {
        process.kill(process.pid, signal);
        return;
      }
      resolve(code ?? 0);
    });
  });
}

function resolvePackageMetadata(specifier) {
  try {
    const binPath = require.resolve(specifier);
    const packageVersion = readPackageVersion(specifier);
    return { binPath, packageVersion };
  } catch {
    const fallback = resolveWorkspaceFallback(specifier);
    if (fallback) {
      return fallback;
    }
    throw new Error(`unable to resolve ${specifier}. Reinstall with: npm i -g codemantle`);
  }
}

function resolveWorkspaceFallback(specifier) {
  if (specifier === PANEL_BIN_SPEC) {
    const localPath = path.resolve(scriptDirectory, "../../../apps/control-plane/bin/codemantle-panel.js");
    if (!existsSync(localPath)) {
      return null;
    }
    const packageVersion = readPackageVersionFromPath(path.resolve(scriptDirectory, "../../../apps/control-plane/package.json"));
    return { binPath: localPath, packageVersion };
  }
  if (specifier === AGENT_BIN_SPEC) {
    const localPath = path.resolve(scriptDirectory, "../../../packages/agent-daemon/bin/codemantle-agent.js");
    if (!existsSync(localPath)) {
      return null;
    }
    const packageVersion = readPackageVersionFromPath(path.resolve(scriptDirectory, "../../../packages/agent-daemon/package.json"));
    return { binPath: localPath, packageVersion };
  }
  return null;
}

function readPackageVersion(specifier) {
  if (specifier === PANEL_BIN_SPEC) {
    return readPackageVersionByName("@codemantle/panel");
  }
  if (specifier === AGENT_BIN_SPEC) {
    return readPackageVersionByName("@codemantle/agent-daemon");
  }
  return "";
}

function readPackageVersionByName(packageName) {
  try {
    const packageJsonPath = require.resolve(`${packageName}/package.json`);
    return readPackageVersionFromPath(packageJsonPath);
  } catch {
    return "";
  }
}

function readPackageVersionFromPath(packageJsonPath) {
  try {
    const payload = JSON.parse(readFileSync(packageJsonPath, "utf8"));
    if (typeof payload.version === "string") {
      return payload.version;
    }
    return "";
  } catch {
    return "";
  }
}

function printHelp() {
  process.stdout.write(
    [
      "codemantle",
      "",
      "Unified orchestrator CLI for CodeMantle panel and agent.",
      "",
      "Usage:",
      "  codemantle --panel [panel-args...]",
      "  codemantle --agent [agent-args...]",
      "  codemantle panel [panel-args...]",
      "  codemantle agent [agent-args...]",
      "  codemantle setup [all|panel|agent]",
      "",
      "Defaults:",
      "  codemantle --panel        => codemantle-panel start",
      "  codemantle --agent        => codemantle-agent --setup",
      "  codemantle setup panel    => codemantle-panel init",
      "  codemantle setup agent    => codemantle-agent --setup",
      "  codemantle setup          => panel init, then agent setup",
      "",
      "Examples:",
      "  codemantle --panel --env-file /opt/codemantle/.env",
      "  codemantle --agent",
      "  codemantle panel doctor --env-file /opt/codemantle/.env",
      "  codemantle agent --configure-env",
      "",
    ].join("\n"),
  );
}

function printAgentHelp() {
  process.stdout.write(
    [
      "codemantle agent",
      "",
      "Delegates to @codemantle/agent-daemon.",
      "",
      "Common usage:",
      "  codemantle --agent                # defaults to --setup",
      "  codemantle agent --setup",
      "  codemantle agent --configure-env",
      "  codemantle agent                  # start daemon with current env",
      "",
    ].join("\n"),
  );
}
