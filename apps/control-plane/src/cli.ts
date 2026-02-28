import path from "node:path";
import { bootstrapEnvFile, envFileExists, migrateEnvFile, parseEnvFile } from "./bootstrap.js";
import { validatePanelEnv } from "./env-schema.js";

type ParsedArgs = {
  command: "start" | "init" | "migrate-env" | "doctor" | "help";
  envFilePath: string;
  nonInteractive: boolean;
  yes: boolean;
  force: boolean;
  write: boolean;
  overrides: Record<string, string>;
};

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.command === "help") {
    printHelp();
    return;
  }

  if (args.command === "init") {
    const result = await bootstrapEnvFile({
      envFilePath: args.envFilePath,
      nonInteractive: args.nonInteractive,
      yes: args.yes,
      force: args.force,
      overrides: args.overrides,
    });

    if (!result.created) {
      if (result.issues.length === 0) {
        process.stdout.write(`env file already exists: ${result.envFilePath}\n`);
      } else {
        process.stdout.write(`env file exists but has validation issues (${result.issues.length}):\n`);
        for (const issue of result.issues) {
          process.stdout.write(`- ${issue.key}: ${issue.message}\n`);
        }
      }
      return;
    }

    process.stdout.write(`created env file: ${result.envFilePath}\n`);
    return;
  }

  if (args.command === "migrate-env") {
    if (!await envFileExists(args.envFilePath)) {
      throw new Error(`env file not found: ${args.envFilePath}`);
    }
    const migration = await migrateEnvFile(args.envFilePath, args.write);
    if (migration.issues.length > 0) {
      process.stdout.write(`migration wrote ${migration.outputPath} with ${migration.issues.length} issue(s):\n`);
      for (const issue of migration.issues) {
        process.stdout.write(`- ${issue.key}: ${issue.message}\n`);
      }
      process.exitCode = 1;
      return;
    }
    process.stdout.write(`${migration.changed ? "updated" : "checked"} env file: ${migration.outputPath}\n`);
    return;
  }

  if (args.command === "doctor") {
    if (!await envFileExists(args.envFilePath)) {
      throw new Error(`env file not found: ${args.envFilePath}`);
    }
    const env = await parseEnvFile(args.envFilePath);
    const issues = validatePanelEnv(env);
    if (issues.length === 0) {
      process.stdout.write(`env health check passed: ${args.envFilePath}\n`);
      return;
    }
    process.stdout.write(`env health check found ${issues.length} issue(s):\n`);
    for (const issue of issues) {
      process.stdout.write(`- ${issue.key}: ${issue.message}\n`);
    }
    process.exitCode = 1;
    return;
  }

  await ensureEnvForStart(args);
  process.env.CONTROL_PLANE_ENV_FILE = args.envFilePath;
  await import("./index.js");
}

function parseArgs(argv: string[]): ParsedArgs {
  const output: ParsedArgs = {
    command: "start",
    envFilePath: path.resolve(process.cwd(), ".env"),
    nonInteractive: false,
    yes: false,
    force: false,
    write: false,
    overrides: {},
  };

  let commandSet = false;
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index]!;

    if (!token.startsWith("-") && !commandSet) {
      commandSet = true;
      output.command = parseCommand(token);
      continue;
    }

    if (token === "--non-interactive") {
      output.nonInteractive = true;
      continue;
    }
    if (token === "--yes") {
      output.yes = true;
      continue;
    }
    if (token === "--force") {
      output.force = true;
      continue;
    }
    if (token === "--write") {
      output.write = true;
      continue;
    }
    if (token === "--help" || token === "-h") {
      output.command = "help";
      continue;
    }

    if (token === "--env-file") {
      const value = argv[index + 1];
      if (!value) {
        throw new Error("missing value for --env-file");
      }
      output.envFilePath = path.resolve(process.cwd(), value);
      index += 1;
      continue;
    }

    if (token === "--config-dir") {
      const value = argv[index + 1];
      if (!value) {
        throw new Error("missing value for --config-dir");
      }
      output.envFilePath = path.resolve(process.cwd(), value, ".env");
      index += 1;
      continue;
    }

    if (token === "--set") {
      const value = argv[index + 1];
      if (!value) {
        throw new Error("missing KEY=VALUE for --set");
      }
      applySet(value, output.overrides);
      index += 1;
      continue;
    }

    if (token.startsWith("--set=")) {
      applySet(token.slice(6), output.overrides);
      continue;
    }

    throw new Error(`unknown argument: ${token}`);
  }

  return output;
}

function parseCommand(raw: string): ParsedArgs["command"] {
  if (raw === "start" || raw === "init" || raw === "migrate-env" || raw === "doctor") {
    return raw;
  }
  if (raw === "help") {
    return "help";
  }
  throw new Error(`unknown command: ${raw}`);
}

function applySet(raw: string, target: Record<string, string>): void {
  const split = raw.indexOf("=");
  if (split <= 0) {
    throw new Error(`invalid --set value: ${raw}`);
  }
  const key = raw.slice(0, split).trim();
  const value = raw.slice(split + 1);
  if (!/^[A-Z][A-Z0-9_]*$/.test(key)) {
    throw new Error(`invalid env key: ${key}`);
  }
  target[key] = value;
}

async function ensureEnvForStart(args: ParsedArgs): Promise<void> {
  if (await envFileExists(args.envFilePath)) {
    return;
  }

  const canPrompt = process.stdin.isTTY && process.stdout.isTTY;
  if (args.nonInteractive || !canPrompt) {
    const required = [
      "AUTH_OWNER_EMAIL",
      "AUTH_OWNER_PASSWORD_HASH (or AUTH_OWNER_PASSWORD)",
      "VALID_TOKENS",
    ];
    throw new Error(
      `missing env file at ${args.envFilePath}. Run 'codemantle-panel init --env-file "${args.envFilePath}"' or provide: ${required.join(", ")}`,
    );
  }

  process.stdout.write(`no env file found at ${args.envFilePath}. Starting first-run setup...\n`);
  await bootstrapEnvFile({
    envFilePath: args.envFilePath,
    nonInteractive: false,
    yes: false,
    force: false,
    overrides: args.overrides,
  });
}

function printHelp(): void {
  process.stdout.write(
    [
      "codemantle-panel",
      "",
      "Usage:",
      "  codemantle-panel [start] [--env-file <path>] [--config-dir <dir>] [--non-interactive]",
      "  codemantle-panel init [--env-file <path>] [--config-dir <dir>] [--set KEY=VALUE] [--yes] [--force]",
      "  codemantle-panel migrate-env [--env-file <path>] [--write]",
      "  codemantle-panel doctor [--env-file <path>]",
      "",
      "Notes:",
      "  - If start is called and no env file exists, interactive setup is launched in TTY mode.",
      "  - Use --non-interactive for headless environments.",
      "",
    ].join("\n"),
  );
}

void main().catch(async (error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`codemantle-panel error: ${message}\n`);
  process.exit(1);
});
