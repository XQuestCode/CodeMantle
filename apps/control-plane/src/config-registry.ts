import { createHash } from "node:crypto";

export const AGENT_TEMPLATE_SCHEMA = {
  $id: "https://codemantle.dev/schema/agent-template.v1.json",
  $schema: "https://json-schema.org/draft/2020-12/schema",
  title: "CodeMantle Agent Template",
  type: "object",
  additionalProperties: false,
  required: ["schemaVersion", "templateId", "templateVersion", "routing", "tools", "mcpRefs"],
  properties: {
    schemaVersion: { type: "string", const: "1.0.0" },
    templateId: { type: "string", pattern: "^[a-z0-9][a-z0-9_-]{2,63}$" },
    templateVersion: { type: "string", pattern: "^[A-Za-z0-9._-]{1,32}$" },
    name: { type: "string", minLength: 1, maxLength: 120 },
    description: { type: "string", minLength: 1, maxLength: 400 },
    routing: {
      type: "object",
      additionalProperties: false,
      required: ["defaultModel", "intents"],
      properties: {
        defaultModel: { type: "string", minLength: 3, maxLength: 120 },
        fallbackOrder: {
          type: "array",
          maxItems: 8,
          items: { type: "string", minLength: 3, maxLength: 120 },
        },
        priorityChain: {
          type: "array",
          minItems: 1,
          maxItems: 12,
          items: { type: "string", minLength: 3, maxLength: 120 },
        },
        intents: {
          type: "array",
          maxItems: 64,
          items: {
            type: "object",
            additionalProperties: false,
            required: ["id", "match", "rules"],
            properties: {
              id: { type: "string", pattern: "^[a-z0-9][a-z0-9_-]{1,63}$" },
              match: { type: "string", minLength: 1, maxLength: 200 },
              model: { type: "string", minLength: 3, maxLength: 120 },
              priority: { type: "integer", minimum: -1000, maximum: 1000 },
              rules: {
                type: "array",
                minItems: 1,
                maxItems: 32,
                items: { type: "string", minLength: 1, maxLength: 400 },
              },
            },
          },
        },
        profiles: {
          type: "array",
          maxItems: 32,
          items: {
            type: "object",
            additionalProperties: false,
            required: ["id", "priorityChain", "rules"],
            properties: {
              id: { type: "string", pattern: "^[a-z0-9][a-z0-9_-]{1,63}$" },
              match: { type: "string", minLength: 1, maxLength: 200 },
              priorityChain: {
                type: "array",
                minItems: 1,
                maxItems: 12,
                items: { type: "string", minLength: 3, maxLength: 120 },
              },
              rules: {
                type: "array",
                minItems: 1,
                maxItems: 32,
                items: { type: "string", minLength: 1, maxLength: 400 },
              },
            },
          },
        },
      },
    },
    policy: {
      type: "object",
      additionalProperties: false,
      required: ["mode"],
      properties: {
        mode: { enum: ["off", "read-only", "restricted"] },
      },
    },
    tools: {
      type: "object",
      additionalProperties: false,
      required: ["enabled", "permissions"],
      properties: {
        enabled: {
          type: "object",
          maxProperties: 256,
          additionalProperties: { type: "boolean" },
        },
        permissions: {
          type: "object",
          maxProperties: 256,
          additionalProperties: { enum: ["allow", "ask", "deny"] },
        },
      },
    },
    mcpRefs: {
      type: "array",
      maxItems: 64,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["serverId", "version", "alias"],
        properties: {
          serverId: { type: "string", pattern: "^[a-z0-9][a-z0-9_-]{1,63}$" },
          version: { type: "string", pattern: "^[A-Za-z0-9._-]{1,32}$" },
          alias: { type: "string", pattern: "^[a-z0-9][a-z0-9_-]{1,63}$" },
          status: { enum: ["disabled", "ask", "allow"] },
        },
      },
    },
  },
} as const;

export type ToolPermission = "allow" | "ask" | "deny";
export type PolicyMode = "off" | "read-only" | "restricted";
export type McpToolStatus = "disabled" | "ask" | "allow";

export type McpRegistryEntry = {
  serverId: string;
  version: string;
  type: "remote";
  url?: string;
  gatewayRef?: {
    gatewayId: string;
    serverPath: string;
  };
  headers?: Record<string, string>;
  enabledByDefault?: boolean;
};

export type AgentTemplate = {
  schemaVersion: "1.0.0";
  templateId: string;
  templateVersion: string;
  name?: string;
  description?: string;
  routing: {
    defaultModel: string;
    fallbackOrder: string[];
    priorityChain: string[];
    intents: Array<{
      id: string;
      match: string;
      model?: string;
      priority?: number;
      rules: string[];
    }>;
    profiles: Array<{
      id: string;
      match?: string;
      priorityChain: string[];
      rules: string[];
    }>;
  };
  policy: {
    mode: PolicyMode;
  };
  tools: {
    enabled: Record<string, boolean>;
    permissions: Record<string, ToolPermission>;
  };
  mcpRefs: Array<{
    serverId: string;
    version: string;
    alias: string;
    status: McpToolStatus;
  }>;
};

export type TemplateValidationResult =
  | { ok: true; template: AgentTemplate }
  | { ok: false; errors: string[] };

export type McpValidationResult =
  | { ok: true; entry: McpRegistryEntry }
  | { ok: false; errors: string[] };

export type CompileResult =
  | { ok: true; compiledConfig: Record<string, unknown>; digest: string; canonical: string }
  | { ok: false; errors: string[] };

export function validateMcpRegistryEntry(value: unknown): McpValidationResult {
  if (!isObject(value)) {
    return { ok: false, errors: ["mcp_entry_must_be_object"] };
  }
  if (!hasOnlyKeys(value, ["serverId", "version", "type", "url", "gatewayRef", "headers", "enabledByDefault"])) {
    return { ok: false, errors: ["mcp_entry_has_unknown_keys"] };
  }
  if (!matchPattern(value.serverId, /^[a-z0-9][a-z0-9_-]{1,63}$/)) {
    return { ok: false, errors: ["invalid_server_id"] };
  }
  if (!matchPattern(value.version, /^[A-Za-z0-9._-]{1,32}$/)) {
    return { ok: false, errors: ["invalid_server_version"] };
  }
  if (value.type !== "remote") {
    return { ok: false, errors: ["unsupported_mcp_type"] };
  }
  if (value.url !== undefined && !isValidUrl(value.url)) {
    return { ok: false, errors: ["invalid_mcp_url"] };
  }
  let gatewayRef: McpRegistryEntry["gatewayRef"] | undefined;
  if (value.gatewayRef !== undefined) {
    if (!isObject(value.gatewayRef) || !hasOnlyKeys(value.gatewayRef, ["gatewayId", "serverPath"])) {
      return { ok: false, errors: ["invalid_mcp_gateway_ref"] };
    }
    if (!matchPattern(value.gatewayRef.gatewayId, /^[a-z0-9][a-z0-9_-]{1,63}$/)) {
      return { ok: false, errors: ["invalid_mcp_gateway_id"] };
    }
    if (typeof value.gatewayRef.serverPath !== "string") {
      return { ok: false, errors: ["invalid_mcp_gateway_path"] };
    }
    const normalizedPath = normalizeGatewayServerPath(value.gatewayRef.serverPath);
    if (!normalizedPath) {
      return { ok: false, errors: ["invalid_mcp_gateway_path"] };
    }
    gatewayRef = {
      gatewayId: value.gatewayRef.gatewayId,
      serverPath: normalizedPath,
    };
  }
  if (!value.url && !gatewayRef) {
    return { ok: false, errors: ["mcp_endpoint_missing"] };
  }
  if (value.enabledByDefault !== undefined && typeof value.enabledByDefault !== "boolean") {
    return { ok: false, errors: ["invalid_enabled_by_default"] };
  }
  if (value.headers !== undefined) {
    if (!isObject(value.headers)) {
      return { ok: false, errors: ["invalid_mcp_headers"] };
    }
    for (const [headerName, headerValue] of Object.entries(value.headers)) {
      if (!/^[A-Za-z0-9-]{1,64}$/.test(headerName)) {
        return { ok: false, errors: ["invalid_mcp_header_name"] };
      }
      if (typeof headerValue !== "string" || headerValue.length < 1 || headerValue.length > 2048) {
        return { ok: false, errors: ["invalid_mcp_header_value"] };
      }
    }
  }

  const entry: McpRegistryEntry = {
    serverId: value.serverId,
    version: value.version,
    type: "remote",
    ...(value.url ? { url: value.url } : {}),
    ...(gatewayRef ? { gatewayRef } : {}),
    ...(value.headers ? { headers: sortRecord(value.headers) } : {}),
    ...(value.enabledByDefault !== undefined ? { enabledByDefault: value.enabledByDefault } : {}),
  };
  return { ok: true, entry };
}

export function validateAgentTemplate(value: unknown): TemplateValidationResult {
  if (!isObject(value)) {
    return { ok: false, errors: ["template_must_be_object"] };
  }
  if (!hasOnlyKeys(value, ["schemaVersion", "templateId", "templateVersion", "name", "description", "routing", "policy", "tools", "mcpRefs"])) {
    return { ok: false, errors: ["template_has_unknown_keys"] };
  }
  if (value.schemaVersion !== "1.0.0") {
    return { ok: false, errors: ["unsupported_schema_version"] };
  }
  if (!matchPattern(value.templateId, /^[a-z0-9][a-z0-9_-]{2,63}$/)) {
    return { ok: false, errors: ["invalid_template_id"] };
  }
  if (!matchPattern(value.templateVersion, /^[A-Za-z0-9._-]{1,32}$/)) {
    return { ok: false, errors: ["invalid_template_version"] };
  }
  if (value.name !== undefined && !shortString(value.name, 120)) {
    return { ok: false, errors: ["invalid_template_name"] };
  }
  if (value.description !== undefined && !shortString(value.description, 400)) {
    return { ok: false, errors: ["invalid_template_description"] };
  }

  const routing = normalizeRouting(value.routing);
  if (!routing.ok) {
    return { ok: false, errors: routing.errors };
  }

  const policy = normalizePolicy(value.policy);
  if (!policy.ok) {
    return { ok: false, errors: policy.errors };
  }

  const tools = normalizeTools(value.tools);
  if (!tools.ok) {
    return { ok: false, errors: tools.errors };
  }

  const refs = normalizeMcpRefs(value.mcpRefs);
  if (!refs.ok) {
    return { ok: false, errors: refs.errors };
  }

  const template: AgentTemplate = {
    schemaVersion: "1.0.0",
    templateId: value.templateId,
    templateVersion: value.templateVersion,
    ...(value.name ? { name: value.name } : {}),
    ...(value.description ? { description: value.description } : {}),
    routing: routing.routing,
    policy: policy.policy,
    tools: tools.tools,
    mcpRefs: refs.refs,
  };

  return { ok: true, template };
}

export function compileTemplateToRuntimeConfig(
  template: AgentTemplate,
  resolveMcpEntry: (serverId: string, version: string) => McpRegistryEntry | undefined,
  options?: {
    resolveGatewayUrl?: (gatewayId: string, serverPath: string) => string | undefined;
  },
): CompileResult {
  const missingRefs: string[] = [];
  const compiledMcp: Record<string, unknown> = {};

  for (const ref of [...template.mcpRefs].sort((left, right) => left.alias.localeCompare(right.alias))) {
    const registryEntry = resolveMcpEntry(ref.serverId, ref.version);
    if (!registryEntry) {
      missingRefs.push(`${ref.serverId}@${ref.version}`);
      continue;
    }
    const resolvedEndpoint = resolveMcpEndpoint(registryEntry, options?.resolveGatewayUrl);
    if (!resolvedEndpoint.ok) {
      missingRefs.push(`${ref.serverId}@${ref.version}:${resolvedEndpoint.error}`);
      continue;
    }
    compiledMcp[ref.alias] = {
      type: registryEntry.type,
      url: resolvedEndpoint.url,
      enabled: ref.status !== "disabled",
      status: ref.status,
      ...(registryEntry.headers ? { headers: registryEntry.headers } : {}),
      ...(registryEntry.gatewayRef ? { gatewayRef: registryEntry.gatewayRef } : {}),
    };
  }

  if (missingRefs.length > 0) {
    return { ok: false, errors: [`missing_mcp_refs:${missingRefs.join(",")}`] };
  }

  const fallbackOrder = derivePriorityChain(template.routing.defaultModel, template.routing.priorityChain);

  const compiled: Record<string, unknown> = {
    $schema: "https://opencode.ai/config.json",
    model: fallbackOrder[0],
    permission: sortRecord(template.tools.permissions),
    tools: sortRecord(template.tools.enabled),
    ...(Object.keys(compiledMcp).length > 0 ? { mcp: compiledMcp } : {}),
    codemantle: {
      schemaVersion: template.schemaVersion,
      templateId: template.templateId,
      templateVersion: template.templateVersion,
      policy: template.policy,
      routing: {
        fallbackOrder,
        priorityChain: fallbackOrder,
        intents: template.routing.intents,
        profiles: template.routing.profiles,
      },
      mcpRefs: template.mcpRefs,
    },
  };

  const canonical = toCanonicalJson(compiled);
  return {
    ok: true,
    compiledConfig: compiled,
    canonical,
    digest: createHash("sha256").update(canonical).digest("base64url"),
  };
}

export function compileTemplateToSessionInitConfig(
  template: AgentTemplate,
  resolveMcpEntry: (serverId: string, version: string) => McpRegistryEntry | undefined,
): CompileResult {
  const missingRefs: string[] = [];
  const mcpTools: Array<{
    alias: string;
    serverId: string;
    version: string;
    type: "remote";
    status: McpToolStatus;
  }> = [];

  for (const ref of [...template.mcpRefs].sort((left, right) => left.alias.localeCompare(right.alias))) {
    const registryEntry = resolveMcpEntry(ref.serverId, ref.version);
    if (!registryEntry) {
      missingRefs.push(`${ref.serverId}@${ref.version}`);
      continue;
    }
    mcpTools.push({
      alias: ref.alias,
      serverId: ref.serverId,
      version: ref.version,
      type: registryEntry.type,
      status: ref.status,
    });
  }

  if (missingRefs.length > 0) {
    return { ok: false, errors: [`missing_mcp_refs:${missingRefs.join(",")}`] };
  }

  const priorityChain = derivePriorityChain(template.routing.defaultModel, template.routing.priorityChain);
  const providers = deriveProviders(priorityChain, template.routing.intents, template.routing.profiles);

  const compiled: Record<string, unknown> = {
    codemantle: {
      schemaVersion: template.schemaVersion,
      templateId: template.templateId,
      templateVersion: template.templateVersion,
      phase: "session-init",
      scope: "session-init",
      policy: template.policy,
      sessionInit: {
        providers,
        routing: {
          defaultModel: template.routing.defaultModel,
          priorityChain,
          intents: template.routing.intents,
          profiles: template.routing.profiles,
        },
        mcp: {
          tools: mcpTools,
        },
      },
    },
  };

  const canonical = toCanonicalJson(compiled);
  return {
    ok: true,
    compiledConfig: compiled,
    canonical,
    digest: createHash("sha256").update(canonical).digest("base64url"),
  };
}

export function toCanonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function normalizeRouting(value: unknown):
  | { ok: true; routing: AgentTemplate["routing"] }
  | { ok: false; errors: string[] } {
  if (!isObject(value)) {
    return { ok: false, errors: ["invalid_routing"] };
  }
  if (!hasOnlyKeys(value, ["defaultModel", "fallbackOrder", "priorityChain", "intents", "profiles"])) {
    return { ok: false, errors: ["routing_has_unknown_keys"] };
  }
  if (!shortString(value.defaultModel, 120)) {
    return { ok: false, errors: ["invalid_default_model"] };
  }
  if (!Array.isArray(value.intents) || value.intents.length > 64) {
    return { ok: false, errors: ["invalid_intents"] };
  }

  const fallbackOrder: string[] = [];
  if (value.fallbackOrder !== undefined) {
    if (!Array.isArray(value.fallbackOrder) || value.fallbackOrder.length > 8) {
      return { ok: false, errors: ["invalid_fallback_order"] };
    }
    for (const modelId of value.fallbackOrder) {
      if (!shortString(modelId, 120)) {
        return { ok: false, errors: ["invalid_fallback_order_model"] };
      }
      fallbackOrder.push(modelId);
    }
  }

  const configuredPriorityChain: string[] = [];
  if (value.priorityChain !== undefined) {
    if (!Array.isArray(value.priorityChain) || value.priorityChain.length < 1 || value.priorityChain.length > 12) {
      return { ok: false, errors: ["invalid_priority_chain"] };
    }
    for (const modelId of value.priorityChain) {
      if (!shortString(modelId, 120)) {
        return { ok: false, errors: ["invalid_priority_chain_model"] };
      }
      configuredPriorityChain.push(modelId);
    }
  }

  const intentIds = new Set<string>();
  const intents: AgentTemplate["routing"]["intents"] = [];

  for (const item of value.intents) {
    if (!isObject(item) || !hasOnlyKeys(item, ["id", "match", "model", "priority", "rules"])) {
      return { ok: false, errors: ["invalid_intent_entry"] };
    }
    if (!matchPattern(item.id, /^[a-z0-9][a-z0-9_-]{1,63}$/)) {
      return { ok: false, errors: ["invalid_intent_id"] };
    }
    if (intentIds.has(item.id)) {
      return { ok: false, errors: ["duplicate_intent_id"] };
    }
    if (!shortString(item.match, 200)) {
      return { ok: false, errors: ["invalid_intent_match"] };
    }
    if (item.model !== undefined && !shortString(item.model, 120)) {
      return { ok: false, errors: ["invalid_intent_model"] };
    }
    if (item.priority !== undefined && (!Number.isInteger(item.priority) || item.priority < -1000 || item.priority > 1000)) {
      return { ok: false, errors: ["invalid_intent_priority"] };
    }
    if (!Array.isArray(item.rules) || item.rules.length < 1 || item.rules.length > 32) {
      return { ok: false, errors: ["invalid_intent_rules"] };
    }
    const rules: string[] = [];
    for (const rule of item.rules) {
      if (!shortString(rule, 400)) {
        return { ok: false, errors: ["invalid_intent_rule"] };
      }
      rules.push(rule);
    }
    rules.sort((left, right) => left.localeCompare(right));
    intents.push({
      id: item.id,
      match: item.match,
      ...(item.model ? { model: item.model } : {}),
      ...(item.priority !== undefined ? { priority: item.priority } : {}),
      rules,
    });
    intentIds.add(item.id);
  }

  intents.sort((left, right) => {
    const leftPriority = left.priority ?? 0;
    const rightPriority = right.priority ?? 0;
    if (leftPriority !== rightPriority) {
      return rightPriority - leftPriority;
    }
    return left.id.localeCompare(right.id);
  });

  const profileIds = new Set<string>();
  const profiles: AgentTemplate["routing"]["profiles"] = [];
  if (value.profiles !== undefined) {
    if (!Array.isArray(value.profiles) || value.profiles.length > 32) {
      return { ok: false, errors: ["invalid_routing_profiles"] };
    }
    for (const item of value.profiles) {
      if (!isObject(item) || !hasOnlyKeys(item, ["id", "match", "priorityChain", "rules"])) {
        return { ok: false, errors: ["invalid_routing_profile_entry"] };
      }
      if (!matchPattern(item.id, /^[a-z0-9][a-z0-9_-]{1,63}$/)) {
        return { ok: false, errors: ["invalid_routing_profile_id"] };
      }
      if (profileIds.has(item.id)) {
        return { ok: false, errors: ["duplicate_routing_profile_id"] };
      }
      if (item.match !== undefined && !shortString(item.match, 200)) {
        return { ok: false, errors: ["invalid_routing_profile_match"] };
      }
      if (!Array.isArray(item.priorityChain) || item.priorityChain.length < 1 || item.priorityChain.length > 12) {
        return { ok: false, errors: ["invalid_routing_profile_priority_chain"] };
      }
      const profilePriorityChain: string[] = [];
      for (const modelId of item.priorityChain) {
        if (!shortString(modelId, 120)) {
          return { ok: false, errors: ["invalid_routing_profile_priority_model"] };
        }
        profilePriorityChain.push(modelId);
      }
      if (!Array.isArray(item.rules) || item.rules.length < 1 || item.rules.length > 32) {
        return { ok: false, errors: ["invalid_routing_profile_rules"] };
      }
      const profileRules: string[] = [];
      for (const rule of item.rules) {
        if (!shortString(rule, 400)) {
          return { ok: false, errors: ["invalid_routing_profile_rule"] };
        }
        profileRules.push(rule);
      }
      profileRules.sort((left, right) => left.localeCompare(right));
      profiles.push({
        id: item.id,
        ...(item.match ? { match: item.match } : {}),
        priorityChain: profilePriorityChain,
        rules: profileRules,
      });
      profileIds.add(item.id);
    }
  }
  profiles.sort((left, right) => left.id.localeCompare(right.id));

  const priorityChain = derivePriorityChain(value.defaultModel, configuredPriorityChain.length > 0 ? configuredPriorityChain : fallbackOrder);

  return {
    ok: true,
    routing: {
      defaultModel: value.defaultModel,
      fallbackOrder,
      priorityChain,
      intents,
      profiles,
    },
  };
}

function normalizePolicy(value: unknown):
  | { ok: true; policy: AgentTemplate["policy"] }
  | { ok: false; errors: string[] } {
  if (value === undefined) {
    return { ok: true, policy: { mode: "off" } };
  }
  if (!isObject(value) || !hasOnlyKeys(value, ["mode"])) {
    return { ok: false, errors: ["invalid_policy"] };
  }
  if (value.mode !== "off" && value.mode !== "read-only" && value.mode !== "restricted") {
    return { ok: false, errors: ["invalid_policy_mode"] };
  }
  return { ok: true, policy: { mode: value.mode } };
}

function normalizeTools(value: unknown):
  | { ok: true; tools: AgentTemplate["tools"] }
  | { ok: false; errors: string[] } {
  if (!isObject(value)) {
    return { ok: false, errors: ["invalid_tools"] };
  }
  if (!hasOnlyKeys(value, ["enabled", "permissions"])) {
    return { ok: false, errors: ["tools_has_unknown_keys"] };
  }
  if (!isObject(value.enabled) || !isObject(value.permissions)) {
    return { ok: false, errors: ["invalid_tools_maps"] };
  }

  const enabled: Record<string, boolean> = {};
  for (const [toolName, toolEnabled] of Object.entries(value.enabled)) {
    if (!matchPattern(toolName, /^[A-Za-z0-9_*:-]{1,80}$/) || typeof toolEnabled !== "boolean") {
      return { ok: false, errors: ["invalid_tool_enabled_entry"] };
    }
    enabled[toolName] = toolEnabled;
  }

  const permissions: Record<string, ToolPermission> = {};
  for (const [permissionName, permissionValue] of Object.entries(value.permissions)) {
    if (!matchPattern(permissionName, /^[A-Za-z0-9_*:-]{1,120}$/)) {
      return { ok: false, errors: ["invalid_tool_permission_key"] };
    }
    if (permissionValue !== "allow" && permissionValue !== "ask" && permissionValue !== "deny") {
      return { ok: false, errors: ["invalid_tool_permission_value"] };
    }
    permissions[permissionName] = permissionValue;
  }

  return { ok: true, tools: { enabled: sortRecord(enabled), permissions: sortRecord(permissions) } };
}

function normalizeMcpRefs(value: unknown):
  | { ok: true; refs: AgentTemplate["mcpRefs"] }
  | { ok: false; errors: string[] } {
  if (!Array.isArray(value) || value.length > 64) {
    return { ok: false, errors: ["invalid_mcp_refs"] };
  }

  const seenAliases = new Set<string>();
  const refs: AgentTemplate["mcpRefs"] = [];
  for (const item of value) {
    if (!isObject(item) || !hasOnlyKeys(item, ["serverId", "version", "alias", "status"])) {
      return { ok: false, errors: ["invalid_mcp_ref_entry"] };
    }
    if (!matchPattern(item.serverId, /^[a-z0-9][a-z0-9_-]{1,63}$/)) {
      return { ok: false, errors: ["invalid_mcp_ref_server_id"] };
    }
    if (!matchPattern(item.version, /^[A-Za-z0-9._-]{1,32}$/)) {
      return { ok: false, errors: ["invalid_mcp_ref_version"] };
    }
    if (!matchPattern(item.alias, /^[a-z0-9][a-z0-9_-]{1,63}$/)) {
      return { ok: false, errors: ["invalid_mcp_ref_alias"] };
    }
    if (seenAliases.has(item.alias)) {
      return { ok: false, errors: ["duplicate_mcp_alias"] };
    }
    if (item.status !== undefined && item.status !== "disabled" && item.status !== "ask" && item.status !== "allow") {
      return { ok: false, errors: ["invalid_mcp_status"] };
    }
    seenAliases.add(item.alias);
    refs.push({
      serverId: item.serverId,
      version: item.version,
      alias: item.alias,
      status: item.status ?? "disabled",
    });
  }

  refs.sort((left, right) => left.alias.localeCompare(right.alias));
  return { ok: true, refs };
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => sortValue(entry));
  }
  if (isObject(value)) {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort((left, right) => left.localeCompare(right))) {
      out[key] = sortValue(value[key]);
    }
    return out;
  }
  return value;
}

function sortRecord<T extends string | number | boolean>(value: Record<string, T>): Record<string, T> {
  const sorted: Record<string, T> = {};
  for (const key of Object.keys(value).sort((left, right) => left.localeCompare(right))) {
    sorted[key] = value[key]!;
  }
  return sorted;
}

function isObject(value: unknown): value is Record<string, any> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const known = new Set(keys);
  for (const key of Object.keys(value)) {
    if (!known.has(key)) {
      return false;
    }
  }
  return true;
}

function shortString(value: unknown, maxLength: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength;
}

function matchPattern(value: unknown, pattern: RegExp): value is string {
  return typeof value === "string" && pattern.test(value);
}

function isValidUrl(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 8 || value.length > 2048) {
    return false;
  }
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function normalizeGatewayServerPath(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 256 || trimmed.includes("\0")) {
    return null;
  }
  const normalized = trimmed.replace(/\\/g, "/").replace(/^\/+/, "");
  if (!normalized || normalized.startsWith(".") || normalized.includes("..") || normalized.includes("://")) {
    return null;
  }
  if (!/^[A-Za-z0-9/_-]+$/.test(normalized)) {
    return null;
  }
  return normalized;
}

function resolveMcpEndpoint(
  entry: McpRegistryEntry,
  resolveGatewayUrl?: (gatewayId: string, serverPath: string) => string | undefined,
): { ok: true; url: string } | { ok: false; error: string } {
  if (entry.gatewayRef) {
    const resolved = resolveGatewayUrl?.(entry.gatewayRef.gatewayId, entry.gatewayRef.serverPath);
    if (!resolved || !isValidUrl(resolved)) {
      return { ok: false, error: "gateway_resolution_failed" };
    }
    return { ok: true, url: resolved };
  }
  if (entry.url && isValidUrl(entry.url)) {
    return { ok: true, url: entry.url };
  }
  return { ok: false, error: "endpoint_missing" };
}

function derivePriorityChain(defaultModel: string, configuredOrder: string[]): string[] {
  const preferred = [defaultModel, ...configuredOrder];
  const seen = new Set<string>();
  const order: string[] = [];
  for (const modelId of preferred) {
    if (!modelId || seen.has(modelId)) {
      continue;
    }
    seen.add(modelId);
    order.push(modelId);
  }
  return order;
}

function deriveProviders(
  priorityChain: string[],
  intents: AgentTemplate["routing"]["intents"],
  profiles: AgentTemplate["routing"]["profiles"],
): string[] {
  const providers = new Set<string>();
  for (const modelId of priorityChain) {
    const providerId = readProviderId(modelId);
    if (providerId) {
      providers.add(providerId);
    }
  }
  for (const intent of intents) {
    const providerId = readProviderId(intent.model);
    if (providerId) {
      providers.add(providerId);
    }
  }
  for (const profile of profiles) {
    for (const modelId of profile.priorityChain) {
      const providerId = readProviderId(modelId);
      if (providerId) {
        providers.add(providerId);
      }
    }
  }
  return Array.from(providers).sort((left, right) => left.localeCompare(right));
}

function readProviderId(modelId: unknown): string | undefined {
  if (typeof modelId !== "string" || modelId.length < 3) {
    return undefined;
  }
  const slash = modelId.indexOf("/");
  if (slash < 1) {
    return undefined;
  }
  const provider = modelId.slice(0, slash);
  return /^[a-z0-9][a-z0-9_-]{1,63}$/.test(provider) ? provider : undefined;
}
