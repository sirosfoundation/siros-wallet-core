//! The engine's MCP tool surface (issue #76): the tool registry as a
//! [`Profile`], `tools/list` and `tools/call` over the WMP JSON-RPC transport
//! — the envelope MCP shares by design (wmp-core.md §2: "MCP Compatibility —
//! share the JSON-RPC 2.0 envelope format and capability negotiation
//! pattern").
//!
//! The methods ride the registry's custom-method dispatch (peer.rs
//! `dispatch_method_internal`'s `lookup_method` arm), so no wmp-core table
//! entry is needed; the method names are the MCP spec's own.
//!
//! The negotiation (core §10.3): the `mcp` capability is active on a session
//! only when BOTH sides offered it — the session create's
//! `capabilities_offered.mcp` and the engine's supported set (the `mcp`
//! params [`McpToolProfile::capability`] builds, merged into the session
//! service's supported set at handler build). A `tools/*` call on a session
//! that did not negotiate it answers `-31005` (capability not supported),
//! exactly as the flows gate refuses.
//!
//! The first registry: the `wallet.debug` toolset — the engine's live state as
//! tools an agent (the MCP client; the first acceptance test joins it via a
//! wallet-to-wallet invitation, #77) can call. Later tools — QERDS records,
//! the address book — register on the same surface.

use std::sync::Arc;

use wmp_core::context::RequestContext;
use wmp_core::error::{RpcError, ERR_CAPABILITY_NOT_SUPPORTED, ERR_INVALID_PARAMS};
use wmp_core::handler::HandlerError;
use wmp_core::profile::{DispatchResult, PeerContext, Profile};
use wmp_core::types::McpCap;

/// `tools/list` — the MCP discovery method (the spec's own name, riding the
/// registry's custom-method dispatch).
pub const METHOD_TOOLS_LIST: &str = "tools/list";
/// `tools/call` — the MCP invocation method.
pub const METHOD_TOOLS_CALL: &str = "tools/call";

/// The capability name (`capabilities_offered` / the negotiated set).
pub const CAPABILITY_MCP: &str = "mcp";

/// One registered tool.
#[derive(Debug, Clone)]
pub struct Tool {
    /// The tool's name (the `tools/call` argument): namespaced
    /// `wallet.debug.status`-style.
    pub name: String,
    /// The human description (the `tools/list` answer's `description`).
    pub description: String,
    /// The input schema, JSON (the `tools/list` answer's `inputSchema`).
    pub input_schema: serde_json::Value,
}

/// The `wallet.debug` toolset: the engine's live state as tools. Read-only;
/// the answers name the counters the later PRs thread through the registry's
/// construction.
fn debug_tools() -> Vec<Tool> {
    vec![
        Tool {
            name: "wallet.debug.status".to_owned(),
            description: "The engine's live state: the sessions, the in-flight flows \
                          (type, step, age), the ask queue depth, the outbox backlog."
                .to_owned(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
            }),
        },
        Tool {
            name: "wallet.debug.config".to_owned(),
            description: "The engine's negotiated capabilities and settings, redacted \
                          (no secrets, no key material)."
                .to_owned(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
            }),
        },
    ]
}

/// The MCP tool registry as a profile: the engine's `tools/list` answer and
/// `tools/call` dispatch, gated on the session's negotiated `mcp`
/// capability.
pub struct McpToolProfile {
    tools: Vec<Tool>,
    /// Whether this engine answers MCP tools at all (`ENGINE_MCP_TOOLS`):
    /// false opts the engine out — the supported set carries no `mcp` params
    /// so no session negotiates the capability, and every `tools/*` call
    /// answers `-31005`.
    enabled: bool,
}

impl McpToolProfile {
    /// The registry with the `wallet.debug` toolset.
    pub fn new(enabled: bool) -> Self {
        Self {
            tools: debug_tools(),
            enabled,
        }
    }

    /// The `mcp` capability's supported-side params — merged into the
    /// session service's supported set at handler build, so the negotiation
    /// (core §10.3) picks them for any session that offered the capability.
    pub fn capability(&self) -> McpCap {
        McpCap {
            tools: self.enabled,
            resources: false,
            prompts: false,
        }
    }

    /// The gate: whether the session negotiated the `mcp` capability. `None`
    /// session fails closed (the peer resolved no session; a tools call has
    /// no business running without one).
    fn session_negotiated(&self, ctx: &RequestContext) -> Result<(), HandlerError> {
        if !self.enabled {
            return Err(not_supported("this engine answers no MCP tools"));
        }
        let session = ctx
            .session
            .as_ref()
            .ok_or_else(|| not_supported("no session: the tools surface rides a session"))?;
        if !session.capabilities.0.contains_key(CAPABILITY_MCP) {
            return Err(not_supported(
                "the session did not negotiate the mcp capability",
            ));
        }
        Ok(())
    }

    /// `tools/list`: every tool's name, description and schema.
    fn list(&self, ctx: &RequestContext) -> DispatchResult {
        self.session_negotiated(ctx)?;
        Ok(Some(serde_json::json!({
            "tools": self.tools.iter().map(|tool| {
                serde_json::json!({
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.input_schema,
                })
            }).collect::<Vec<_>>(),
        })))
    }

    /// `tools/call`: one tool by name, its `arguments`, the answer.
    /// `-32602` for an unknown tool (the envelope's invalid-params code).
    fn call(&self, ctx: &RequestContext, params: &serde_json::Value) -> DispatchResult {
        self.session_negotiated(ctx)?;
        let name = params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| HandlerError::Rpc(RpcError::code(ERR_INVALID_PARAMS)))?;
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or(serde_json::json!({}));
        let Some(_tool) = self.tools.iter().find(|tool| tool.name == name) else {
            return Err(not_a_tool(name));
        };
        debug_call(name, &arguments)
    }
}

impl Profile for McpToolProfile {
    fn name(&self) -> String {
        "mcp-tools".to_owned()
    }

    /// The profile needs no peer context: the tools answer from the engine's
    /// own state; nothing is sent unprompted.
    fn init(&self, _ctx: Arc<dyn PeerContext>) -> Result<(), HandlerError> {
        Ok(())
    }

    /// The `mcp` capability this profile provides — the negotiation's
    /// profile-activation names (`ENGINE_MCP_TOOLS=false` carries none, so
    /// the capability is never active).
    fn capabilities(&self) -> Vec<String> {
        if self.enabled {
            vec![CAPABILITY_MCP.to_owned()]
        } else {
            Vec::new()
        }
    }

    /// The custom methods this profile handles: the MCP spec's own two.
    fn methods(&self) -> Vec<String> {
        vec![METHOD_TOOLS_LIST.to_owned(), METHOD_TOOLS_CALL.to_owned()]
    }

    /// The dispatch. The `tools/*` methods answer only as requests — a
    /// notification is dropped by the envelope before the profile sees it
    /// (`RequestContext::is_notification`), which is correct for MCP: both
    /// methods return answers.
    fn handle_method(
        &self,
        ctx: &RequestContext,
        method: &str,
        params: &serde_json::Value,
    ) -> DispatchResult {
        match method {
            METHOD_TOOLS_LIST => self.list(ctx),
            METHOD_TOOLS_CALL => self.call(ctx, params),
            _ => Err(HandlerError::Rpc(RpcError::code(
                wmp_core::error::ERR_METHOD_NOT_FOUND,
            ))),
        }
    }
}

/// The `-31005` refusal: the session may not use the tools surface.
fn not_supported(reason: &str) -> HandlerError {
    HandlerError::Rpc(RpcError::new(
        ERR_CAPABILITY_NOT_SUPPORTED,
        Some(serde_json::json!({ "reason": reason })),
    ))
}

/// The `-32602` for an unknown tool.
fn not_a_tool(name: &str) -> HandlerError {
    HandlerError::Rpc(RpcError::new(
        ERR_INVALID_PARAMS,
        Some(serde_json::json!({ "reason": "unknown tool", "tool": name })),
    ))
}

/// The read-only debug answers. The state tools answer from the engine's own
/// view — the later PRs thread the real counters (the sessions, the
/// in-flight flows) through the profile's construction; the names and the
/// routing land first, so the acceptance test's `wallet.debug` round-trip
/// works end to end.
fn debug_call(name: &str, _arguments: &serde_json::Value) -> DispatchResult {
    let text = match name {
        "wallet.debug.status" => {
            "engine: ok (the live counters thread through the profile's \
             construction; the names and the routing land first)"
        }
        "wallet.debug.config" => {
            "engine config: mcp tools enabled (the redacted settings surface \
             lands with the real counters)"
        }
        _ => return Err(not_a_tool(name)),
    };
    Ok(Some(serde_json::json!({
        "content": [{ "type": "text", "text": text }],
    })))
}
