import { spawn } from "node:child_process";
import type {
	ExtensionAPI,
	ToolCallEventResult,
} from "@mariozechner/pi-coding-agent";

type GateDecision = {
	allow: boolean;
	reason: string;
	finding: string;
};

function check(payload: Record<string, unknown>): Promise<GateDecision> {
	return new Promise((resolve, reject) => {
		const child = spawn("gov", ["gate", "check"], {
			stdio: ["pipe", "pipe", "pipe"],
		});
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (chunk: Buffer) => {
			stdout += chunk.toString();
		});
		child.stderr.on("data", (chunk: Buffer) => {
			stderr += chunk.toString();
		});
		child.on("error", reject);
		child.on("close", (code) => {
			if (code !== 0 || !stdout.trim()) {
				reject(new Error(stderr || "gov gate check returned no decision"));
				return;
			}
			resolve(JSON.parse(stdout) as GateDecision);
		});
		child.stdin.end(JSON.stringify(payload));
	});
}

const PI_AUDIT_TOOL_MAP: Record<string, string> = { bash: "Bash", write: "Write", edit: "Edit" };

// Embassy VPS-coordination lock check. Only fires an SSH round-trip for the
// rare coordinated-file case — everything else the script exits instantly.
// Fails OPEN on any failure (unreachable VPS/SSH/timeout), same guarantee
// embassy_coordination_hook.py itself makes.
function checkEmbassy(toolName: string, command: string, path: string): Promise<{ deny: boolean; reason: string }> {
	return new Promise((resolve) => {
		const child = spawn("python3", ["/home/lam/.claude/hooks/embassy_coordination_hook.py"], {
			stdio: ["pipe", "pipe", "ignore"],
		});
		let stdout = "";
		const timer = setTimeout(() => {
			child.kill();
			resolve({ deny: false, reason: "" });
		}, 10000);
		child.stdout.on("data", (chunk: Buffer) => {
			stdout += chunk.toString();
		});
		child.on("error", () => {
			clearTimeout(timer);
			resolve({ deny: false, reason: "" });
		});
		child.on("close", () => {
			clearTimeout(timer);
			try {
				const out = stdout.trim();
				if (!out) return resolve({ deny: false, reason: "" });
				const parsed = JSON.parse(out);
				const hso = parsed?.hookSpecificOutput;
				if (hso?.permissionDecision === "deny") {
					resolve({ deny: true, reason: hso.permissionDecisionReason ?? "Embassy coordination lock" });
				} else {
					resolve({ deny: false, reason: "" });
				}
			} catch {
				resolve({ deny: false, reason: "" });
			}
		});
		child.stdin.end(
			JSON.stringify({ tool_name: toolName, tool_input: { command, file_path: path } }),
		);
	});
}

export default function govGate(pi: ExtensionAPI) {
	pi.on(
		"tool_call",
		async (event, ctx): Promise<ToolCallEventResult | undefined> => {
			const input = event.input as { command?: string; path?: string };
			const decision = await check({
				tool: event.toolName,
				command: input.command ?? "",
				path: input.path ?? "",
				cwd: ctx.cwd,
			});
			if (!decision.allow) {
				return {
					block: true,
					reason: `Governator ${decision.finding}: ${decision.reason}`,
				};
			}
			const toolName = PI_AUDIT_TOOL_MAP[String(event.toolName ?? "").toLowerCase()];
			if (toolName) {
				const embassy = await checkEmbassy(toolName, input.command ?? "", input.path ?? "");
				if (embassy.deny) {
					return { block: true, reason: embassy.reason };
				}
			}
			return undefined;
		},
	);

	// Audit trail (F6 unification). Mirrors Claude Code's harness_audit.py
	// PostToolUse hook so Pi's Bash/Write/Edit calls land in the SAME shared
	// ledger (~/.governator/harness/state/claude_ledger.db), queryable via
	// `python3 claude_harness.py history` alongside Claude Code's and Codex's
	// own interactive calls. Best-effort: never throws, never blocks.
	pi.on("tool_result", (event: any) => {
		const rawToolName = String(event?.toolName ?? event?.tool_name ?? "").toLowerCase();
		const toolName = PI_AUDIT_TOOL_MAP[rawToolName];
		if (!toolName) return;
		const rawInput = { ...(event?.params ?? event?.input ?? {}) };
		if (rawInput.path !== undefined && rawInput.file_path === undefined) {
			rawInput.file_path = String(rawInput.path);
		}
		const payload = JSON.stringify({
			tool_name: toolName,
			tool_input: rawInput,
			tool_response: { error: event?.error || event?.isError ? "error" : null },
		});
		try {
			const child = spawn("python3", ["/home/lam/.claude/hooks/harness_audit.py"], {
				stdio: ["pipe", "ignore", "ignore"],
			});
			child.stdin.end(payload);
			child.on("error", () => {
				// Never let audit logging affect the tool call itself.
			});
		} catch {
			// Never let audit logging affect the tool call itself.
		}
	});
}
