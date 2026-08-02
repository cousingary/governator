import { spawnSync } from "node:child_process";
import type { Plugin } from "@opencode-ai/plugin";

type GateDecision = {
	allow: boolean;
	reason: string;
	finding: string;
};

function check(payload: string): GateDecision {
	const result = spawnSync("gov", ["gate", "check"], {
		input: payload,
		encoding: "utf8",
		timeout: 2000,
	});
	if (result.status !== 0 || !result.stdout.trim()) {
		// Fail closed: a gate we cannot reach is a gate that denies.
		return { allow: false, reason: "governator gate unavailable", finding: "" };
	}
	return JSON.parse(result.stdout) as GateDecision;
}

// Embassy VPS-coordination lock check. Only fires an SSH round-trip for the
// rare coordinated-file case (telegram_bot.py, nginx.conf, crontab, ...) —
// everything else the script exits instantly. Fails OPEN (never blocks) on
// any failure — unreachable VPS/SSH/timeout is not a reason to stop working,
// same guarantee embassy_coordination_hook.py itself makes.
function checkEmbassy(toolName: string, command: string, filePath: string): { deny: boolean; reason: string } {
	try {
		const payload = JSON.stringify({
			tool_name: toolName,
			tool_input: { command, file_path: filePath },
		});
		const result = spawnSync("python3", ["/home/lam/.claude/hooks/embassy_coordination_hook.py"], {
			input: payload,
			encoding: "utf8",
			timeout: 10000,
		});
		const out = result.stdout?.trim();
		if (!out) return { deny: false, reason: "" };
		const parsed = JSON.parse(out);
		const hso = parsed?.hookSpecificOutput;
		if (hso?.permissionDecision === "deny") {
			return { deny: true, reason: hso.permissionDecisionReason ?? "Embassy coordination lock" };
		}
		return { deny: false, reason: "" };
	} catch {
		return { deny: false, reason: "" };
	}
}

export const GovernatorGate: Plugin = async ({ directory }) => ({
	// Primary gate. `tool.execute.before` fires on every tool call regardless of
	// the configured permission policy, so it works with `permission: allow` and
	// is not subject to the `permission.ask` bypass trap. Verified on 1.18.7.
	"tool.execute.before": async (input: any, output: any) => {
		const args = (output?.args ?? {}) as Record<string, unknown>;
		const command = (args.command as string) ?? "";
		const filePath = (args.filePath as string) ?? (args.path as string) ?? "";
		const decision = check(
			JSON.stringify({
				tool: input?.tool,
				command,
				path: filePath,
				cwd: directory,
			}),
		);
		if (!decision.allow) {
			throw new Error(`Governator denied: ${decision.reason}`);
		}
		const toolMap: Record<string, string> = { bash: "Bash", write: "Write", edit: "Edit" };
		const toolName = toolMap[String(input?.tool ?? "").toLowerCase()];
		if (toolName) {
			const embassy = checkEmbassy(toolName, command, filePath);
			if (embassy.deny) {
				throw new Error(embassy.reason);
			}
		}
	},

	// Audit trail (F6 unification). Mirrors Claude Code's harness_audit.py
	// PostToolUse hook so OpenCode's Bash/Write/Edit calls land in the SAME
	// shared ledger (~/.governator/harness/state/claude_ledger.db), queryable
	// via `python3 claude_harness.py history` alongside Claude Code's and
	// Codex's own interactive calls. Best-effort: never throws, never blocks.
	"tool.execute.after": async (input: any, output: any) => {
		const toolMap: Record<string, string> = { bash: "Bash", write: "Write", edit: "Edit" };
		const toolName = toolMap[String(input?.tool ?? "").toLowerCase()];
		if (!toolName) return;
		const args = (input?.args ?? {}) as Record<string, unknown>;
		const payload = JSON.stringify({
			tool_name: toolName,
			tool_input: {
				command: (args.command as string) ?? "",
				file_path: (args.filePath as string) ?? (args.path as string) ?? "",
			},
			tool_response: { error: output?.metadata?.error ?? null },
		});
		try {
			spawnSync("python3", ["/home/lam/.claude/hooks/harness_audit.py"], {
				input: payload,
				encoding: "utf8",
				timeout: 3000,
			});
		} catch {
			// Never let audit logging affect the tool call itself.
		}
	},

	// Legacy gate, retained for OpenCode runtimes older than 1.18.7 where
	// `tool.execute.before` is absent. Removed from the 1.18.7 runtime — it
	// never fires there, so on current versions this is inert, not redundant.
	"permission.ask": async (input, output) => {
		const metadata = input.metadata as { command?: string; path?: string };
		const pattern = Array.isArray(input.pattern)
			? input.pattern.join(" ")
			: (input.pattern ?? "");
		const decision = check(
			JSON.stringify({
				tool: input.type,
				command: metadata.command ?? (input.type === "bash" ? pattern : ""),
				path: metadata.path ?? (input.type !== "bash" ? pattern : ""),
				cwd: directory,
			}),
		);
		output.status = decision.allow ? "allow" : "deny";
	},
});

export default GovernatorGate;
