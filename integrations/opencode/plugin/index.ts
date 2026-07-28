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

export const GovernatorGate: Plugin = async ({ directory }) => ({
	// Primary gate. `tool.execute.before` fires on every tool call regardless of
	// the configured permission policy, so it works with `permission: allow` and
	// is not subject to the `permission.ask` bypass trap. Verified on 1.18.7.
	"tool.execute.before": async (input: any, output: any) => {
		const args = (output?.args ?? {}) as Record<string, unknown>;
		const decision = check(
			JSON.stringify({
				tool: input?.tool,
				command: (args.command as string) ?? "",
				path: (args.filePath as string) ?? (args.path as string) ?? "",
				cwd: directory,
			}),
		);
		if (!decision.allow) {
			throw new Error(`Governator denied: ${decision.reason}`);
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
