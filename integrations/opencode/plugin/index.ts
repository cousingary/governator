import { spawnSync } from "node:child_process";
import type { Plugin } from "@opencode-ai/plugin";

type GateDecision = {
	allow: boolean;
	reason: string;
	finding: string;
};

export const GovernatorGate: Plugin = async ({ directory }) => ({
	"permission.ask": async (input, output) => {
		const metadata = input.metadata as { command?: string; path?: string };
		const pattern = Array.isArray(input.pattern)
			? input.pattern.join(" ")
			: (input.pattern ?? "");
		const payload = JSON.stringify({
			tool: input.type,
			command: metadata.command ?? (input.type === "bash" ? pattern : ""),
			path: metadata.path ?? (input.type !== "bash" ? pattern : ""),
			cwd: directory,
		});
		const result = spawnSync("gov", ["gate", "check"], {
			input: payload,
			encoding: "utf8",
			timeout: 2000,
		});
		if (result.status !== 0 || !result.stdout.trim()) {
			output.status = "deny";
			return;
		}
		const decision = JSON.parse(result.stdout) as GateDecision;
		output.status = decision.allow ? "allow" : "deny";
	},
});

export default GovernatorGate;
