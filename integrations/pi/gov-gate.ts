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
			return undefined;
		},
	);
}
