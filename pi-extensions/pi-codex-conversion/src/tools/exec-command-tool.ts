import { createBashToolDefinition, type BashToolDetails, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { Container } from "@earendil-works/pi-tui";
import { resolve } from "node:path";

const EXEC_COMMAND_PARAMETERS = Type.Object({
	cmd: Type.String({ description: "Shell command to execute." }),
	workdir: Type.Optional(Type.String({ description: "Defaults to current cwd." })),
	shell: Type.Optional(Type.String({ description: "Defaults to the user's shell." })),
	tty: Type.Optional(
		Type.Boolean({
			description: "Allocate a TTY. Defaults to false.",
		}),
	),
	yield_time_ms: Type.Optional(Type.Number({ description: "Wait for output before yielding." })),
	max_output_tokens: Type.Optional(Type.Number({ description: "Excess output will be truncated." })),
	login: Type.Optional(Type.Boolean({ description: "Whether to run through a login-style shell so user PATH/toolchain setup is loaded. Defaults to true." })),
});

interface ExecCommandParams {
	cmd: string;
	workdir?: string;
	shell?: string;
	tty?: boolean;
	yield_time_ms?: number;
	max_output_tokens?: number;
	login?: boolean;
}

function prepareExecCommandArguments(args: unknown): ExecCommandParams {
	if (!args || typeof args !== "object") {
		return args as ExecCommandParams;
	}

	const record = args as Record<string, unknown>;
	const prepared: Record<string, unknown> = { ...record };
	if (!("cmd" in prepared) && "command" in prepared) {
		prepared.cmd = prepared.command;
	}
	if (!("workdir" in prepared)) {
		if ("cwd" in prepared) {
			prepared.workdir = prepared.cwd;
		} else if ("working_directory" in prepared) {
			prepared.workdir = prepared.working_directory;
		}
	}
	return prepared as unknown as ExecCommandParams;
}

function parseExecCommandParams(params: unknown): ExecCommandParams {
	if (!params || typeof params !== "object") {
		throw new Error("exec_command requires an object parameter");
	}

	const cmd = "cmd" in params ? params.cmd : undefined;
	if (typeof cmd !== "string") {
		throw new Error("exec_command requires a string 'cmd' parameter");
	}

	return {
		cmd,
		workdir: "workdir" in params && typeof params.workdir === "string" ? params.workdir : undefined,
		shell: "shell" in params && typeof params.shell === "string" ? params.shell : undefined,
		tty: "tty" in params && typeof params.tty === "boolean" ? params.tty : undefined,
		yield_time_ms: "yield_time_ms" in params && typeof params.yield_time_ms === "number" ? params.yield_time_ms : undefined,
		max_output_tokens:
			"max_output_tokens" in params && typeof params.max_output_tokens === "number" ? params.max_output_tokens : undefined,
		login: "login" in params && typeof params.login === "boolean" ? params.login : undefined,
	};
}

function resolveWorkdir(cwd: string, workdir: string | undefined): string {
	return workdir ? resolve(cwd, workdir) : cwd;
}

export function registerExecCommandTool(pi: ExtensionAPI): void {
	const renderBashTool = createBashToolDefinition(process.cwd());

	pi.registerTool({
		name: "exec_command",
		label: "exec_command",
		description: "Runs a shell command using Pi's native bash tool, while preserving Codex's exec_command input schema.",
		promptSnippet: "Run a command.",
		parameters: EXEC_COMMAND_PARAMETERS,
		prepareArguments: prepareExecCommandArguments,
		async execute(toolCallId, params, signal, onUpdate, ctx) {
			if (signal?.aborted) {
				throw new Error("exec_command aborted");
			}

			const typedParams = parseExecCommandParams(params);
			const bashTool = createBashToolDefinition(resolveWorkdir(ctx.cwd, typedParams.workdir));
			return bashTool.execute(
				toolCallId,
				{ command: typedParams.cmd },
				signal,
				onUpdate,
				ctx,
			) as ReturnType<typeof bashTool.execute>;
		},
		renderCall(args, theme, context) {
			const typedArgs = prepareExecCommandArguments(args);
			return renderBashTool.renderCall?.({ command: typedArgs.cmd }, theme, context as never) ?? new Container();
		},
		renderResult(result, options, theme, context) {
			return renderBashTool.renderResult?.(result as { content: Array<{ type: "text"; text: string }>; details: BashToolDetails | undefined }, options, theme, context as never) ?? new Container();
		},
	});
}
