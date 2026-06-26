/**
 * tps-footer — Appends a tokens/sec status to pi's native footer.
 *
 * Uses ctx.ui.setStatus("tps", ...) instead of setFooter, so the native
 * footer (pwd, git, token totals, context %, cost, model) is preserved and
 * our TPS value is appended on its own status line.
 *
 *   - Shows the rolling (EMA-smoothed) output tokens/sec.
 *   - Updates live during streaming and finalizes when each assistant
 *     message ends. Shows "— t/s" before the first response, then the
 *     rolling rate while idle.
 */
import type { AssistantMessage } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const EMA_ALPHA = 0.5; // weight on newest sample
const MIN_DURATION_MS = 100; // below this the rate is too noisy
// Match pi's native (dark) footer dim color — theme.fg("dim") → dimGray #666666.
const DIM = "\x1b[38;2;102;102;102m";
const RESET = "\x1b[39m";

function fmtTps(n: number): string {
	if (n >= 100) return n.toFixed(0);
	if (n >= 10) return n.toFixed(1);
	return n.toFixed(2);
}

export default function (pi: ExtensionAPI) {
	// In-flight assistant message window.
	let streamStartTs: number | undefined;
	let streamOutput = 0;

	// Finalized rates.
	let emaTps: number | undefined;
	let lastTps: number | undefined;

	// Live refresh of the status line while streaming.
	let liveTimer: ReturnType<typeof setInterval> | undefined;

	type Ctx = { ui: { setStatus: (key: string, text: string | undefined) => void } };

	function statusText(): string {
		let value: number | undefined;
		if (streamStartTs !== undefined) {
			const elapsed = Date.now() - streamStartTs;
			if (elapsed >= MIN_DURATION_MS && streamOutput > 0) {
				value = (streamOutput * 1000) / elapsed;
			}
		}
		if (value === undefined) value = emaTps ?? lastTps;
		return value === undefined ? "— t/s" : `${fmtTps(value)} t/s`;
	}

	function publish(ctx: Ctx) {
		ctx.ui.setStatus("tps", `${DIM}${statusText()}${RESET}`);
	}

	function startLiveTimer(ctx: Ctx) {
		stopLiveTimer();
		liveTimer = setInterval(() => publish(ctx), 200);
	}

	function stopLiveTimer() {
		if (liveTimer !== undefined) {
			clearInterval(liveTimer);
			liveTimer = undefined;
		}
	}

	function resetSession() {
		streamStartTs = undefined;
		streamOutput = 0;
		emaTps = undefined;
		lastTps = undefined;
	}

	pi.on("session_start", async (_event, ctx) => {
		resetSession();
		publish(ctx);
	});

	pi.on("message_start", async (event, ctx) => {
		if (event.message.role !== "assistant") return;
		streamStartTs = undefined;
		streamOutput = 0;
		publish(ctx);
	});

	pi.on("message_update", async (event, ctx) => {
		if (event.message.role !== "assistant") return;
		const ev = event.assistantMessageEvent;
		const output = "partial" in ev ? ev.partial.usage.output : undefined;
		const streamingEvent = ev.type === "start" || ev.type === "text_start" || ev.type === "text_delta";
		if (streamStartTs === undefined && streamingEvent) {
			streamStartTs = Date.now();
			streamOutput = output ?? 0;
			startLiveTimer(ctx);
		} else if (streamStartTs !== undefined && output !== undefined) {
			streamOutput = output;
		}
		publish(ctx);
	});

	pi.on("message_end", async (event, ctx) => {
		if (event.message.role !== "assistant") return;
		const m = event.message as AssistantMessage;
		const out = m.usage.output;

		if (streamStartTs !== undefined) {
			const elapsedMs = Date.now() - streamStartTs;
			if (elapsedMs >= MIN_DURATION_MS && out > 0) {
				const inst = (out * 1000) / elapsedMs;
				lastTps = inst;
				emaTps = emaTps === undefined ? inst : EMA_ALPHA * inst + (1 - EMA_ALPHA) * emaTps;
			}
		}
		streamStartTs = undefined;
		streamOutput = 0;
		stopLiveTimer();
		publish(ctx);
	});

	pi.on("session_shutdown", async (_event, ctx) => {
		stopLiveTimer();
		ctx.ui.setStatus("tps", undefined);
	});
}
