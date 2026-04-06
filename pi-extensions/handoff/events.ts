export const HANDOFF_ACTIVITY_START_EVENT = "handoff:activity_start";
export const HANDOFF_ACTIVITY_END_EVENT = "handoff:activity_end";

export type HandoffActivityPhase = "generation" | "seeding";

export interface HandoffActivityEvent {
	phase: HandoffActivityPhase;
}

export function buildHandoffActivityEvent(event: HandoffActivityEvent): HandoffActivityEvent {
	return event;
}
