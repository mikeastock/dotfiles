export type PendingHandoff = {
  finalPrompt: string;
  parentSession: string | undefined;
};

export function createPendingHandoffStore() {
  let pending: PendingHandoff | null = null;
  return {
    set(value: PendingHandoff) {
      pending = value;
    },
    consume(): PendingHandoff | null {
      const value = pending;
      pending = null;
      return value;
    },
  };
}
