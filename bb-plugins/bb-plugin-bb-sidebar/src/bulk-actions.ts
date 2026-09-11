export interface BulkActionFailure {
  threadId: string;
  error: string;
}

export interface BulkActionResult {
  succeededThreadIds: string[];
  failures: BulkActionFailure[];
}

function errorMessage(error: unknown): string {
  if (error instanceof Error && error.message.trim().length > 0) {
    return error.message.trim();
  }
  return "Unknown error";
}

export async function runBulkAction(
  threadIds: readonly string[],
  action: (threadId: string) => Promise<void>,
  concurrency = 4,
): Promise<BulkActionResult> {
  const results = new Map<string, BulkActionFailure | null>();
  let nextIndex = 0;
  const workerCount = Math.max(1, Math.min(concurrency, threadIds.length));

  await Promise.all(
    Array.from({ length: workerCount }, async () => {
      while (nextIndex < threadIds.length) {
        const threadId = threadIds[nextIndex++]!;
        try {
          await action(threadId);
          results.set(threadId, null);
        } catch (error) {
          results.set(threadId, { threadId, error: errorMessage(error) });
        }
      }
    }),
  );

  return {
    succeededThreadIds: threadIds.filter(
      (threadId) => results.get(threadId) === null,
    ),
    failures: threadIds.flatMap((threadId) => {
      const result = results.get(threadId);
      return result ? [result] : [];
    }),
  };
}
