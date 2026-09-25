export interface ThreadTaskFailure {
  threadId: string;
  error: string;
}

export interface ThreadTaskResult {
  succeededThreadIds: string[];
  failures: ThreadTaskFailure[];
}

function errorMessage(error: unknown): string {
  if (error instanceof Error && error.message.trim().length > 0) {
    return error.message.trim();
  }
  return "Unknown error";
}

export async function runThreadTasks(
  threadIds: readonly string[],
  task: (threadId: string) => Promise<void>,
  concurrency = 4,
): Promise<ThreadTaskResult> {
  const results = new Map<string, ThreadTaskFailure | null>();
  let nextIndex = 0;
  const workerCount = Math.max(1, Math.min(concurrency, threadIds.length));

  await Promise.all(
    Array.from({ length: workerCount }, async () => {
      while (nextIndex < threadIds.length) {
        const threadId = threadIds[nextIndex++]!;
        try {
          await task(threadId);
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
