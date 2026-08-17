import type { PluginSidebarThread } from "@get-bb/plugin-sdk";
import { sortByCreatedAtDescending } from "./inbox";

export interface ThreadNode {
  thread: PluginSidebarThread;
  /** 0 for a row that sits at the list's left edge. */
  depth: number;
  children: ThreadNode[];
}

/**
 * The flat list folded into the parent/child tree, the way bb's own sidebar
 * builds it.
 *
 * A thread is a root when it has no parent OR when its parent is not in the
 * list being folded — deleted, archived, filtered out by search, or sitting on
 * a different shelf. That promotion is what keeps this safe: a row can never
 * be tucked inside a parent that is not on screen to be expanded.
 *
 * Siblings keep the list's own order — newest first — so nesting changes where
 * a row sits, never how its neighbours are ranked.
 */
export function buildThreadTree(
  threads: readonly PluginSidebarThread[],
): ThreadNode[] {
  const present = new Set(threads.map((thread) => thread.id));
  const childrenByParent = new Map<string, PluginSidebarThread[]>();
  const roots: PluginSidebarThread[] = [];

  for (const thread of threads) {
    const parentId = thread.parentThreadId;
    if (parentId === null || !present.has(parentId)) {
      roots.push(thread);
      continue;
    }
    const siblings = childrenByParent.get(parentId);
    if (siblings === undefined) childrenByParent.set(parentId, [thread]);
    else siblings.push(thread);
  }

  const placed = new Set<string>();

  function build(
    thread: PluginSidebarThread,
    depth: number,
    ancestors: ReadonlySet<string>,
  ): ThreadNode {
    placed.add(thread.id);
    const withSelf = new Set(ancestors);
    withSelf.add(thread.id);

    const children = sortByCreatedAtDescending(
      childrenByParent.get(thread.id) ?? [],
    )
      // Parentage comes from the server and nothing here enforces acyclicity,
      // so a loop would otherwise recurse until the stack gives out.
      .filter((child) => !withSelf.has(child.id) && !placed.has(child.id))
      .map((child) => build(child, depth + 1, withSelf));

    return { thread, depth, children };
  }

  const tree = sortByCreatedAtDescending(roots).map((thread) =>
    build(thread, 0, new Set()),
  );

  // Anything a cycle kept out of the tree still gets a row. Dropping it would
  // repeat the bug this whole feature exists to fix: a thread doing real work
  // with nowhere on screen to appear.
  const stranded = threads.filter((thread) => !placed.has(thread.id));
  for (const thread of sortByCreatedAtDescending(stranded)) {
    if (placed.has(thread.id)) continue;
    tree.push(build(thread, 0, new Set()));
  }

  return tree;
}

/** What a collapsed row is hiding, so it can still answer for it. */
export interface SubtreeSummary {
  total: number;
  waiting: number;
  unread: number;
}

/**
 * Everything below a node, flattened into counts.
 *
 * A collapsed parent has to keep speaking for its descendants — otherwise
 * collapsing becomes a way to lose a thread that is waiting on you, which is
 * exactly the failure the flat list was changed to avoid.
 */
export function summarizeDescendants(node: ThreadNode): SubtreeSummary {
  const summary: SubtreeSummary = { total: 0, waiting: 0, unread: 0 };

  function walk(nodes: readonly ThreadNode[]): void {
    for (const child of nodes) {
      summary.total += 1;
      if (child.thread.hasPendingInteraction) summary.waiting += 1;
      else if (child.thread.isUnread) summary.unread += 1;
      walk(child.children);
    }
  }

  walk(node.children);
  return summary;
}

/**
 * The tree in render order, with collapsed subtrees left out.
 *
 * Returns one flat array rather than nested lists: every row stays a sibling
 * in one `<ul>`, and `depth` becomes indentation, which is how bb draws it.
 */
export function visibleRows(
  nodes: readonly ThreadNode[],
  collapsed: ReadonlySet<string>,
): ThreadNode[] {
  const rows: ThreadNode[] = [];

  function walk(list: readonly ThreadNode[]): void {
    for (const node of list) {
      rows.push(node);
      if (!collapsed.has(node.thread.id)) walk(node.children);
    }
  }

  walk(nodes);
  return rows;
}
