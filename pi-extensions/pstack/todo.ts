export const TODO_STATUSES = ["pending", "in_progress", "completed", "cancelled"] as const;
export type TodoStatus = (typeof TODO_STATUSES)[number];

export interface Todo {
	content: string;
	status: TodoStatus;
}

export interface TodoDetails {
	todos: Todo[];
}

// Models often number items themselves; the widget numbers them already.
const LEADING_NUMBER = /^\s*\d+[.)]\s+/;

const MARKS: Record<TodoStatus, string> = { pending: "[ ]", in_progress: "[~]", completed: "[x]", cancelled: "[-]" };

export function renderTodos(todos: Todo[]): string[] {
	if (todos.length === 0) return ["(no todos)"];
	const done = todos.filter((todo) => todo.status === "completed" || todo.status === "cancelled").length;
	return [`${done}/${todos.length} done`, ...todos.map((todo, index) => `${MARKS[todo.status]} ${index + 1}. ${todo.content.replace(LEADING_NUMBER, "")}`)];
}

/** The latest todo list on the branch, from the details of the last `todo_write` result. */
export function restoreTodos(entries: ReadonlyArray<{ type: string; message?: unknown }>): Todo[] {
	let todos: Todo[] = [];
	for (const entry of entries) {
		const message = entry.message as { role?: string; toolName?: string; details?: TodoDetails } | undefined;
		if (entry.type === "message" && message?.role === "toolResult" && message.toolName === "todo_write" && message.details) {
			todos = message.details.todos;
		}
	}
	return todos;
}
