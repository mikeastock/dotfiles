export interface AgentConfig {
	name: string;
	description: string;
	tools?: string[];
	model?: string;
	systemPrompt: string;
	source: "bundled" | "user" | "project";
	filePath: string;
	thinking?: string;
	spawning?: boolean;
	skills?: string[];
	cwd?: string;
}

/**
 * Simple YAML frontmatter parser. Returns the frontmatter key-value pairs
 * and the markdown body after the closing `---`.
 */
export function parseFrontmatterSimple(content: string): { frontmatter: Record<string, string>; body: string } {
	const match = content.match(/^---\n([\s\S]*?)\n---\n?([\s\S]*)$/);
	if (!match) return { frontmatter: {}, body: content };

	const fm: Record<string, string> = {};
	for (const line of match[1].split("\n")) {
		const idx = line.indexOf(":");
		if (idx === -1) continue;
		const key = line.slice(0, idx).trim();
		const value = line.slice(idx + 1).trim();
		if (key) fm[key] = value;
	}
	return { frontmatter: fm, body: match[2].trim() };
}

/**
 * Parse a single agent markdown file's content into an AgentConfig.
 * Returns null if the content lacks required frontmatter (name, description).
 */
export function parseAgentContent(
	content: string,
	source: AgentConfig["source"],
	filePath: string,
	parseFn: (content: string) => { frontmatter: Record<string, string>; body: string } = parseFrontmatterSimple,
): AgentConfig | null {
	const { frontmatter, body } = parseFn(content);

	if (!frontmatter.name || !frontmatter.description) {
		return null;
	}

	const tools = frontmatter.tools
		?.split(",")
		.map((t: string) => t.trim())
		.filter(Boolean);

	const thinkingRaw = frontmatter.thinking;
	const thinking = typeof thinkingRaw === "string" ? thinkingRaw.trim() || undefined : undefined;

	const spawningRaw = frontmatter.spawning;
	const spawning = typeof spawningRaw === "boolean" ? spawningRaw
		: typeof spawningRaw === "string" ? (spawningRaw.trim() === "false" ? false : spawningRaw.trim() === "true" ? true : undefined)
		: undefined;

	const skillsRaw = frontmatter.skills;
	const skills = typeof skillsRaw === "string"
		? skillsRaw.split(",").map((s: string) => s.trim()).filter(Boolean)
		: undefined;

	const cwdRaw = frontmatter.cwd;
	const cwd = typeof cwdRaw === "string" ? cwdRaw.trim() || undefined : undefined;

	return {
		name: frontmatter.name,
		description: frontmatter.description,
		tools: tools && tools.length > 0 ? tools : undefined,
		model: frontmatter.model || undefined,
		thinking,
		spawning,
		skills: skills && skills.length > 0 ? skills : undefined,
		cwd,
		systemPrompt: body,
		source,
		filePath,
	};
}
