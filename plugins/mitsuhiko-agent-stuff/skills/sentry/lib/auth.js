import { readFileSync, existsSync } from "fs";
import { homedir } from "os";
import { join } from "path";

export const SENTRY_API_BASE = "https://sentry.io/api/0";

// Cache for project slug -> ID resolution
const projectIdCache = new Map();

/**
 * Get auth token from ~/.sentryclirc
 * @returns {string} The auth token
 */
export function getAuthToken() {
  const rcPath = join(homedir(), ".sentryclirc");
  if (!existsSync(rcPath)) {
    console.error("Error: ~/.sentryclirc not found");
    console.error("Run 'sentry-cli login' to authenticate");
    process.exit(1);
  }

  const content = readFileSync(rcPath, "utf-8");
  const match = content.match(/token\s*=\s*(.+)/);
  if (!match) {
    console.error("Error: No token found in ~/.sentryclirc");
    process.exit(1);
  }
  return match[1].trim();
}

/**
 * Fetch JSON from a Sentry API endpoint
 * @param {string} url - The full URL to fetch
 * @param {string} token - The auth token
 * @returns {Promise<any>} The parsed JSON response
 */
export async function fetchJson(url, token) {
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API error ${res.status}: ${text}`);
  }

  return res.json();
}

/**
 * Format a timestamp for display
 * @param {string|number} ts - Timestamp (ISO string or unix)
 * @returns {string} Formatted timestamp
 */
export function formatTimestamp(ts) {
  if (!ts) return "N/A";
  try {
    const date = new Date(ts);
    if (isNaN(date.getTime())) return ts;
    return date.toLocaleString();
  } catch {
    return ts;
  }
}

/**
 * Resolve a project slug to its numeric ID.
 * If the input is already a numeric ID, returns it as-is.
 * @param {string} org - Organization slug
 * @param {string} project - Project slug or numeric ID
 * @param {string} token - Auth token
 * @returns {Promise<string>} The numeric project ID
 */
export async function resolveProjectId(org, project, token) {
  // If already numeric, return as-is
  if (/^\d+$/.test(project)) {
    return project;
  }

  // Check cache
  const cacheKey = `${org}/${project}`;
  if (projectIdCache.has(cacheKey)) {
    return projectIdCache.get(cacheKey);
  }

  // Fetch project details to get the ID
  const url = `${SENTRY_API_BASE}/projects/${encodeURIComponent(org)}/${encodeURIComponent(project)}/`;
  const data = await fetchJson(url, token);

  if (!data || !data.id) {
    throw new Error(`Project '${project}' not found in organization '${org}'`);
  }

  const id = String(data.id);
  projectIdCache.set(cacheKey, id);
  return id;
}
