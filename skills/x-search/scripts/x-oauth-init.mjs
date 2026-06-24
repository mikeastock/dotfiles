#!/usr/bin/env node
import { createServer } from "node:http";
import {
  DEFAULT_SCOPES,
  REDIRECT_URI,
  basicAuth,
  loadClientConfig,
  pkcePair,
  randomState,
  tokenFromResponse,
  writeTokenCache
} from "./x-lib.mjs";

const PORT = 8787;
const CALLBACK_PATH = "/callback";
const clientConfig = loadClientConfig();
const { verifier, challenge } = pkcePair();
const state = randomState();
const scopes = process.argv.includes("--bookmarks")
  ? `${DEFAULT_SCOPES} bookmark.read`
  : DEFAULT_SCOPES;

const authorizationUrl = new URL("https://twitter.com/i/oauth2/authorize");
authorizationUrl.search = new URLSearchParams({
  response_type: "code",
  client_id: clientConfig.clientId,
  redirect_uri: REDIRECT_URI,
  scope: scopes,
  state,
  code_challenge: challenge,
  code_challenge_method: "S256"
}).toString();

console.log("Open this URL to authorize the X search app:");
console.log(authorizationUrl.toString());
console.log("");
console.log(`Waiting for callback at ${REDIRECT_URI} ...`);

const server = createServer(async (request, response) => {
  try {
    const requestUrl = new URL(request.url || "/", REDIRECT_URI);
    if (requestUrl.pathname !== CALLBACK_PATH) {
      response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      response.end("Not found.");
      return;
    }

    const error = requestUrl.searchParams.get("error");
    if (error) {
      throw new Error(`X authorization failed: ${error}`);
    }

    if (requestUrl.searchParams.get("state") !== state) {
      response.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
      response.end("X authorization callback state did not match. Use the newest authorization URL.\n");
      console.error("Ignored X authorization callback with non-matching state.");
      return;
    }

    const code = requestUrl.searchParams.get("code");
    if (!code) {
      throw new Error("X authorization callback did not include code.");
    }

    const token = await exchangeCode(code);
    writeTokenCache(token);

    response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    response.end("X search OAuth token saved. You can close this tab.\n");
    console.log("Saved X OAuth tokens to ~/.local/state/codex/x-search/tokens.json");
    server.close();
  } catch (caught) {
    const message = caught instanceof Error ? caught.message : String(caught);
    response.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
    response.end(`${message}\n`);
    console.error(message);
    server.close(() => {
      process.exitCode = 1;
    });
  }
});

server.listen(PORT, "127.0.0.1");

async function exchangeCode(code) {
  const params = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier
  });

  const tokenResponse = await fetch("https://api.twitter.com/2/oauth2/token", {
    method: "POST",
    headers: {
      authorization: basicAuth(clientConfig),
      "content-type": "application/x-www-form-urlencoded"
    },
    body: params
  });
  const body = await tokenResponse.json().catch(async () => ({ text: await tokenResponse.text() }));

  if (!tokenResponse.ok) {
    throw new Error(`Could not exchange X authorization code (${tokenResponse.status}): ${JSON.stringify(body)}`);
  }

  return tokenFromResponse(body, { scope: scopes });
}
