import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const serverPath = fileURLToPath(new URL("../index.js", import.meta.url));
let client;

before(async () => {
  client = new Client({ name: "omnideck-tests", version: "1.0.0" });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [serverPath] }));
});

after(async () => {
  await client.close();
});

async function call(name, args) {
  const res = await client.callTool({ name, arguments: args });
  return res.content.map((c) => c.text).join("\n");
}

test("lists six tools, all annotated as read-only and closed-world", async () => {
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map((t) => t.name).sort(), [
    "check_output_fidelity", "decode_jwt", "estimate_llm_cost", "hash_text", "redact_sensitive_data", "split_for_context"
  ]);
  for (const t of tools) {
    assert.deepEqual(t.annotations, { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }, t.name);
  }
});

test("redact_sensitive_data masks keys and cards whole, not fragmented by the phone pattern", async () => {
  const out = await call("redact_sensitive_data", {
    text: "mail john@example.com, call 555-123-4567, key sk-ant-abcdefghij1234567890, card 4111111111111111"
  });
  assert.match(out, /\[EMAIL REDACTED\]/);
  assert.match(out, /\[PHONE REDACTED\]/);
  assert.match(out, /key \[API KEY REDACTED\],/);
  assert.match(out, /card \[CARD REDACTED\]/);
  assert.doesNotMatch(out, /john@example\.com|sk-ant-|4111111111111111/);
});

test("redact_sensitive_data respects the categories filter", async () => {
  const out = await call("redact_sensitive_data", { text: "john@example.com 10.0.0.1", categories: ["ip_addresses"] });
  assert.match(out, /john@example\.com/);
  assert.match(out, /\[IP REDACTED\]/);
});

test("decode_jwt decodes payload and reports expiry, rejects garbage", async () => {
  const token =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyNDI2MjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  const out = await call("decode_jwt", { token: "Bearer " + token });
  assert.match(out, /"name": "John Doe"/);
  assert.match(out, /EXPIRED/);
  assert.match(await call("decode_jwt", { token: "not-a-jwt" }), /Not a valid JWT/);
});

test("estimate_llm_cost sorts cheapest first and uses supplied token counts", async () => {
  const out = await call("estimate_llm_cost", { input_tokens: 1_000_000, output_tokens: 0 });
  const totals = [...out.matchAll(/total \$([0-9.]+)/g)].map((m) => Number(m[1]));
  assert.ok(totals.length >= 3);
  assert.deepEqual(totals, [...totals].sort((a, b) => a - b));
  assert.match(out, /input tokens supplied by caller/);
});

test("split_for_context keeps every paragraph and respects the budget", async () => {
  const paragraphs = Array.from({ length: 6 }, (_, i) => `Paragraph ${i} ` + "word ".repeat(40));
  const out = await call("split_for_context", { text: paragraphs.join("\n\n"), max_tokens: 120 });
  const parts = Number(out.match(/Split into (\d+) part/)[1]);
  assert.ok(parts > 1);
  for (let i = 0; i < 6; i++) assert.match(out, new RegExp(`Paragraph ${i} `));
});

test("check_output_fidelity flags invented specifics only", async () => {
  const out = await call("check_output_fidelity", {
    original: "Acme reported revenue of 12 million dollars in 2024, led by Jane Smith.",
    ai_output: "Acme reported revenue of 15 million dollars in 2024 under Robert Klein."
  });
  assert.match(out, /- 15/);
  assert.match(out, /- Robert Klein/);
  assert.doesNotMatch(out, /- Acme|- 2024/);
});

test("hash_text matches known digests", async () => {
  assert.equal(await call("hash_text", { text: "hello", algorithm: "sha256" }),
    "sha256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  assert.equal(await call("hash_text", { text: "hello", algorithm: "md5" }), "md5: 5d41402abc4b2a76b9719d911017c592");
});
