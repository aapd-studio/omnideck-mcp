#!/usr/bin/env node
// OmniDeck MCP — privacy-first local tools for AI agents.
//
// Every tool here is pure local computation. This server makes NO network
// requests of any kind: nothing you pass to it leaves your machine. That is
// the entire point — these are the tasks people usually solve by pasting
// secrets, tokens and private documents into a random website.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { createHash } from "node:crypto";

// Exact tokenization when gpt-tokenizer is available, rough estimate otherwise.
// Wrapped so a missing/renamed module degrades instead of crashing the server.
let encodeFn = null;
try {
  ({ encode: encodeFn } = await import("gpt-tokenizer/model/o200k_base"));
} catch {
  try {
    ({ encode: encodeFn } = await import("gpt-tokenizer"));
  } catch {
    encodeFn = null;
  }
}

function countTokens(text) {
  if (!text) return { tokens: 0, exact: Boolean(encodeFn) };
  if (encodeFn) {
    try {
      return { tokens: encodeFn(text).length, exact: true };
    } catch {
      /* fall through to the estimate below */
    }
  }
  return { tokens: Math.ceil(text.length / 4), exact: false };
}

const text = (s) => ({ content: [{ type: "text", text: s }] });

const server = new McpServer({ name: "omnideck", version: "1.0.0" });

/* ---------------------------------------------------------------- redaction */

// Order matters: each pattern runs on the output of the previous one, so the
// more specific patterns (keys, cards, IBAN) must run before the generic phone
// pattern, or phone's shorter digit-run match fragments a key's trailing digits
// or a card number before those patterns see the full string. Phone stays last.
const REDACTION_CATEGORIES = [
  {
    id: "emails",
    tag: "[EMAIL REDACTED]",
    regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g
  },
  {
    id: "api_keys",
    tag: "[API KEY REDACTED]",
    regex: /\b(sk-[a-zA-Z0-9_-]{10,}|sk-ant-[a-zA-Z0-9_-]{10,}|AIza[a-zA-Z0-9_-]{20,}|gh[oprsu]_[a-zA-Z0-9]{20,}|glpat-[a-zA-Z0-9_-]{15,}|xox[baprs]-[a-zA-Z0-9-]{10,}|AKIA[A-Z0-9]{12,}|eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b/g
  },
  { id: "credit_cards", tag: "[CARD REDACTED]", regex: /\b(?:\d[ -]?){13,19}\b/g },
  { id: "iban", tag: "[IBAN REDACTED]", regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/g },
  {
    id: "ip_addresses",
    tag: "[IP REDACTED]",
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b/g
  },
  {
    id: "phone_numbers",
    tag: "[PHONE REDACTED]",
    regex: /(?:\+?\d{1,3}[\s.-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b/g
  }
];

const CATEGORY_IDS = REDACTION_CATEGORIES.map((c) => c.id);

server.registerTool(
  "redact_sensitive_data",
  {
    title: "Redact sensitive data",
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    },
    description:
      "Mask emails, API keys, credit cards, IBANs, IP addresses and phone numbers in a block of text. Use this BEFORE sending user-supplied text, logs, config files or pasted documents to any external API, or before quoting them back in a shared transcript. Runs entirely locally — nothing is transmitted.",
    inputSchema: {
      text: z.string().describe("The text to scrub."),
      categories: z
        .array(z.enum(CATEGORY_IDS))
        .optional()
        .describe(`Which categories to mask. Defaults to all: ${CATEGORY_IDS.join(", ")}.`)
    }
  },
  async ({ text: input, categories }) => {
    const active = categories?.length
      ? REDACTION_CATEGORIES.filter((c) => categories.includes(c.id))
      : REDACTION_CATEGORIES;

    let out = input;
    const counts = {};
    for (const cat of active) {
      let n = 0;
      out = out.replace(cat.regex, () => {
        n++;
        return cat.tag;
      });
      if (n > 0) counts[cat.id] = n;
    }

    const found = Object.entries(counts);
    const summary = found.length
      ? found.map(([k, v]) => `${v} ${k}`).join(", ")
      : "nothing matched the selected categories";

    return text(`Masked: ${summary}\n\n--- REDACTED TEXT ---\n${out}`);
  }
);

/* --------------------------------------------------------------------- jwt */

function b64urlDecode(segment) {
  const pad = segment.length % 4 === 0 ? "" : "=".repeat(4 - (segment.length % 4));
  return Buffer.from(segment.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64").toString("utf8");
}

server.registerTool(
  "decode_jwt",
  {
    title: "Decode a JWT",
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    },
    description:
      "Decode the header and payload of a JSON Web Token and report its expiry status. Does NOT verify the signature (no secret is involved, and none should be pasted anywhere). Use this instead of an online JWT decoder — a token is a live credential and should never be pasted into a website.",
    inputSchema: { token: z.string().describe("The JWT, with or without a 'Bearer ' prefix.") }
  },
  async ({ token }) => {
    const raw = token.trim().replace(/^Bearer\s+/i, "");
    const parts = raw.split(".");
    if (parts.length < 2) {
      return text("Not a valid JWT: expected at least two dot-separated segments.");
    }

    let header, payload;
    try {
      header = JSON.parse(b64urlDecode(parts[0]));
      payload = JSON.parse(b64urlDecode(parts[1]));
    } catch {
      return text("Could not decode this token: the header or payload is not valid base64url JSON.");
    }

    const lines = [
      "Signature NOT verified (decode only).",
      "",
      `Header:\n${JSON.stringify(header, null, 2)}`,
      "",
      `Payload:\n${JSON.stringify(payload, null, 2)}`
    ];

    if (typeof payload.exp === "number") {
      const expiry = new Date(payload.exp * 1000);
      const expired = Date.now() > payload.exp * 1000;
      lines.push("", `Expires: ${expiry.toISOString()} — ${expired ? "EXPIRED" : "still valid"}`);
    }

    return text(lines.join("\n"));
  }
);

/* -------------------------------------------------------------------- cost */

// Update every 2-3 months. USD per 1,000,000 tokens, standard public list rates.
const PRICE_DATE = "2026-08";
const PRICES = [
  { label: "GPT-4o mini", input: 0.15, output: 0.6 },
  { label: "Gemini 2.0 Flash", input: 0.1, output: 0.4 },
  { label: "Claude Haiku 4.5", input: 0.8, output: 4.0 },
  { label: "GPT-4o", input: 2.5, output: 10.0 },
  { label: "Gemini 1.5 Pro", input: 1.25, output: 5.0 },
  { label: "Claude Sonnet 5", input: 3.0, output: 15.0 },
  { label: "GPT-4 Turbo", input: 10.0, output: 30.0 },
  { label: "Claude Opus 4", input: 15.0, output: 75.0 }
];

server.registerTool(
  "estimate_llm_cost",
  {
    title: "Estimate and compare LLM cost",
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    },
    description:
      "Compare what one request would cost across GPT, Claude and Gemini models, sorted cheapest first. Pass the prompt text, or pass input_tokens directly if you already know the count. Useful for picking a model before running a large batch job.",
    inputSchema: {
      text: z.string().optional().describe("The prompt text. Its tokens are counted for you."),
      input_tokens: z
        .number()
        .int()
        .nonnegative()
        .optional()
        .describe("Exact input token count, if you already have it. Overrides `text`."),
      output_tokens: z
        .number()
        .int()
        .nonnegative()
        .default(500)
        .describe("Expected output tokens. Defaults to 500.")
    }
  },
  async ({ text: input, input_tokens, output_tokens }) => {
    let inTokens;
    let note;
    if (typeof input_tokens === "number") {
      inTokens = input_tokens;
      note = "input tokens supplied by caller";
    } else if (input) {
      const counted = countTokens(input);
      inTokens = counted.tokens;
      note = counted.exact
        ? "input tokens counted exactly (o200k_base)"
        : "input tokens ESTIMATED at ~4 chars/token — install gpt-tokenizer for exact counts";
    } else {
      return text("Provide either `text` or `input_tokens`.");
    }

    const rows = PRICES.map((m) => {
      const inCost = (inTokens / 1e6) * m.input;
      const outCost = (output_tokens / 1e6) * m.output;
      return { label: m.label, inCost, outCost, total: inCost + outCost };
    }).sort((a, b) => a.total - b.total);

    const fmt = (n) => "$" + n.toFixed(6);
    const body = rows
      .map((r, i) => `${i === 0 ? "*" : " "} ${r.label.padEnd(20)} in ${fmt(r.inCost)}  out ${fmt(r.outCost)}  total ${fmt(r.total)}`)
      .join("\n");

    return text(
      `Input: ${inTokens} tokens (${note})\nOutput: ${output_tokens} tokens\nList prices as of ${PRICE_DATE}\n\n${body}\n\n* cheapest`
    );
  }
);

/* ------------------------------------------------------------------- split */

const CHARS_PER_TOKEN = 4;

// Split on paragraph boundaries; if a single paragraph exceeds the limit, fall
// back to splitting that paragraph at sentence boundaries.
function splitText(input, charLimit) {
  const units = [];
  for (const p of input.split(/\n\s*\n/)) {
    if (p.length <= charLimit) {
      units.push(p);
      continue;
    }
    const sentences = p.match(/[^.!?]+[.!?]+(\s|$)|[^.!?]+$/g) || [p];
    let buf = "";
    for (const s of sentences) {
      if ((buf + s).length > charLimit && buf) {
        units.push(buf);
        buf = s;
      } else {
        buf += s;
      }
    }
    if (buf) units.push(buf);
  }

  const chunks = [];
  let current = "";
  for (const u of units) {
    const candidate = current ? current + "\n\n" + u : u;
    if (candidate.length > charLimit && current) {
      chunks.push(current);
      current = u;
    } else {
      current = candidate;
    }
  }
  if (current) chunks.push(current);
  return chunks;
}

server.registerTool(
  "split_for_context",
  {
    title: "Split text for a context window",
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    },
    description:
      "Break a long document into chunks that fit a target context window, cutting on paragraph boundaries (falling back to sentence boundaries) so no chunk ends mid-thought. Use when a file is too large to process in one pass.",
    inputSchema: {
      text: z.string().describe("The document to split."),
      max_tokens: z
        .number()
        .int()
        .positive()
        .default(8000)
        .describe("Approximate token budget per chunk. Defaults to 8000.")
    }
  },
  async ({ text: input, max_tokens }) => {
    const body = input.trim();
    if (!body) return text("Nothing to split.");

    const chunks = splitText(body, max_tokens * CHARS_PER_TOKEN);
    const rendered = chunks
      .map((c, i) => `--- PART ${i + 1} of ${chunks.length} (~${Math.round(c.length / CHARS_PER_TOKEN)} tokens) ---\n${c}`)
      .join("\n\n");

    return text(`Split into ${chunks.length} part(s).\n\n${rendered}`);
  }
);

/* ---------------------------------------------------------------- fidelity */

const STOP_WORDS = /^(I|The|A|An|This|That|These|Those|It|We|They|He|She|You)$/;

function norm(s) {
  return s.toLowerCase().replace(/[^\w\s]/g, "");
}

// Pull out "salient" spans: numbers/percentages/dates, and runs of capitalized
// words that look like proper nouns — the parts most likely to be fabricated.
function extractSalientSpans(input) {
  const spans = [];
  let m;
  const numberRe = /\b\d[\d,.]*%?\b/g;
  while ((m = numberRe.exec(input))) spans.push({ start: m.index, end: m.index + m[0].length, text: m[0] });

  const properNounRe = /\b[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*\b/g;
  while ((m = properNounRe.exec(input))) {
    if (STOP_WORDS.test(m[0])) continue;
    spans.push({ start: m.index, end: m.index + m[0].length, text: m[0] });
  }

  spans.sort((a, b) => a.start - b.start);
  const merged = [];
  for (const s of spans) {
    const last = merged[merged.length - 1];
    if (last && s.start <= last.end) {
      last.end = Math.max(last.end, s.end);
      last.text = input.slice(last.start, last.end);
    } else {
      merged.push({ ...s });
    }
  }
  return merged;
}

server.registerTool(
  "check_output_fidelity",
  {
    title: "Check AI output against its source",
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    },
    description:
      "Flag names, numbers and dates that appear in an AI-generated summary but NOT in the source text it was based on — the usual shape of a hallucination. This is a lexical heuristic, not a fact-checker: it catches invented specifics, not wrong reasoning. Use it to decide what to verify by hand.",
    inputSchema: {
      original: z.string().describe("The source text the output was generated from."),
      ai_output: z.string().describe("The AI-generated text to check.")
    }
  },
  async ({ original, ai_output }) => {
    if (!original.trim() || !ai_output.trim()) {
      return text("Provide both `original` and `ai_output`.");
    }

    const originalNorm = norm(original);
    const spans = extractSalientSpans(ai_output);
    const flagged = spans.filter((s) => {
      const n = norm(s.text);
      return n.length > 0 && !originalNorm.includes(n);
    });

    if (!flagged.length) {
      return text(`Checked ${spans.length} salient term(s). All of them appear in the original text.`);
    }

    const list = [...new Set(flagged.map((s) => s.text))].map((t) => `  - ${t}`).join("\n");
    return text(
      `${flagged.length} of ${spans.length} salient term(s) were NOT found in the original — verify these:\n\n${list}\n\nHeuristic only: a term can be legitimately rephrased and still be correct.`
    );
  }
);

/* -------------------------------------------------------------------- hash */

server.registerTool(
  "hash_text",
  {
    title: "Hash text locally",
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    },
    description:
      "Compute an MD5, SHA-1, SHA-256 or SHA-512 digest of a string, locally. Use instead of an online hash generator when the input is a password, secret or any private value.",
    inputSchema: {
      text: z.string().describe("The string to hash."),
      algorithm: z.enum(["md5", "sha1", "sha256", "sha512"]).default("sha256").describe("Digest algorithm.")
    }
  },
  async ({ text: input, algorithm }) => {
    const digest = createHash(algorithm).update(input, "utf8").digest("hex");
    return text(`${algorithm}: ${digest}`);
  }
);

/* ------------------------------------------------------------------- start */

await server.connect(new StdioServerTransport());
