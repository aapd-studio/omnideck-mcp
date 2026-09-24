# OmniDeck MCP

[![M8ven Verified](https://m8ven.ai/badge/mcp/aapd-studio/omnideck-mcp?variant=verified)](https://m8ven.ai/mcp/aapd-studio/omnideck-mcp)

**Local, privacy-first tools for AI agents. No network calls, ever.**

Some tasks are awkward to hand to an AI agent because doing them normally means
pasting a secret into a website: decoding a JWT, hashing a password, scrubbing
a log file before it goes to an API. This server does those locally instead.

Every tool is pure computation inside your own process. The server opens no
sockets and makes no outbound requests — nothing you pass to it leaves your
machine.

## Install

```bash
npm install -g omnideck-mcp
```

Or run it without installing:

```bash
npx omnideck-mcp
```

## Configure

**Claude Desktop** — add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "omnideck": {
      "command": "npx",
      "args": ["-y", "omnideck-mcp"]
    }
  }
}
```

**Claude Code:**

```bash
claude mcp add omnideck -- npx -y omnideck-mcp
```

Any MCP client that speaks stdio works the same way.

## Tools

### `redact_sensitive_data`

Masks emails, API keys, credit cards, IBANs, IP addresses and phone numbers.
Run it over logs, config files or user-pasted text **before** that content
reaches an external API or a shared transcript.

Patterns are applied most-specific-first, so a key like `sk-ant-…` is matched
whole rather than being chopped up by the generic phone-number pattern.

```
Contact me at john@example.com, key sk-ant-abcdefghij1234567890
→ Contact me at [EMAIL REDACTED], key [API KEY REDACTED]
```

Optional `categories` argument restricts which classes are masked.

### `decode_jwt`

Decodes a token's header and payload and reports whether it has expired. The
signature is **not** verified — no secret is needed, and none should be pasted
anywhere. A JWT is a live credential; this exists so you never have to paste
one into an online decoder.

### `estimate_llm_cost`

Compares what a single request would cost across eight GPT, Claude and Gemini
models, cheapest first. Pass `text` (tokens are counted exactly via
`gpt-tokenizer`) or pass `input_tokens` directly. Useful before committing to a
model for a large batch job.

List prices are current as of **2026-08** and are refreshed periodically —
check your provider's pricing page before relying on them for billing
decisions.

### `split_for_context`

Splits a long document into chunks that fit a token budget, cutting on
paragraph boundaries and falling back to sentence boundaries, so no chunk ends
mid-thought.

### `check_output_fidelity`

Flags names, numbers and dates that appear in an AI-generated summary but not
in the source it was based on — the usual shape of a fabricated detail.

This is a **lexical heuristic, not a fact-checker.** It catches invented
specifics, not faulty reasoning, and a correctly-rephrased term can be flagged.
Treat the output as a list of things to verify by hand.

### `hash_text`

MD5, SHA-1, SHA-256 or SHA-512 digest of a string, computed locally. For when
the input is a password or other private value that has no business going into
an online hash generator.

## Privacy

- No network requests. No telemetry. No analytics. No logging of your inputs.
- Three runtime dependencies: the MCP SDK, `zod`, and `gpt-tokenizer`.
- MIT licensed — read [`index.js`](./index.js) and verify all of the above; it
  is a single readable file.

## Related

Full documentation for this server, in English and Spanish:
[omnideck.cc/mcp](https://omnideck.cc/mcp)

These tools also run as free browser-based utilities, alongside ~125 others, at
[omnideck.cc](https://omnideck.cc) — same principle, everything client-side.

## License

MIT © AAPD Studio
