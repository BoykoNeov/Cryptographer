/**
 * Tiny markdown renderer covering the features used by step-documentation
 * detail strings. Intentionally not a full CommonMark implementation —
 * we're optimizing for "small bundle, predictable output" over coverage.
 *
 * Supported (block-level):
 *   - blank-line separated paragraphs
 *   - "# Heading" / "## Heading" / "### Heading"
 *   - "- list item" or "* list item" (single-level only)
 *   - fenced code blocks: ```lang\ncode\n```
 *
 * Supported (inline):
 *   - **bold**
 *   - `code`
 *
 * Anything else falls through as plain text. If we ever need real
 * markdown features (links, tables, math), pull in `marked` and replace.
 */

import { For, type JSX, Show } from "solid-js";

type Props = {
  source: string;
};

// ─── Block-level parsing ──────────────────────────────────────────────────
// Parse the source into a sequence of typed blocks. Each block is rendered
// independently; inline parsing happens inside paragraphs and list items.

type Block =
  | { kind: "heading"; level: 1 | 2 | 3; text: string }
  | { kind: "paragraph"; text: string }
  | { kind: "list"; items: string[] }
  | { kind: "code"; language: string; text: string };

const parseBlocks = (source: string): Block[] => {
  const blocks: Block[] = [];
  // Normalize line endings before splitting; Windows CRLF would otherwise
  // leave a stray \r at the end of every line and break inline parsing.
  const lines = source.replace(/\r\n/g, "\n").split("\n");

  let i = 0;
  while (i < lines.length) {
    const line = lines[i] ?? "";

    // Skip blank lines between blocks
    if (line.trim() === "") {
      i++;
      continue;
    }

    // Headings: # / ## / ###
    const headingMatch = /^(#{1,3})\s+(.+)$/.exec(line);
    if (headingMatch) {
      const level = headingMatch[1]?.length as 1 | 2 | 3;
      blocks.push({ kind: "heading", level, text: headingMatch[2] ?? "" });
      i++;
      continue;
    }

    // Fenced code: ```[lang]
    if (line.startsWith("```")) {
      const language = line.slice(3).trim();
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !(lines[i] ?? "").startsWith("```")) {
        codeLines.push(lines[i] ?? "");
        i++;
      }
      // Skip the closing fence (or EOF)
      if (i < lines.length) i++;
      blocks.push({ kind: "code", language, text: codeLines.join("\n") });
      continue;
    }

    // Lists: a run of lines starting with "- " or "* "
    if (/^[-*]\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^[-*]\s+/.test(lines[i] ?? "")) {
        items.push((lines[i] ?? "").replace(/^[-*]\s+/, ""));
        i++;
      }
      blocks.push({ kind: "list", items });
      continue;
    }

    // Paragraph: collect consecutive non-blank lines that aren't another
    // block kind. A blank line, a heading, a fence, or a list ends it.
    const paraLines: string[] = [];
    while (i < lines.length) {
      const l = lines[i] ?? "";
      if (l.trim() === "") break;
      if (/^#{1,3}\s+/.test(l)) break;
      if (l.startsWith("```")) break;
      if (/^[-*]\s+/.test(l)) break;
      paraLines.push(l);
      i++;
    }
    if (paraLines.length > 0) {
      // Paragraphs join lines with a single space — soft line breaks.
      blocks.push({ kind: "paragraph", text: paraLines.join(" ") });
    }
  }

  return blocks;
};

// ─── Inline parsing ───────────────────────────────────────────────────────
// Turn an inline-text string into a flat array of JSX nodes (text, <strong>,
// <code>). Single-pass scanner — handles nested simple cases like
// "**bold with `code` inside**" by recursing on the inner text.

const renderInline = (text: string): JSX.Element[] => {
  const out: JSX.Element[] = [];
  let i = 0;
  let buffer = "";

  const flush = (): void => {
    if (buffer.length === 0) return;
    out.push(buffer);
    buffer = "";
  };

  while (i < text.length) {
    // **bold** — non-greedy
    if (text.startsWith("**", i)) {
      const end = text.indexOf("**", i + 2);
      if (end !== -1) {
        flush();
        out.push(<strong>{renderInline(text.slice(i + 2, end))}</strong>);
        i = end + 2;
        continue;
      }
    }

    // `code` — non-greedy, no nesting
    if (text[i] === "`") {
      const end = text.indexOf("`", i + 1);
      if (end !== -1) {
        flush();
        out.push(<code>{text.slice(i + 1, end)}</code>);
        i = end + 1;
        continue;
      }
    }

    buffer += text[i];
    i++;
  }
  flush();
  return out;
};

// ─── Rendering ────────────────────────────────────────────────────────────

export const Markdown = (props: Props) => {
  // Parse fresh on every render — these are short docs (a few KB at most)
  // and the doc text itself rarely changes once registered. If this ever
  // shows up in a profile, memoize on `source`.
  const blocks = () => parseBlocks(props.source);

  return (
    <div class="markdown">
      <For each={blocks()}>
        {(block) => (
          <Show
            when={block.kind === "heading"}
            fallback={
              <Show
                when={block.kind === "list"}
                fallback={
                  <Show
                    when={block.kind === "code"}
                    fallback={
                      // Paragraph
                      <p>{renderInline((block as { text: string }).text)}</p>
                    }
                  >
                    <pre>
                      <code>{(block as { text: string }).text}</code>
                    </pre>
                  </Show>
                }
              >
                <ul>
                  <For each={(block as { items: string[] }).items}>
                    {(item) => <li>{renderInline(item)}</li>}
                  </For>
                </ul>
              </Show>
            }
          >
            {/* Heading: render h1/h2/h3 based on level */}
            <HeadingTag block={block as { level: 1 | 2 | 3; text: string }} />
          </Show>
        )}
      </For>
    </div>
  );
};

// Solid doesn't support dynamic JSX tag names cleanly via a string, so
// we dispatch with a small switch — verbose but explicit.
const HeadingTag = (props: { block: { level: 1 | 2 | 3; text: string } }) => (
  <Show
    when={props.block.level === 1}
    fallback={
      <Show when={props.block.level === 2} fallback={<h3>{renderInline(props.block.text)}</h3>}>
        <h2>{renderInline(props.block.text)}</h2>
      </Show>
    }
  >
    <h1>{renderInline(props.block.text)}</h1>
  </Show>
);
