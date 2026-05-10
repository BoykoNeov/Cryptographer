/**
 * Renders the small markdown subset used for step-doc detail strings.
 * Pure parsing logic lives in markdown-parser.ts so it can be tested in a
 * node-only environment; this file is the JSX renderer on top.
 *
 * Supported features (mirrored in markdown-parser.ts):
 *   block: paragraphs, # / ## / ### headings, - / * lists, ``` code fences
 *   inline: **bold**, `code`
 *
 * Anything else falls through as plain text. If we ever need real
 * markdown features (links, tables, math), drop in `marked` and replace.
 */

import { For, type JSX, Show } from "solid-js";
import { type Block, parseBlocks } from "./markdown-parser";

type Props = {
  source: string;
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
  // Parse on every render — these are short docs (a few KB at most) and
  // the doc text rarely changes once registered. Memoize on `source` if
  // this ever shows up in a profile.
  const blocks = () => parseBlocks(props.source);

  return (
    <div class="markdown">
      <For each={blocks()}>{(block) => <BlockView block={block} />}</For>
    </div>
  );
};

// Single block dispatcher. Cleaner than a chain of nested <Show> fallbacks.
const BlockView = (props: { block: Block }) => (
  <Show
    when={props.block.kind === "heading"}
    fallback={
      <Show
        when={props.block.kind === "list"}
        fallback={
          <Show
            when={props.block.kind === "code"}
            fallback={<p>{renderInline((props.block as { text: string }).text)}</p>}
          >
            <pre>
              <code>{(props.block as { text: string }).text}</code>
            </pre>
          </Show>
        }
      >
        <ul>
          <For each={(props.block as { items: string[] }).items}>
            {(item) => <li>{renderInline(item)}</li>}
          </For>
        </ul>
      </Show>
    }
  >
    <HeadingTag block={props.block as { level: 1 | 2 | 3; text: string }} />
  </Show>
);

// Solid doesn't support a string-typed dynamic JSX tag cleanly; explicit
// dispatch is verbose but keeps the type narrowing intact.
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
