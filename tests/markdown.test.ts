/**
 * Tests for the tiny markdown subset parser. The parser sits between
 * step-doc text and the rendered HTML — silent bugs here would corrupt
 * every doc downstream. Cheap insurance.
 *
 * We test the *parser shape* (block kinds and their fields) rather than
 * the rendered DOM, because the renderer is straightforward dispatch and
 * the parser is the part with edge cases. Render-shape testing would
 * require a DOM environment and add little signal.
 *
 * Imports from markdown-parser.ts (pure logic, no Solid) rather than
 * Markdown.tsx (the JSX renderer) so the tests can run in a node-only
 * environment without dragging in solid-js/web/server.
 */

import { parseBlocks } from "@/ui/components/markdown-parser";
import { describe, expect, it } from "vitest";

describe("Markdown parser (tiny subset)", () => {
  it("treats blank-line separated lines as separate paragraphs", () => {
    const blocks = parseBlocks("first paragraph\n\nsecond paragraph");
    expect(blocks).toEqual([
      { kind: "paragraph", text: "first paragraph" },
      { kind: "paragraph", text: "second paragraph" },
    ]);
  });

  it("joins consecutive non-blank lines into a single paragraph", () => {
    const blocks = parseBlocks("line one\nline two\nline three");
    expect(blocks).toHaveLength(1);
    expect(blocks[0]).toEqual({
      kind: "paragraph",
      text: "line one line two line three",
    });
  });

  it("parses three heading levels", () => {
    const blocks = parseBlocks("# h1\n## h2\n### h3");
    expect(blocks).toEqual([
      { kind: "heading", level: 1, text: "h1" },
      { kind: "heading", level: 2, text: "h2" },
      { kind: "heading", level: 3, text: "h3" },
    ]);
  });

  it("parses lists with both - and * markers", () => {
    const blocks = parseBlocks("- alpha\n- beta\n* gamma");
    expect(blocks).toHaveLength(1);
    expect(blocks[0]).toEqual({
      kind: "list",
      items: ["alpha", "beta", "gamma"],
    });
  });

  it("parses fenced code blocks with language tag", () => {
    const blocks = parseBlocks("```ts\nconst x = 1;\nconst y = 2;\n```");
    expect(blocks).toEqual([{ kind: "code", language: "ts", text: "const x = 1;\nconst y = 2;" }]);
  });

  it("parses fenced code with no language tag", () => {
    const blocks = parseBlocks("```\nplain code\n```");
    expect(blocks[0]).toEqual({ kind: "code", language: "", text: "plain code" });
  });

  it("ends a paragraph when a heading begins", () => {
    const blocks = parseBlocks("para text\n# heading");
    expect(blocks).toEqual([
      { kind: "paragraph", text: "para text" },
      { kind: "heading", level: 1, text: "heading" },
    ]);
  });

  it("ends a paragraph when a list begins", () => {
    const blocks = parseBlocks("para text\n- item");
    expect(blocks).toEqual([
      { kind: "paragraph", text: "para text" },
      { kind: "list", items: ["item"] },
    ]);
  });

  it("normalizes Windows CRLF line endings", () => {
    const blocks = parseBlocks("first\r\n\r\nsecond");
    expect(blocks).toEqual([
      { kind: "paragraph", text: "first" },
      { kind: "paragraph", text: "second" },
    ]);
  });

  it("tolerates an unterminated fenced code block (treats EOF as fence end)", () => {
    // No closing ``` — still produces a code block with whatever content
    // we collected, rather than throwing or hanging.
    const blocks = parseBlocks("```\nabc\ndef");
    expect(blocks).toEqual([{ kind: "code", language: "", text: "abc\ndef" }]);
  });

  it("renders unbalanced **bold** as literal asterisks (no crash)", () => {
    // Inline parsing is permissive: an unmatched ** stays as literal text.
    // We assert at the parser layer that the paragraph is built correctly;
    // inline rendering is exercised at the JSX layer.
    const blocks = parseBlocks("with **unmatched bold");
    expect(blocks).toEqual([{ kind: "paragraph", text: "with **unmatched bold" }]);
  });

  it("handles an empty source", () => {
    expect(parseBlocks("")).toEqual([]);
  });

  it("handles only whitespace", () => {
    expect(parseBlocks("\n\n   \n")).toEqual([]);
  });
});
