/**
 * Pure markdown parser — no Solid, no JSX, no DOM. Lives in its own file
 * so the parser can be unit-tested in a node-only test environment
 * without dragging the Solid SSR runtime into the test bundle.
 *
 * The renderer (Markdown.tsx) imports `parseBlocks` from here and turns
 * the resulting blocks into JSX. The split also makes the parser
 * trivially reusable if we ever need to render docs in a non-Solid
 * context (CLI help, exported HTML, etc.).
 *
 * Supported (block-level):
 *   - blank-line separated paragraphs
 *   - "# Heading" / "## Heading" / "### Heading"
 *   - "- list item" or "* list item" (single-level only)
 *   - fenced code blocks: ```lang\ncode\n```
 *
 * Supported (inline, handled by the renderer):
 *   - **bold**, `code`
 */

export type Block =
  | { kind: "heading"; level: 1 | 2 | 3; text: string }
  | { kind: "paragraph"; text: string }
  | { kind: "list"; items: string[] }
  | { kind: "code"; language: string; text: string };

export const parseBlocks = (source: string): Block[] => {
  const blocks: Block[] = [];
  // Normalize line endings before splitting; Windows CRLF would otherwise
  // leave a stray \r at the end of every line and break inline parsing.
  const lines = source.replace(/\r\n/g, "\n").split("\n");

  let i = 0;
  while (i < lines.length) {
    const line = lines[i] ?? "";

    // Skip blank lines between blocks.
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
      // Skip the closing fence (or EOF).
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
