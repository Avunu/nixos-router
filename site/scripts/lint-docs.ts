// Lints the docs collection (../docs) for the mistakes `jx build` lets through.
//
// The build only warns on bad frontmatter, and two Jx Markdown rules turn
// ordinary-looking prose into broken pages without any warning at all:
//
//   * A colon directly followed by a letter or digit starts a text directive,
//     so `host:port` in prose renders as "host" plus an empty <port> element.
//     Such text has to sit in inline code.
//   * Any string containing a dollar-brace sequence is a template expression,
//     evaluated in the browser, even inside a code block. There is no escape.
//
// It also checks what a static site cannot recover from: links and anchors
// that point at nothing, images that are not on disk, and pages that are
// missing from, or extra to, docs/nav.json.
//
// Run: bun scripts/lint-docs.ts   (exit 1 on any problem)

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { processMarkdown } from "@jxsuite/parser";

const repo = resolve(import.meta.dir, "../..");
const docsDir = join(repo, "docs");

const CALLOUTS = new Set(["doc-note", "doc-tip", "doc-warning"]);
// Everything standard Markdown (plus GFM) produces. A tag outside this set came
// from a directive, and the only directives the docs use are the callouts.
const MARKDOWN_TAGS = new Set(
  "a blockquote br code del em h1 h2 h3 h4 h5 h6 hr img input li ol p pre section span strong sup table tbody td th thead tr ul".split(
    " ",
  ),
);

type Node = {
  tagName?: string;
  children?: unknown;
  attributes?: Record<string, string>;
  [k: string]: unknown;
};
type Page = {
  slug: string;
  file: string;
  source: string;
  frontmatter: Record<string, unknown>;
  children: unknown[];
};

const problems: string[] = [];
const report = (file: string, msg: string) => problems.push(`${relative(repo, file)}: ${msg}`);

function walk(node: unknown, visit: (n: Node) => void) {
  if (Array.isArray(node)) {
    for (const c of node) walk(c, visit);
  } else if (node && typeof node === "object") {
    const n = node as Node;
    if (n.tagName) visit(n);
    walk(n.children, visit);
  }
}

function text(node: unknown): string {
  if (typeof node === "string") return node;
  if (Array.isArray(node)) return node.map(text).join("");
  if (node && typeof node === "object") {
    const n = node as Node;
    return typeof n.textContent === "string" ? n.textContent : text(n.children);
  }
  return "";
}

const files = readdirSync(docsDir, { recursive: true })
  .map(String)
  .filter((f) => f.endsWith(".md"))
  .sort();

const pages = new Map<string, Page>();
for (const f of files) {
  const file = join(docsDir, f);
  const source = readFileSync(file, "utf8");
  const result = processMarkdown(source, file, { directives: true, sourceRoot: docsDir });
  const slug = f.replace(/\.md$/, "");
  pages.set(slug, {
    slug,
    file,
    source,
    frontmatter: result.frontmatter,
    children: result.$children,
  });
}

// Heading ids per page, for anchor checks.
const anchors = new Map<string, Set<string>>();
for (const page of pages.values()) {
  const ids = new Set<string>();
  walk(page.children, (n) => {
    if (/^h[1-6]$/.test(n.tagName!) && typeof n.id === "string") ids.add(n.id);
  });
  anchors.set(page.slug, ids);
}

for (const page of pages.values()) {
  const { file, source, frontmatter } = page;

  for (const key of ["title", "description"]) {
    if (typeof frontmatter[key] !== "string" || !(frontmatter[key] as string).trim()) {
      report(file, `frontmatter \`${key}\` is missing`);
    }
  }
  const code = frontmatter.code;
  if (code !== undefined) {
    if (!Array.isArray(code)) report(file, "frontmatter `code` must be a list of paths");
    else
      for (const p of code) {
        if (!existsSync(join(repo, String(p)))) report(file, `frontmatter \`code\` names a missing path: ${p}`);
      }
  }

  source.split("\n").forEach((line, i) => {
    if (line.includes("$" + "{")) {
      report(file, `line ${i + 1}: contains a dollar-brace, which Jx evaluates as a template; rewrite it`);
    }
  });

  const first = page.children.find((c) => typeof c !== "string") as Node | undefined;
  if (first?.tagName !== "h1") report(file, "the body must open with a `# Title` heading");
  else if (text(first).trim() !== String(frontmatter.title ?? "").trim()) {
    report(file, `the H1 ("${text(first).trim()}") differs from frontmatter title ("${frontmatter.title}")`);
  }

  walk(page.children, (n) => {
    const tag = n.tagName!;
    if (!MARKDOWN_TAGS.has(tag) && !CALLOUTS.has(tag)) {
      report(
        file,
        `stray <${tag}> element: a colon followed by "${tag}" was read as a directive; put that text in inline code`,
      );
    }

    const attr = (k: string) => n.attributes?.[k] ?? (n[k] as string | undefined);
    const href = tag === "a" ? attr("href") : undefined;
    if (href !== undefined) {
      if (/^(https?:|mailto:)/.test(href) || href.startsWith("#")) {
        if (href.startsWith("#") && !anchors.get(page.slug)!.has(href.slice(1))) {
          report(file, `link ${href}: no such heading on this page`);
        }
        return;
      }
      if (!href.startsWith("/")) {
        report(file, `link ${href}: use a site-absolute path such as /docs/ingress/ (relative links break on the site)`);
        return;
      }
      const [path, hash] = href.split("#");
      if (path === "/" || path === "/docs/") return;
      const m = /^\/docs\/(.+?)\/$/.exec(path);
      if (!m) {
        report(file, `link ${href}: internal links must look like /docs/<page>/ (with the trailing slash)`);
        return;
      }
      if (!pages.has(m[1])) {
        report(file, `link ${href}: there is no docs/${m[1]}.md`);
      } else if (hash && !anchors.get(m[1])!.has(hash)) {
        report(file, `link ${href}: docs/${m[1]}.md has no heading with id "${hash}"`);
      }
    }

    if (tag === "img") {
      const src = String(attr("src") ?? "");
      if (!attr("alt")) report(file, `image ${src}: alt text is required`);
      if (!/^https?:/.test(src) && !existsSync(resolve(dirname(file), src))) {
        report(file, `image ${src}: file not found (paths are relative to the page)`);
      }
    }
  });
}

// Every page in the sidebar, and nothing in the sidebar that is not a page.
const nav = JSON.parse(readFileSync(join(docsDir, "nav.json"), "utf8"));
const navPaths = new Set<string>();
for (const section of nav.sections) {
  for (const p of section.pages ?? []) navPaths.add(p.path);
  for (const g of section.groups ?? []) for (const p of g.pages ?? []) navPaths.add(p.path);
}
for (const p of navPaths) if (!pages.has(p)) problems.push(`docs/nav.json: "${p}" has no docs/${p}.md`);
for (const slug of pages.keys()) if (!navPaths.has(slug)) problems.push(`docs/${slug}.md: not listed in docs/nav.json`);

if (problems.length) {
  console.error(problems.join("\n"));
  console.error(`\n${problems.length} problem(s) in ${pages.size} page(s).`);
  process.exit(1);
}
console.log(`docs: ${pages.size} pages OK`);
