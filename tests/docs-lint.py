"""Lint the pages under docs/ for what only this repository can check.

    python3 -I docs-lint.py <repository root>

The documentation site (Avunu/site-docs) checks links, anchors, images and the Markdown itself when a
release is bumped into it. It does not know this repository, and three things it lets through are
caught here:

  * Front matter. Every page has a `title` and a `description`, and `code`, the list of source files
    the page describes, names only paths that exist. `code` is what tells a reader (and the next person
    to change that code) which pages to revisit; a renamed file would otherwise leave it pointing at
    nothing without a word. Without a `description` the site quietly uses the first paragraph.
  * Colons in prose. Jx reads a colon directly followed by a letter or digit as the start of a text
    directive and deletes the text after it, with no warning and a passing build: `vpn.example.com:51820`
    comes out as "vpn.example.com", and `03:00` as "03". Such text goes in backticks. (Links, bare and
    angle-bracket URLs, code and raw HTML are safe, and are not looked at.)
  * Image alt text. The site renders `![](diagram.svg)` as `alt=""`, which marks a diagram decorative
    and hides it from a screen reader.
"""

import re
import sys
from pathlib import Path

import yaml

root = Path(sys.argv[1])
FRONT_MATTER = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)
FENCE = re.compile(r"^\s{0,3}(```|~~~)")
# What is safe from the directive trap, blanked out before looking for a colon.
SAFE = [
    re.compile(r"(`+).+?\1"),  # code spans
    re.compile(r"\]\([^)]*\)"),  # link and image destinations
    re.compile(r"<[^>\n]*>"),  # autolinks, raw HTML tags, HTML comments on one line
    re.compile(r"https?://[^\s)<>]+"),  # bare URLs
]
DIRECTIVE = re.compile(r"(?<!:):[A-Za-z0-9]")
EMPTY_ALT = re.compile(r"!\[\s*\]\(")
problems = []
pages = sorted((root / "docs").rglob("*.md"))

for page in pages:
    name = page.relative_to(root).as_posix()
    text = page.read_text()
    match = FRONT_MATTER.match(text)
    if match is None:
        problems.append(f"{name}: no front matter")
        continue
    try:
        data = yaml.safe_load(match.group(1))
    except yaml.YAMLError as error:
        problems.append(f"{name}: front matter is not valid YAML ({error})")
        continue
    if not isinstance(data, dict):
        problems.append(f"{name}: front matter is not a mapping")
        continue

    for key in ("title", "description"):
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            problems.append(f"{name}: `{key}` is missing")
    code = data.get("code")
    if code is not None:
        if not isinstance(code, list):
            problems.append(f"{name}: `code` must be a list of paths")
        else:
            for path in code:
                if not (root / str(path)).exists():
                    problems.append(f"{name}: `code` names a missing path: {path}")

    first_body_line = text[: match.end()].count("\n") + 1
    in_fence = False
    for number, line in enumerate(text[match.end() :].split("\n"), first_body_line):
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if EMPTY_ALT.search(line):
            problems.append(f"{name}:{number}: image without alt text")
        prose = line
        for pattern in SAFE:
            prose = pattern.sub(lambda m: " " * len(m.group(0)), prose)
        for hit in DIRECTIVE.finditer(prose):
            around = prose[max(0, hit.start() - 12) : hit.end() + 12].strip()
            problems.append(
                f"{name}:{number}: `{around}`: a colon directly followed by a letter or digit "
                "starts a Jx directive and deletes the text after it; put it in backticks"
            )

if problems:
    print("\n".join(problems), file=sys.stderr)
    print(f"\n{len(problems)} problem(s) in {len(pages)} page(s).", file=sys.stderr)
    sys.exit(1)
print(f"{len(pages)} page(s) OK")
