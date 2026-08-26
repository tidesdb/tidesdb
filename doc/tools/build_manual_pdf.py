#!/usr/bin/env python3
"""Typeset the TidesDB manual (doc/manual.json + its markdown) as a printed book.

The design is a plain academic manual: Century Schoolbook on a single measure,
justified and hyphenated, numbered parts, chapters and sections, running heads,
booktabs rules, unshaded verbatim code, and a contents list with real page
numbers.

Reading order, part titles and chapter titles come from manual.json, so this
stays in step with the site build.

Requires: python-markdown, pygments, and a Chrome/Chromium binary.
Optional:
  * websockets  -- without it there are no page numbers and no running heads
  * pdftotext   -- without it the contents list has no page numbers
  * pdfunite    -- without it every page carries the same running head

Chrome's PDF backend emits no internal link annotations, so nothing in the file
is clickable; the numbering, the running heads and the contents pages are what
carry a reader from one place to another, as in a printed book.

    ./tools/build_manual_pdf.py                       # -> doc/tidesdb-manual.pdf
    ./tools/build_manual_pdf.py --paper b5 --recto-chapters
    ./tools/build_manual_pdf.py --toc-depth 3 -o /tmp/manual.pdf
"""

from __future__ import annotations

import argparse
import base64
import html as html_mod
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import date
from pathlib import Path

try:
    import markdown
    from markdown.extensions.toc import slugify as md_slugify
except ImportError:  # pragma: no cover
    sys.exit("error: python-markdown is required (pip install markdown)")

try:
    from pygments.formatters import HtmlFormatter
except ImportError:  # pragma: no cover
    sys.exit("error: pygments is required (pip install pygments)")

CHROME_CANDIDATES = (
    "google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome",
)

# name -> (width mm, height mm, side margin mm, head margin mm, foot margin mm)
PAPER = {
    "a4":     (210.0, 297.0, 32.0, 20.0, 20.0),
    "letter": (215.9, 279.4, 34.0, 19.0, 19.0),
    "b5":     (176.0, 250.0, 24.0, 17.0, 17.0),   # the usual academic-press trim
    "digest": (139.7, 215.9, 19.0, 14.0, 14.0),   # 5.5 x 8.5 in
}

BODY_STACK = '"C059", "Century Schoolbook L", "Bitstream Charter", "P052", "Nimbus Roman", "Liberation Serif", serif'
MONO_STACK = '"DejaVu Sans Mono", "Nimbus Mono PS", "Liberation Mono", monospace'
MONO_ADVANCE = 0.602   # DejaVu Sans Mono advance width, in em
ROMAN = ("", "I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X",
         "XI", "XII", "XIII", "XIV", "XV", "XVI", "XVII", "XVIII", "XIX", "XX")

FENCE = re.compile(r"^(?P<indent>[ \t]{0,3})(?P<ticks>`{3,}|~{3,})(?P<info>[^`]*)$")
ASIDE_OPEN = re.compile(r"^:::\s*(note|tip|caution|warning|danger|important)\s*(?:\[(.*)\])?\s*$")
ASIDE_CLOSE = re.compile(r"^:::\s*$")
ASIDE_LABEL = {"note": "Note", "tip": "Tip", "caution": "Caution",
               "warning": "Warning", "danger": "Danger", "important": "Important"}
FRONTMATTER = re.compile(r"\A---\r?\n(.*?)\r?\n---\r?\n", re.S)
FM_TITLE = re.compile(r"^title:\s*(.+?)\s*$", re.M)
INTERNAL_HREF = re.compile(r'href="(/[^"#]*)?(#[^"]*)?"')
ID_ATTR = re.compile(r'\bid="([^"]+)"')
HEADING = re.compile(r'<h(?P<level>[234])(?P<attrs>[^>]*)>(?P<text>.*?)</h(?P=level)>', re.S)
PRE_BLOCK = re.compile(r"<pre\b[^>]*>.*?</pre>", re.S)
TAGS = re.compile(r"<[^>]+>")
# Verbatim text and display type are never hyphenated.
NO_HYPHENS = re.compile(r"(?is)<(pre|code|h1|h2|h3|h4)\b.*?</\1>")
# A run of letters that is a word, not part of an entity such as &hellip;
WORD = re.compile(r"(?<![&\w])[A-Za-z]{6,}(?![\w;])")
HYPHEN_DICTS = ("hyph_en_US.dic", "hyph_en_GB.dic", "hyph_en.dic")
SHY = "\u00ad"  # soft hyphen: invisible unless the line breaks there


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def plain_text(markup: str) -> str:
    """Markup reduced to the words a reader sees."""
    return html_mod.unescape(TAGS.sub("", markup)).replace(SHY, "")


def normalise(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", plain_text(text).lower()).strip()


def squash(text: str) -> str:
    """Comparison key for extracted page text. Letterspaced small caps come back
    from pdftotext with spaces sprinkled through them ("Ch apter 15"), so the
    only safe comparison drops every space. Entities have to go too: a heading
    holding &ldquo; must match the curly quote the page actually shows."""
    return re.sub(r"[^a-z0-9]+", "", plain_text(text).lower())


def chapter_prefix(slug: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", slug.strip("/").lower()).strip("-") or "chapter"


class Hyphenator:
    """Liang hyphenation over the system libhyphen patterns.

    Chrome ships no hyphenation dictionary on Linux, so `hyphens: auto` does
    nothing and justified text opens up into rivers. Marking the break points
    ourselves with soft hyphens gets the even colour a book page wants."""

    def __init__(self, path: Path):
        self.patterns: dict[str, list[int]] = {}
        self.maxlen, self.left, self.right = 0, 2, 3
        with path.open(encoding="utf-8", errors="replace") as fh:
            fh.readline()   # character set
            for line in fh:
                line = line.strip()
                if not line or line[0] in "%#":
                    continue
                if line.startswith("LEFTHYPHENMIN"):
                    self.left = int(line.split()[1])
                    continue
                if line.startswith("RIGHTHYPHENMIN"):
                    self.right = int(line.split()[1])
                    continue
                if not re.fullmatch(r"[^\s=/]+", line):
                    continue   # a compound or non-standard rule: skip it
                chars = re.sub(r"\d", "", line)
                points = [0] * (len(chars) + 1)
                idx = 0
                for ch in line:
                    if ch.isdigit():
                        points[idx] = int(ch)
                    else:
                        idx += 1
                self.patterns[chars] = points
                self.maxlen = max(self.maxlen, len(chars))

    @classmethod
    def load(cls, explicit: str | None = None) -> "Hyphenator | None":
        candidates = [Path(explicit)] if explicit else [
            Path("/usr/share/hyphen") / name for name in HYPHEN_DICTS]
        for path in candidates:
            if path.is_file():
                try:
                    return cls(path)
                except OSError:
                    continue
        return None

    def points(self, word: str) -> list[int]:
        work = "." + word.lower() + "."
        points = [0] * (len(work) + 1)
        for i in range(len(work)):
            for j in range(i + 1, min(i + self.maxlen, len(work)) + 1):
                pattern = self.patterns.get(work[i:j])
                if pattern:
                    for k, value in enumerate(pattern):
                        if value > points[i + k]:
                            points[i + k] = value
        return points

    def mark(self, word: str) -> str:
        """The word with soft hyphens at every legal break."""
        if len(word) < self.left + self.right + 1:
            return word
        points = self.points(word)
        out = []
        for i, ch in enumerate(word):
            out.append(ch)
            if self.left - 1 <= i < len(word) - self.right and points[i + 2] % 2:
                out.append(SHY)
        return "".join(out)


def hyphenate_html(body: str, hyph: Hyphenator) -> str:
    """Mark break points in running text, leaving verbatim and display type alone."""
    def mark_text(fragment: str) -> str:
        pieces = []
        pos = 0
        for tag in TAGS.finditer(fragment):
            pieces.append(WORD.sub(lambda m: hyph.mark(m.group(0)), fragment[pos:tag.start()]))
            pieces.append(tag.group(0))
            pos = tag.end()
        pieces.append(WORD.sub(lambda m: hyph.mark(m.group(0)), fragment[pos:]))
        return "".join(pieces)

    out, pos = [], 0
    for skip in NO_HYPHENS.finditer(body):
        out.append(mark_text(body[pos:skip.start()]))
        out.append(skip.group(0))
        pos = skip.end()
    out.append(mark_text(body[pos:]))
    return "".join(out)


def find_chrome(explicit: str | None) -> str:
    for name in filter(None, (explicit, os.environ.get("TIDESDB_CHROME"), *CHROME_CANDIDATES)):
        path = shutil.which(name) or (name if os.path.isfile(name) and os.access(name, os.X_OK) else None)
        if path:
            return path
    sys.exit("error: no Chrome/Chromium found; set --chrome or $TIDESDB_CHROME")


def project_version(doc_dir: Path) -> str | None:
    """Read project(... VERSION x.y.z) from the CMakeLists.txt above doc/."""
    cml = doc_dir.parent / "CMakeLists.txt"
    if not cml.is_file():
        return None
    m = re.search(r"project\s*\([^)]*?VERSION\s+([0-9][0-9.]*)",
                  cml.read_text(encoding="utf-8", errors="replace"), re.I)
    return m.group(1) if m else None


# =========================================================================== #
# markdown
# =========================================================================== #

def strip_frontmatter(text: str) -> tuple[str, str | None]:
    m = FRONTMATTER.match(text)
    if not m:
        return text, None
    t = FM_TITLE.search(m.group(1))
    return text[m.end():], (t.group(1).strip().strip("'\"") if t else None)


def convert_asides(text: str) -> str:
    """Turn Starlight ::: asides into div blocks python-markdown can nest into,
    and reduce Expressive Code fence info strings to the bare language.

    The site's code fences carry directives for the sample extractor, as in
    ```c,no-compile. python-markdown does not recognise an info string like that,
    so it reads the line as ordinary text, then takes the closing fence for an
    opening one and swallows the rest of the chapter into a code block."""
    out: list[str] = []
    depth = 0
    fence: str | None = None
    for line in text.split("\n"):
        marker = FENCE.match(line)
        if marker:
            ticks, info = marker.group("ticks"), (marker.group("info") or "").strip()
            if fence is None:
                fence = ticks[0] * len(ticks)
                lang = re.split(r"[,\s]", info, maxsplit=1)[0] if info else ""
                if not re.fullmatch(r"[A-Za-z0-9_+#-]*", lang):
                    lang = ""
                out.append(f"{marker.group('indent')}{ticks}{lang}")
                continue
            if not info and ticks.startswith(fence[0]) and len(ticks) >= len(fence):
                fence = None
            out.append(line)
            continue
        if fence is not None:   # inside a listing: pass everything through as is
            out.append(line)
            continue
        opened = ASIDE_OPEN.match(line)
        if opened:
            kind, title = opened.group(1), (opened.group(2) or "").strip()
            label = ASIDE_LABEL[kind]
            out += ["", f'<div class="aside aside-{kind}" markdown="1">', ""]
            out += [f'<span class="aside-kind">{label}</span>' + (f"&#8202;&#8212;&#8202;{title}" if title else ""),
                    "{: .aside-title }", ""]
            depth += 1
            continue
        if depth and ASIDE_CLOSE.match(line):
            out += ["", "</div>", ""]
            depth -= 1
            continue
        out.append(line)
    if depth:
        log(f"warning: {depth} unterminated ::: aside(s)")
        out += ["</div>"] * depth
    return "\n".join(out)


def demote_headings(body: str, chapter_title: str) -> str:
    """The chapter opener prints the title, so the file's own h1 is at best a
    duplicate: drop it when it repeats the title, demote it otherwise."""
    first = re.search(r"<h1\b[^>]*>(.*?)</h1>", body, re.S)
    if first and normalise(first.group(1)) == normalise(chapter_title):
        body = body[: first.start()] + body[first.end():]
    return re.sub(r"<(/?)h1\b", r"<\g<1>h2", body)


def render_chapters(manual: dict, doc_dir: Path) -> tuple[list[dict], list[str]]:
    warnings: list[str] = []
    chapters: list[dict] = []
    for part in manual.get("parts", []):
        part_dir = doc_dir / part["dir"]
        for chapter in part.get("chapters", []):
            path = part_dir / chapter["file"]
            if not path.is_file():
                warnings.append(f"missing chapter file: {path}")
                continue
            raw, fm_title = strip_frontmatter(path.read_text(encoding="utf-8"))
            prefix = chapter_prefix(chapter["slug"])
            md = markdown.Markdown(
                extensions=["extra", "attr_list", "md_in_html", "sane_lists", "smarty", "toc", "codehilite"],
                extension_configs={
                    "toc": {"slugify": lambda value, sep, _p=prefix: f"{_p}--{md_slugify(value, sep)}",
                            "toc_depth": "2-3"},
                    "codehilite": {"guess_lang": False, "linenums": False},
                },
            )
            title = chapter.get("title") or fm_title or path.stem
            chapters.append({
                "part": part,
                "id": prefix,
                "title": title,
                "slug": chapter["slug"].strip("/"),
                "html": demote_headings(md.convert(convert_asides(raw)), title),
                "sections": [],
            })
    return chapters, warnings


# =========================================================================== #
# numbering, links, code fitting
# =========================================================================== #

def number_document(chapters: list[dict]) -> None:
    """Number parts in roman, chapters in sequence, sections as chapter.section."""
    part_no = 0
    seen: dict[str, int] = {}
    for n, chapter in enumerate(chapters, 1):
        pid = chapter["part"]["id"]
        if pid not in seen:
            part_no += 1
            seen[pid] = part_no
        chapter["part_number"] = seen[pid]
        chapter["number"] = n
        counters = [0, 0]

        # Reference chapters repeat the same subheadings under every function
        # (Synopsis, Description, Errors). Numbering those is noise, so a chapter
        # whose subheadings recur is numbered to section depth only.
        subs = [normalise(m.group("text")) for m in HEADING.finditer(chapter["html"])
                if m.group("level") == "3"]
        number_subs = len(subs) == len(set(subs))

        def stamp(m: re.Match) -> str:
            level, attrs, text = int(m.group("level")), m.group("attrs"), m.group("text")
            if level == 2:
                counters[0] += 1
                counters[1] = 0
                number = f"{n}.{counters[0]}"
            else:
                if not counters[0] or not number_subs:
                    return m.group(0)
                counters[1] += 1
                number = f"{n}.{counters[0]}.{counters[1]}"
            ident = ID_ATTR.search(attrs)
            chapter["sections"].append({"id": ident.group(1) if ident else "",
                                        "number": number, "title": text, "level": level})
            return f'<h{level}{attrs}><span class="secnum">{number}</span>{text}</h{level}>'

        chapter["html"] = HEADING.sub(stamp, chapter["html"])


def resolve_links(chapters: list[dict], xref_numbers: bool) -> list[str]:
    """Rewrite site-absolute links into in-document anchors, and -- since a paper
    manual has no links -- name the chapter a cross-reference points at."""
    by_slug = {c["slug"]: c for c in chapters}
    ids = {c["id"] for c in chapters}
    for c in chapters:
        ids.update(ID_ATTR.findall(c["html"]))
    dangling: set[str] = set()

    for chapter in chapters:
        def rewrite(m: re.Match) -> str:
            page, frag = m.group(1), m.group(2) or ""
            if page is None:  # same-page anchor: scope it to this chapter
                target = f"{chapter['id']}--{frag[1:]}" if frag else ""
                return f'href="#{target}"' if target in ids else m.group(0)
            target_chapter = by_slug.get(page.strip("/"))
            if target_chapter is None:
                dangling.add(f"{chapter['slug']} -> {page}{frag} (no such chapter)")
                return 'class="dead-xref"'
            anchor = f"{target_chapter['id']}--{frag[1:]}" if frag else target_chapter["id"]
            if anchor not in ids:
                dangling.add(f"{chapter['slug']} -> {page}{frag} (no such heading)")
                anchor = target_chapter["id"]
            cls = "" if target_chapter is chapter else f' class="xref" data-ch="{target_chapter["number"]}"'
            return f'href="#{anchor}"{cls}'

        chapter["html"] = INTERNAL_HREF.sub(rewrite, chapter["html"])
        if xref_numbers:
            chapter["html"] = re.sub(
                r'(<a href="#[^"]*" class="xref" data-ch="(\d+)">.*?</a>)',
                lambda m: f'{m.group(1)}<span class="xref-num"> (ch. {m.group(2)})</span>',
                chapter["html"], flags=re.S)
    return sorted(dangling)


def fit_code(chapters: list[dict], measure_pt: float, indent_pt: float) -> None:
    """Shrink each verbatim block just enough that its longest line fits the
    measure -- nothing is ever clipped, and short listings stay readable."""
    room = measure_pt - indent_pt
    base, floor = 8.4, 6.1

    def size_for(block: str) -> str:
        text = html_mod.unescape(TAGS.sub("", block))
        widest = max((len(line) for line in text.split("\n")), default=0)
        if widest == 0:
            return block
        size = min(base, room / (widest * MONO_ADVANCE) * 0.99)
        if size >= base - 0.05:
            return block
        if size < floor:   # rare: let the listing run into the outer margin
            return block.replace("<pre", f'<pre class="bleed" style="font-size:{floor:.2f}pt"', 1)
        return block.replace("<pre", f'<pre style="font-size:{size:.2f}pt"', 1)

    for chapter in chapters:
        chapter["html"] = PRE_BLOCK.sub(lambda m: size_for(m.group(0)), chapter["html"])


# =========================================================================== #
# the book
# =========================================================================== #

def needs_divider(part: dict, chapters: list[dict]) -> bool:
    """A lone chapter that restates its part's title does not need a part page."""
    own = [c for c in chapters if c["part"]["id"] == part["id"]]
    return not (len(own) == 1 and normalise(own[0]["title"]) == normalise(part["title"]))


def toc_row(kind: str, number: str, title: str, page: int | None) -> str:
    return (f'<p class="toc-row toc-{kind}">'
            f'<span class="toc-num">{number}</span>'
            f'<span class="toc-title">{title}</span>'
            f'<span class="toc-dots"></span>'
            f'<span class="toc-page">{page if page else ""}</span></p>')


def build_toc_html(chapters: list[dict], depth: int) -> str:
    rows = ['<section class="frontmatter toc"><h1>Contents</h1>']
    seen: set[str] = set()
    for c in chapters:
        part = c["part"]
        if part["id"] not in seen:
            seen.add(part["id"])
            if needs_divider(part, chapters):
                rows.append(f'<p class="toc-part">Part {ROMAN[c["part_number"]]} {part["title"]}</p>')
        rows.append(toc_row("chapter", str(c["number"]), c["title"], c.get("page")))
        if depth >= 3:
            for s in c["sections"]:
                if s["level"] == 2:
                    rows.append(toc_row("section", s["number"], s["title"], s.get("page")))
    rows.append("</section>")
    return "\n".join(rows)


def build_body_html(chapters: list[dict]) -> str:
    out: list[str] = []
    seen: set[str] = set()
    for c in chapters:
        part = c["part"]
        if part["id"] not in seen:
            seen.add(part["id"])
            if needs_divider(part, chapters):
                out.append('<section class="part">'
                           f'<p class="part-number">Part {ROMAN[c["part_number"]]}</p>'
                           f'<h1>{part["title"]}</h1></section>')
        out.append(
            f'<section class="chapter" id="{c["id"]}">'
            f'<header class="opener"><p class="chapter-number">Chapter {c["number"]}</p>'
            f'<h1>{c["title"]}</h1></header>\n{c["html"]}\n</section>')
    return "\n".join(out)


def stylesheet(args, code_css: str) -> str:
    width, height, side, head, foot = PAPER[args.paper]
    chapter_break = "right" if args.recto_chapters else "page"
    return f"""
@page {{ size: {width}mm {height}mm; margin: {head}mm {side}mm {foot}mm; }}
* {{ box-sizing: border-box; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
html {{ font-size: {args.body_size}pt; }}
body {{
  margin: 0; font-family: {BODY_STACK}; line-height: 1.42; color: #000;
  text-align: justify; hyphens: auto; -webkit-hyphens: auto;
  orphans: 2; widows: 2; font-kerning: normal;
  font-variant-ligatures: common-ligatures; text-rendering: optimizeLegibility;
}}
p {{ margin: 0; text-indent: 0; }}
p + p {{ text-indent: 1.3em; }}
a {{ color: inherit; text-decoration: none; }}
.xref-num, .dead-xref {{ white-space: nowrap; }}
em {{ font-style: italic; }}
h1, h2, h3, h4 {{ font-weight: 700; break-after: avoid; break-inside: avoid; }}
h2 {{ font-size: 1.14rem; margin: 1.5em 0 .45em; }}
h3 {{ font-size: 1.0rem; margin: 1.25em 0 .35em; }}
h4 {{ font-size: 1.0rem; font-weight: 400; font-style: italic; margin: 1.1em 0 .3em; }}
.secnum {{ margin-right: .7em; font-variant-numeric: lining-nums tabular-nums; }}
ul, ol {{ margin: .55em 0 .75em; padding-left: 1.5em; }}
li {{ margin: .18em 0; }}
li p, li p + p {{ text-indent: 0; }}
hr {{ border: 0; border-top: .4pt solid #000; width: 30%; margin: 1.5em auto; }}
sup {{ line-height: 0; }}

/* --- title page --- */
.title-page {{ break-after: page; text-align: center; padding-top: 30mm; height: 100vh;
               display: flex; flex-direction: column; }}
.title-page .edition {{ margin-top: auto; padding-bottom: 22mm; }}
.title-page .imprint {{ font-variant: small-caps; letter-spacing: .14em; font-size: .8rem; margin-bottom: 26mm; }}
.title-page h1 {{
  font-size: 2.35rem; font-weight: 400; letter-spacing: .1em; text-transform: uppercase;
  margin: 0; padding: .45em 0; border-top: 1.1pt solid #000; border-bottom: 1.1pt solid #000;
}}
.title-page .subtitle {{ font-style: italic; font-size: 1.06rem; margin: 1.6em 0 0; }}
.title-page .edition {{ font-variant: small-caps; letter-spacing: .1em; font-size: .88rem; line-height: 2; }}

/* --- contents --- */
.frontmatter {{ break-before: page; }}
.frontmatter h1 {{
  font-size: 1.5rem; font-weight: 400; text-align: center; letter-spacing: .18em;
  text-transform: uppercase; margin: 0 0 2.2em;
}}
.toc-part {{
  margin: 1.5em 0 .5em; font-variant: small-caps; letter-spacing: .1em; font-size: .95rem;
  text-align: left; text-indent: 0;
}}
.toc-row {{ display: flex; align-items: baseline; text-indent: 0; margin: .12em 0; text-align: left; }}
.toc-num {{ flex: none; width: 2.9em; font-variant-numeric: lining-nums tabular-nums; }}
.toc-section {{ padding-left: 2.9em; font-size: .94rem; }}
.toc-section .toc-num {{ width: 3.1em; }}
.toc-dots {{ flex: 1 1 0; min-width: 1.2em; margin: 0 .3em; overflow: hidden; white-space: nowrap; }}
.toc-dots::before {{ content: "{"." * 200}"; letter-spacing: .28em; }}
.toc-page {{ flex: none; min-width: 2.2em; text-align: right; font-variant-numeric: lining-nums tabular-nums; }}
.toc-title {{ flex: 0 1 auto; white-space: nowrap; }}

/* --- parts and chapters --- */
.part {{
  break-before: {chapter_break}; text-align: center; padding-top: 70mm; break-after: page;
}}
.part-number {{ font-variant: small-caps; letter-spacing: .2em; font-size: .95rem; margin: 0 0 1.4em; }}
.part h1 {{ font-size: 1.85rem; font-weight: 400; letter-spacing: .06em; margin: 0;
            padding-top: .5em; border-top: .6pt solid #000; display: inline-block; }}
.chapter {{ break-before: {chapter_break}; }}
.opener {{ padding-top: 24mm; margin-bottom: 2.1em; }}
.chapter-number {{
  font-variant: small-caps; letter-spacing: .2em; font-size: .9rem; margin: 0 0 .5em;
  padding-bottom: .45em; border-bottom: .6pt solid #000; text-align: left;
}}
.chapter > .opener h1 {{ font-size: 1.75rem; font-weight: 700; margin: 0; text-align: left;
                         line-height: 1.15; hyphens: none; }}

/* --- verbatim --- */
code, kbd, samp {{ font-family: {MONO_STACK}; }}
:not(pre) > code {{ font-size: .86em; hyphens: none; }}
pre {{
  font-family: {MONO_STACK}; font-size: 8.4pt; line-height: 1.32; white-space: pre;
  margin: .95em 0 1.05em 1.5em; text-align: left; hyphens: none; background: none; border: 0;
}}
pre.bleed {{ margin-right: -14mm; }}
pre code {{ font-size: inherit; }}
.codehilite {{ background: none; }}
{code_css}

/* --- tables, set with booktabs rules --- */
table {{ width: 100%; border-collapse: collapse; margin: 1.1em 0; font-size: .9rem;
         text-align: left; hyphens: none; }}
thead {{ display: table-header-group; }}
tr {{ break-inside: avoid; }}
th {{ font-weight: 700; padding: .3em .6em .3em 0; vertical-align: bottom;
      border-top: 1pt solid #000; border-bottom: .5pt solid #000; }}
td {{ padding: .26em .6em .26em 0; vertical-align: top; }}
tbody tr:last-child td {{ border-bottom: 1pt solid #000; }}
th:last-child, td:last-child {{ padding-right: 0; }}

/* --- asides, set as small print between rules --- */
.aside {{
  break-inside: avoid; margin: 1.05em 1.5em; padding: .5em 0; font-size: .92rem; line-height: 1.36;
  border-top: .4pt solid #000; border-bottom: .4pt solid #000;
}}
.aside p {{ text-indent: 0; }}
.aside p + p {{ text-indent: 1.3em; }}
.aside > :last-child {{ margin-bottom: 0; }}
.aside-title {{ font-weight: 700; }}
.aside-kind {{ font-variant: small-caps; letter-spacing: .09em; font-weight: 400; }}
blockquote {{ margin: .9em 1.5em; font-size: .95rem; }}

/* --- colophon --- */
.colophon {{ break-before: page; padding-top: 60mm; text-align: center; font-size: .9rem; }}
.colophon p {{ text-indent: 0; margin: .5em 0; }}
.colophon .rule {{ width: 22%; margin: 0 auto 2em; border-top: .5pt solid #000; }}
"""


def build_html(manual: dict, chapters: list[dict], args, version: str | None) -> str:
    title = manual.get("title", "Manual")
    subtitle = manual.get("subtitle") or "A manual for the storage engine"
    edition = [f"Version {version}" if version else None,
               date.today().strftime("%B %Y")]
    code_css = HtmlFormatter(style=args.code_style).get_style_defs(".codehilite")
    colophon = (f"<p>Set in C059, a Century Schoolbook, with verbatim text in DejaVu Sans Mono.</p>"
                f"<p>Generated from the manual sources at "
                f"{'version ' + version if version else 'the checked-out revision'} "
                f"on {date.today().isoformat()}.</p>")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{title}</title>
<style>{stylesheet(args, code_css)}</style></head><body>
<section class="title-page">
  <p class="imprint">{args.imprint}</p>
  <h1>{title}</h1>
  <p class="subtitle">{subtitle}</p>
  <p class="edition">{"<br>".join(e for e in edition if e)}</p>
</section>
{build_toc_html(chapters, args.toc_depth)}
{build_body_html(chapters)}
<section class="colophon"><div class="rule"></div>{colophon}</section>
</body></html>
"""


# =========================================================================== #
# printing
# =========================================================================== #

def head_template(left: str, args) -> str:
    """A running head: chapter title on the left, page number on the outer edge."""
    _, _, side, head, _ = PAPER[args.paper]
    if left is None:
        return "<span></span>"
    return (f'<div style="width:100%;font-family:{html_mod.escape(BODY_STACK)};font-size:8.5pt;'
            f'padding:0 {side}mm;margin-top:{max(head - 12, 4):.0f}mm;'
            'display:flex;justify-content:space-between;align-items:baseline;'
            'font-variant:small-caps;letter-spacing:.08em;">'
            f'<span>{html_mod.escape(left)}</span>'
            '<span class="pageNumber" style="font-variant:lining-nums"></span></div>')


def print_params(args, ranges: str | None, header: str) -> dict:
    width, height, side, head, foot = PAPER[args.paper]
    mm = 1 / 25.4
    params = {
        "printBackground": True,
        "paperWidth": width * mm,
        "paperHeight": height * mm,
        "marginTop": head * mm,
        "marginRight": side * mm,
        "marginBottom": foot * mm,
        "marginLeft": side * mm,
        "displayHeaderFooter": True,
        "headerTemplate": header,
        "footerTemplate": "<span></span>",
        "preferCSSPageSize": False,
    }
    if ranges:
        params["pageRanges"] = ranges
    return params


def launch_chrome(chrome: str, profile: Path, extra: list[str]) -> subprocess.Popen:
    cmd = [chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
           "--no-default-browser-check", "--disable-extensions", "--disable-lcd-text",
           "--font-render-hinting=none", f"--user-data-dir={profile}", *extra]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def print_jobs(chrome: str, html: Path, jobs: list[tuple], args) -> bool:
    """Run one Chrome session and print each (pageRanges, headerTemplate, path) job.
    Returns False when websockets is missing, so the caller can fall back."""
    try:
        import asyncio
        import websockets
    except ImportError:
        return False

    async def run() -> None:
        with tempfile.TemporaryDirectory(prefix="tidesdb-pdf-") as tmp:
            profile = Path(tmp)
            proc = launch_chrome(chrome, profile, ["--remote-debugging-port=0", "about:blank"])
            try:
                port_file = profile / "DevToolsActivePort"
                deadline = time.monotonic() + 30
                lines: list[str] = []
                while time.monotonic() < deadline:
                    if port_file.is_file():
                        lines = port_file.read_text().splitlines()
                        if len(lines) >= 2:
                            break
                    if proc.poll() is not None:
                        raise RuntimeError("chrome exited before the debug port was ready")
                    await asyncio.sleep(0.05)
                else:
                    raise RuntimeError("timed out waiting for chrome's debug port")

                async with websockets.connect(f"ws://127.0.0.1:{lines[0]}{lines[1]}",
                                              max_size=None, ping_interval=None) as ws:
                    counter = iter(range(1, 1 << 30))
                    seen: set[str] = set()   # events can arrive before the reply expecting them

                    async def pump(timeout=None):
                        raw = await (asyncio.wait_for(ws.recv(), timeout) if timeout else ws.recv())
                        msg = json.loads(raw)
                        if "method" in msg:
                            seen.add(msg["method"])
                        return msg

                    async def call(method, params=None, session=None):
                        mid = next(counter)
                        msg = {"id": mid, "method": method, "params": params or {}}
                        if session:
                            msg["sessionId"] = session
                        await ws.send(json.dumps(msg))
                        while True:
                            reply = await pump()
                            if reply.get("id") == mid:
                                if "error" in reply:
                                    raise RuntimeError(f"{method}: {reply['error']}")
                                return reply.get("result", {})

                    async def wait_event(name, timeout):
                        end = time.monotonic() + timeout
                        while name not in seen:
                            left = end - time.monotonic()
                            if left <= 0:
                                return False
                            try:
                                await pump(left)
                            except asyncio.TimeoutError:
                                return False
                        return True

                    target = await call("Target.createTarget", {"url": "about:blank"})
                    sess = (await call("Target.attachToTarget",
                                       {"targetId": target["targetId"], "flatten": True}))["sessionId"]
                    await call("Page.enable", session=sess)
                    await call("Page.navigate", {"url": html.as_uri()}, session=sess)
                    if not await wait_event("Page.loadEventFired", args.timeout):
                        log("warning: page load event never fired; printing anyway")
                    await call("Runtime.evaluate",
                               {"expression": "document.fonts.ready.then(() => true)", "awaitPromise": True},
                               session=sess)
                    for ranges, header, out_path in jobs:
                        result = await call("Page.printToPDF", print_params(args, ranges, header), session=sess)
                        Path(out_path).write_bytes(base64.b64decode(result["data"]))
                    try:
                        await call("Browser.close")
                    except Exception:
                        pass
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        proc.kill()

    try:
        asyncio.run(run())
    except Exception as exc:
        log(f"warning: DevTools print failed ({exc}); falling back to --print-to-pdf")
        return False
    return True


def print_with_cli(chrome: str, html: Path, out: Path, args) -> None:
    """Fallback: no page numbers and no running heads; geometry comes from @page."""
    with tempfile.TemporaryDirectory(prefix="tidesdb-pdf-") as tmp:
        proc = launch_chrome(chrome, Path(tmp),
                             ["--no-pdf-header-footer", "--run-all-compositor-stages-before-draw",
                              f"--print-to-pdf={out}", html.as_uri()])
        try:
            proc.wait(timeout=args.timeout + 60)
        except subprocess.TimeoutExpired:
            proc.kill()
            sys.exit("error: chrome timed out while printing")
    if proc.returncode != 0 or not out.is_file():
        sys.exit(f"error: chrome failed to print (exit {proc.returncode})")


# =========================================================================== #
# pagination
# =========================================================================== #

def page_lines(pdf: Path) -> list[list[str]] | None:
    """Extracted text of each page, as stripped non-empty lines."""
    if not shutil.which("pdftotext"):
        return None
    try:
        proc = subprocess.run(["pdftotext", "-layout", str(pdf), "-"],
                              capture_output=True, check=True)
    except (subprocess.CalledProcessError, OSError):
        return None
    return [[l.strip() for l in page.splitlines() if l.strip()]
            for page in proc.stdout.decode("utf-8", "replace").split("\f")]


def locate(pages: list[list[str]], chapters: list[dict]) -> None:
    """Find the page each chapter and each section opens on."""
    cursor = 0
    for c in chapters:
        c["page"] = None
        want_number = squash(f"Chapter {c['number']}")
        want_title = squash(c["title"])
        for i in range(cursor, len(pages)):
            lines = pages[i]
            if len(lines) >= 2 and squash(lines[0]) == want_number and squash(lines[1]).startswith(want_title):
                c["page"] = i + 1
                cursor = i
                break
        else:
            log(f"warning: could not locate chapter {c['number']} ({c['title']}) in the printed pages")
    for n, c in enumerate(chapters):
        opener = (c.get("page") or 1) - 1
        end = next((chapters[m]["page"] - 1 for m in range(n + 1, len(chapters)) if chapters[m].get("page")),
                   len(pages))
        here = opener
        for s in c["sections"]:
            if s["level"] != 2:
                continue
            want = squash(f"{s['number']} {s['title']}")
            # A heading that breaks across lines will not match whole; its opening
            # words still do, and a section never precedes the one before it.
            stub = want[:max(len(squash(s["number"])) + 8, 12)]
            found = None
            for i in range(here, end):
                lines = [squash(line) for line in pages[i]]
                if any(line == want for line in lines):
                    found = i
                    break
                if found is None and any(line.startswith(stub) for line in lines):
                    found = i
                    break
            # Falling back to where the section cannot be before keeps it in the
            # outline: a bookmark one page early beats a missing one.
            s["page"] = (found if found is not None else here) + 1
            here = s["page"] - 1


def part_pages(pages: list[list[str]], chapters: list[dict]) -> set[int]:
    """Pages carrying a part title, which take no running head."""
    found: set[int] = set()
    for c in chapters:
        if not c.get("page") or not needs_divider(c["part"], chapters):
            continue
        candidate = c["page"] - 2   # the page before the chapter opener, zero-based
        if 0 <= candidate < len(pages):
            lines = pages[candidate]
            if lines and squash(lines[0]) == squash(f"Part {ROMAN[c['part_number']]}"):
                found.add(candidate + 1)
    return found


def stitch(chrome: str, html: Path, out: Path, pages: list[list[str]], chapters: list[dict], args) -> bool:
    """Print each chapter with its own running head, then join the pieces."""
    if not shutil.which("pdfunite"):
        return False
    located = [c for c in chapters if c.get("page")]
    if len(located) != len(chapters):
        return False
    total = len(pages)
    if pages and not pages[-1]:
        total -= 1   # pdftotext leaves a trailing empty page after the last \f
    # Part pages and the page a chapter opens on carry no running head, the way
    # a book leaves its display pages clear.
    bare = part_pages(pages, chapters) | {c["page"] for c in located}

    spans: list[tuple[int, int, str | None]] = []
    first = located[0]["page"]
    if first > 1:
        spans.append((1, first - 1, None))      # title page and contents
    for n, c in enumerate(located):
        end = located[n + 1]["page"] - 1 if n + 1 < len(located) else total
        head = f"{c['number']}. {c['title']}"
        start = c["page"]
        for page in sorted(p for p in bare if start <= p <= end):
            if page > start:
                spans.append((start, page - 1, head))
            spans.append((page, page, None))
            start = page + 1
        if start <= end:
            spans.append((start, end, head))

    with tempfile.TemporaryDirectory(prefix="tidesdb-parts-") as tmp:
        jobs, parts = [], []
        for n, (lo, hi, head) in enumerate(spans):
            piece = Path(tmp) / f"part-{n:03d}.pdf"
            jobs.append((f"{lo}-{hi}", head_template(head, args), piece))
            parts.append(str(piece))
        if not print_jobs(chrome, html, jobs, args):
            return False
        try:
            subprocess.run(["pdfunite", *parts, str(out)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        except (subprocess.CalledProcessError, OSError) as exc:
            log(f"warning: pdfunite failed ({exc}); keeping the single-pass file")
            return False
    return True


# =========================================================================== #
# the outline a reader navigates by
# =========================================================================== #
#
# The outline is appended as an incremental update rather than handed to a tool
# that rewrites the file. Ghostscript would do the job in three lines, but its
# pdfwrite device re-encodes the fonts and loses the ligature mappings with them:
# after a pass through it, searching the manual for "file" misses every "fi" in
# the book. Appending leaves every existing byte, and so the whole text layer,
# exactly as Chrome wrote it.

OBJ_DEF = "{} 0 obj"
TRAILER = re.compile(rb"trailer\s*<<(.*?)>>\s*startxref\s+(\d+)", re.S)
REF = re.compile(rb"(\d+)\s+\d+\s+R")


def pdf_string(text: str) -> str:
    """A PDF text string: UTF-16BE hex, so dashes and curly quotes survive."""
    return "<FEFF" + plain_text(text).encode("utf-16-be", "replace").hex().upper() + ">"


def last_object(data: bytes, number: int) -> bytes | None:
    """The newest definition of an object, as the bytes between obj and endobj."""
    found = None
    for m in re.finditer(rf"(?<![0-9]){number}\s+0\s+obj".encode(), data):
        stop = data.find(b"endobj", m.end())
        if stop != -1:
            found = data[m.end():stop]
    return found


def bracketed(dictionary: bytes, key: bytes) -> bytes | None:
    """The array following a key, brackets included."""
    at = dictionary.find(key)
    if at == -1:
        return None
    open_at = dictionary.find(b"[", at)
    if open_at == -1:
        return None
    depth = 0
    for i in range(open_at, len(dictionary)):
        if dictionary[i:i + 1] == b"[":
            depth += 1
        elif dictionary[i:i + 1] == b"]":
            depth -= 1
            if depth == 0:
                return dictionary[open_at:i + 1]
    return None


def page_objects(data: bytes, catalog: bytes) -> list[int]:
    """Every page object number, in the order the pages are printed."""
    pages_ref = re.search(rb"/Pages\s+(\d+)\s+\d+\s+R", catalog)
    if not pages_ref:
        return []
    order: list[int] = []

    def walk(number: int, depth: int = 0) -> None:
        if depth > 32:
            return
        node = last_object(data, number)
        if node is None:
            return
        if re.search(rb"/Type\s*/Page[^s]", node):
            order.append(number)
            return
        kids = bracketed(node, b"/Kids")
        if kids:
            for kid in REF.finditer(kids):
                walk(int(kid.group(1)), depth + 1)

    walk(int(pages_ref.group(1)))
    return order


def outline_items(chapters: list[dict]) -> list[dict]:
    """Parts, their chapters and their sections, as a flat list with levels."""
    items: list[dict] = []
    seen: set[str] = set()
    for c in chapters:
        if not c.get("page"):
            continue
        part = c["part"]
        if part["id"] not in seen:
            seen.add(part["id"])
            page = c["page"]
            if needs_divider(part, chapters) and page > 1:
                page -= 1        # the part page sits just before its first chapter
            items.append({"level": 0, "page": page,
                          "title": f"Part {ROMAN[c['part_number']]}  {part['title']}"})
        items.append({"level": 1, "page": c["page"], "title": f"{c['number']}  {c['title']}"})
        for s in c["sections"]:
            if s["level"] == 2 and s.get("page"):
                items.append({"level": 2, "page": s["page"],
                              "title": f"{s['number']}  {plain_text(s['title'])}"})
    return items


def attach_outline(pdf: Path, chapters: list[dict]) -> bool:
    """Append an outline to a finished PDF, leaving its pages untouched."""
    data = pdf.read_bytes()
    trailers = list(TRAILER.finditer(data))
    if not trailers:
        log("warning: no classic trailer in the PDF; skipping the outline")
        return False
    trailer, prev_xref = trailers[-1].group(1), int(trailers[-1].group(2))
    root = re.search(rb"/Root\s+(\d+)\s+\d+\s+R", trailer)
    size = re.search(rb"/Size\s+(\d+)", trailer)
    if not root or not size:
        return False
    # pdfunite writes a /Size lower than the object numbers it actually used, so
    # taking new numbers from it would overwrite live objects. The highest number
    # in the file is the only safe starting point.
    highest = max((int(m.group(1)) for m in re.finditer(rb"(?:^|[^0-9])(\d+)\s+\d+\s+obj", data)),
                  default=int(size.group(1)) - 1)
    catalog_no, next_no = int(root.group(1)), max(highest + 1, int(size.group(1)))
    catalog = last_object(data, catalog_no)
    if catalog is None:
        return False
    pages = page_objects(data, catalog)
    items = [i for i in outline_items(chapters) if 1 <= i["page"] <= len(pages)]
    if not items:
        log("warning: nothing to put in the outline")
        return False

    # Number the outline root and every item, then link them: an item's siblings
    # are the next and previous entries at its own level within the same parent.
    root_no = next_no
    for n, item in enumerate(items):
        item["no"] = root_no + 1 + n
    for n, item in enumerate(items):
        parent, prev, nxt = root_no, None, None
        for other in reversed(items[:n]):
            if other["level"] < item["level"]:
                parent = other["no"]
                break
            if other["level"] == item["level"]:
                prev = prev or other["no"]
        for other in items[n + 1:]:
            if other["level"] < item["level"]:
                break
            if other["level"] == item["level"]:
                nxt = other["no"]
                break
        item.update(parent=parent, prev=prev, next=nxt)

    def children_of(number: int) -> list[dict]:
        return [i for i in items if i["parent"] == number]

    def render(item: dict) -> str:
        kids = children_of(item["no"])
        body = [f"/Title {pdf_string(item['title'])}", f"/Parent {item['parent']} 0 R"]
        if item["prev"]:
            body.append(f"/Prev {item['prev']} 0 R")
        if item["next"]:
            body.append(f"/Next {item['next']} 0 R")
        if kids:
            body.append(f"/First {kids[0]['no']} 0 R /Last {kids[-1]['no']} 0 R")
            # Parts open to show their chapters; chapters keep their sections folded.
            body.append(f"/Count {len(kids) if item['level'] == 0 else -len(kids)}")
        body.append(f"/Dest [{pages[item['page'] - 1]} 0 R /XYZ null null null]")
        return "<< " + " ".join(body) + " >>"

    top = children_of(root_no)
    visible = len(top) + sum(len(children_of(i["no"])) for i in top)
    out = bytearray(data)
    if not out.endswith(b"\n"):
        out += b"\n"
    offsets: dict[int, int] = {}

    def append(number: int, body: str) -> None:
        offsets[number] = len(out)
        out.extend(f"{number} 0 obj\n{body}\nendobj\n".encode("ascii"))

    append(root_no, "<< /Type /Outlines "
                    f"/First {top[0]['no']} 0 R /Last {top[-1]['no']} 0 R /Count {visible} >>")
    for item in items:
        append(item["no"], render(item))

    # A fresh catalog, carrying the keys it already had plus the outline.
    body = re.sub(rb"/Outlines\s+\d+\s+\d+\s+R", b"", catalog)
    body = re.sub(rb"/PageMode\s*/\w+", b"", body).strip()
    inner = body[2:-2].strip() if body.startswith(b"<<") and body.endswith(b">>") else body
    append(catalog_no, f"<< {inner.decode('latin-1')} /Outlines {root_no} 0 R /PageMode /UseOutlines >>")

    # An incremental xref: one subsection for the catalog, one for the new objects.
    start_xref = len(out)
    numbers = sorted(offsets)
    runs: list[list[int]] = []
    for number in numbers:
        if runs and number == runs[-1][-1] + 1:
            runs[-1].append(number)
        else:
            runs.append([number])
    out.extend(b"xref\n")
    for run in runs:
        out.extend(f"{run[0]} {len(run)}\n".encode("ascii"))
        for number in run:
            out.extend(f"{offsets[number]:010d} 00000 n \n".encode("ascii"))
    ident = bracketed(trailer, b"/ID")
    out.extend(f"trailer\n<< /Size {items[-1]['no'] + 1} /Root {catalog_no} 0 R "
               f"/Prev {prev_xref}".encode("ascii"))
    if ident:
        out.extend(b" /ID " + ident)
    out.extend(f" >>\nstartxref\n{start_xref}\n%%EOF\n".encode("ascii"))
    pdf.write_bytes(bytes(out))
    return True


def parse_margins(text: str) -> float:
    return float(text)


def main() -> int:
    default_doc = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description="Typeset the TidesDB manual as a PDF book.")
    ap.add_argument("doc_dir", nargs="?", type=Path, default=default_doc,
                    help=f"documentation directory holding manual.json (default: {default_doc})")
    ap.add_argument("-o", "--output", type=Path, help="output PDF (default: <doc_dir>/tidesdb-manual.pdf)")
    ap.add_argument("--paper", choices=sorted(PAPER), default="a4",
                    help="trim size: a4, letter, b5 (academic press), digest (default: a4)")
    ap.add_argument("--body-size", type=float, default=11.0, help="body type size in points (default: 11)")
    ap.add_argument("--toc-depth", type=int, choices=(2, 3), default=2,
                    help="2 = chapters only (default), 3 = also list sections")
    ap.add_argument("--code-style", default="bw", help="pygments style for code (default: bw, black and white)")
    ap.add_argument("--imprint", default="TidesDB", help="small-caps line above the title (default: TidesDB)")
    ap.add_argument("--manual-version", help="version on the title page (default: from CMakeLists.txt)")
    ap.add_argument("--recto-chapters", action="store_true",
                    help="open every part and chapter on a right-hand page, as a printed book does")
    ap.add_argument("--no-xref-numbers", dest="xref_numbers", action="store_false",
                    help="do not annotate cross-references with the chapter they point at")
    ap.add_argument("--no-running-heads", dest="running_heads", action="store_false",
                    help="skip the per-chapter running heads, which prints far fewer passes")
    ap.add_argument("--no-bookmarks", dest="bookmarks", action="store_false",
                    help="do not attach the PDF outline (parts, chapters and sections)")
    ap.add_argument("--no-hyphenation", dest="hyphenate", action="store_false",
                    help="do not mark hyphenation points (justification will be looser)")
    ap.add_argument("--hyphen-dict", help="libhyphen pattern file (default: the system en_US one)")
    ap.add_argument("--chrome", help="path to the Chrome/Chromium binary")
    ap.add_argument("--timeout", type=int, default=120, help="seconds to wait for the page to render")
    ap.add_argument("--html-only", action="store_true", help="write the intermediate HTML and stop")
    ap.add_argument("--keep-html", action="store_true", help="also keep the HTML next to the PDF")
    ap.add_argument("-q", "--quiet", action="store_true", help="only report errors")
    args = ap.parse_args()

    doc_dir = args.doc_dir.expanduser().resolve()
    manual_path = doc_dir / "manual.json"
    if not manual_path.is_file():
        sys.exit(f"error: no manual.json in {doc_dir}")
    out = (args.output or doc_dir / "tidesdb-manual.pdf").expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    manual = json.loads(manual_path.read_text(encoding="utf-8"))
    chapters, warnings = render_chapters(manual, doc_dir)
    if not chapters:
        sys.exit("error: manual.json listed no readable chapters")
    number_document(chapters)
    warnings += resolve_links(chapters, args.xref_numbers)

    width, _, side, _, _ = PAPER[args.paper]
    measure_pt = (width - 2 * side) * 72 / 25.4
    fit_code(chapters, measure_pt, 1.5 * args.body_size)

    if args.hyphenate:
        hyph = Hyphenator.load(args.hyphen_dict)
        if hyph is None:
            warnings.append("no hyphenation dictionary found; justified text will be loose "
                            "(install hyphen-en-us, or pass --no-hyphenation)")
        else:
            for c in chapters:
                c["html"] = hyphenate_html(c["html"], hyph)

    version = args.manual_version or project_version(doc_dir)
    for w in warnings:
        log(f"warning: {w}")

    workdir = Path(tempfile.mkdtemp(prefix="tidesdb-pdf-"))
    html_path = out.with_suffix(".html") if (args.html_only or args.keep_html) else workdir / "manual.html"
    html_path.write_text(build_html(manual, chapters, args, version), encoding="utf-8")
    if args.html_only:
        shutil.rmtree(workdir, ignore_errors=True)
        if not args.quiet:
            print(f"wrote {html_path} ({len(chapters)} chapters)")
        return 0

    chrome = find_chrome(args.chrome)
    if not args.quiet:
        log(f"setting {len(chapters)} chapters ...")

    draft = workdir / "draft.pdf"
    if not print_jobs(chrome, html_path, [(None, head_template(None, args), draft)], args):
        print_with_cli(chrome, html_path, out, args)
        shutil.rmtree(workdir, ignore_errors=True)
        if not args.quiet:
            print(f"wrote {out} (no page numbers or running heads: install websockets for those)")
        return 0

    pages = page_lines(draft)
    if pages is None:
        log("warning: pdftotext not found; the contents list will have no page numbers")
        shutil.copyfile(draft, out)
    else:
        locate(pages, chapters)                          # first pass: where things landed
        html_path.write_text(build_html(manual, chapters, args, version), encoding="utf-8")
        if not print_jobs(chrome, html_path, [(None, head_template(None, args), draft)], args):
            sys.exit("error: second pass failed")
        pages = page_lines(draft) or pages
        locate(pages, chapters)                          # confirm nothing shifted
        if not (args.running_heads and stitch(chrome, html_path, out, pages, chapters, args)):
            shutil.copyfile(draft, out)
        if args.bookmarks and not attach_outline(out, chapters):
            log("warning: the PDF has no outline, so a reader's sidebar will be empty")

    shutil.rmtree(workdir, ignore_errors=True)
    if not args.quiet:
        size = out.stat().st_size / 1024
        counted = page_lines(out) or []
        if counted and not counted[-1]:
            counted.pop()      # pdftotext leaves an empty page after the last form feed
        printed = len(counted) or "?"
        print(f"wrote {out} ({size:.0f} KiB, {len(chapters)} chapters, {printed} pages"
              + (f", version {version}" if version else "") + ")")
    return 0


if __name__ == "__main__":
    sys.exit(main())
