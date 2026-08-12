#!/usr/bin/env python3
"""Build a release's notes from the CHANGELOG.

The release workflow used to take the section for the version being released and
nothing else. That is right when every version is released, and quietly wrong
when several are bundled into one release: `v0.31.2` shipped describing two
listing fixes, while the eleven versions it actually contained — the whole MCP
surface — went unmentioned. The notes were not incomplete in a way anyone could
see; they read like a small patch release.

So the range is the unit, not the version: everything from the version being
released back to the last one that was actually tagged. A single-version release
is the same case with one section in it, and comes out exactly as before.

Reading the tag list rather than the CHANGELOG alone is what makes that possible.
The CHANGELOG knows what changed; only the tags know what was published.

Usage (tags arrive on stdin, one per line; none means "no previous release"):

    git tag --list 'v*' | python scripts/release_notes.py --version 0.31.2
"""
from __future__ import annotations

import argparse
import re
import sys
from typing import Iterable, List, Optional, Sequence, Tuple

SECTION_RE = re.compile(r"^## \[([^\]]+)\]")


def version_key(version: str) -> Tuple[int, ...]:
    """A sortable key for a dotted version.

    Non-numeric components sort as 0 rather than raising: a malformed tag in the
    repository should not be able to fail a release.
    """
    parts: List[int] = []
    for piece in version.split("."):
        digits = re.match(r"\d+", piece.strip())
        parts.append(int(digits.group()) if digits else 0)
    return tuple(parts)


def parse_sections(changelog: str) -> List[Tuple[str, str]]:
    """Every ``## [version]`` section as (version, body), in file order.

    The body excludes its own heading, so a single-section result is byte-identical
    to what the previous awk one-liner produced.
    """
    sections: List[Tuple[str, str]] = []
    current: Optional[str] = None
    body: List[str] = []
    for line in changelog.splitlines():
        match = SECTION_RE.match(line)
        if match:
            if current is not None:
                sections.append((current, "\n".join(body).strip("\n")))
            current = match.group(1).strip()
            body = []
        elif current is not None:
            body.append(line)
    if current is not None:
        sections.append((current, "\n".join(body).strip("\n")))
    return sections


def previous_version(tags: Iterable[str], target: str) -> Optional[str]:
    """The highest already-released version strictly below ``target``.

    Strictly below, not simply "the next tag down", so a tag for a later version
    — a hotfix branch, a mistake — cannot make the range run backwards and come
    out empty.
    """
    target_key = version_key(target)
    below = [
        tag.lstrip("v").strip()
        for tag in tags
        if tag.strip() and version_key(tag.lstrip("v").strip()) < target_key
    ]
    return max(below, key=version_key) if below else None


def extract_notes(changelog: str, version: str, since: Optional[str] = None) -> str:
    """The notes for ``version``, back to but excluding ``since``.

    Raises :class:`LookupError` when the version has no section at all. An empty
    body is how the old extraction failed — silently, into a published release —
    so the absence is made loud rather than left to become an empty page.
    """
    sections = parse_sections(changelog)
    index = next((i for i, (v, _) in enumerate(sections) if v == version), None)
    if index is None:
        raise LookupError(f"CHANGELOG.md has no '## [{version}]' section")

    included = [sections[index]]
    for entry in sections[index + 1:]:
        # No previous release means no lower bound: a first release covers the
        # whole file. Erring long is the safe direction — over-reporting is
        # visible on the release page, under-reporting is what shipped once
        # already and looked fine.
        if since is not None and entry[0] == since:
            break
        included.append(entry)

    if len(included) == 1:
        return included[0][1].strip("\n") + "\n"

    # More than one version in the release, so each keeps its heading — otherwise
    # the reader cannot tell which change arrived when, which is most of the
    # value of bundling them.
    parts = [f"## {v}\n\n{body}".rstrip() for v, body in included]
    return "\n\n".join(parts) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="version being released, without the leading v")
    parser.add_argument("--changelog", default="CHANGELOG.md")
    parser.add_argument(
        "--since",
        default=None,
        help="stop before this version; by default the highest tag below --version, read from stdin",
    )
    args = parser.parse_args(argv)

    with open(args.changelog, "r", encoding="utf-8") as handle:
        changelog = handle.read()

    since = args.since
    if since is None and not sys.stdin.isatty():
        since = previous_version(sys.stdin.read().splitlines(), args.version)

    try:
        notes = extract_notes(changelog, args.version, since)
    except LookupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if since:
        print(f"note: notes cover {args.version} back to {since}", file=sys.stderr)
    else:
        print(f"note: no earlier release found; notes cover {args.version} onwards", file=sys.stderr)

    sys.stdout.write(notes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
