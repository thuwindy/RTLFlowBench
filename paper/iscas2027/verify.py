#!/usr/bin/env python3
"""Verify the declared paper-source files without importing or executing them."""
from pathlib import Path
import hashlib
import json
import sys

def main():
    root = Path(__file__).resolve().parent
    manifest = json.loads((root / "provenance/source-manifest.json").read_text())
    errors = []
    seen = set()
    for entry in manifest["entries"]:
        relative = Path(entry["path"])
        if relative.is_absolute() or ".." in relative.parts or str(relative) in seen:
            errors.append("unsafe or duplicate manifest path")
            continue
        seen.add(str(relative))
        path = root / relative
        if any(p.is_symlink() for p in [path, *path.parents] if p != root.parent):
            errors.append(f"symlink: {relative}")
            continue
        if not path.is_file():
            errors.append(f"missing: {relative}")
            continue
        payload = path.read_bytes()
        if len(payload) != entry["bytes"] or hashlib.sha256(payload).hexdigest() != entry["sha256"]:
            errors.append(f"hash or size mismatch: {relative}")
    source_roots = [root / name for name in ("sources", "public-tasks", "evaluator-helpers")]
    actual = {str(p.relative_to(root)) for d in source_roots for p in d.rglob("*") if p.is_file()}
    if actual != seen:
        errors.append("source tree membership differs from manifest")
    print(json.dumps({"status": "FAIL" if errors else "PASS", "files_checked": len(seen),
                      "scope": "source bytes only; no EDA/model/runtime replay", "errors": errors}, indent=2))
    return bool(errors)

if __name__ == "__main__":
    sys.exit(main())
