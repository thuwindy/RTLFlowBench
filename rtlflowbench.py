#!/usr/bin/env python3
"""Offline public-preview tools. No model requests and no hidden evaluation."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parent


def inventory(root):
    result = {}
    for path in sorted(root.rglob('*')):
        rel = path.relative_to(root)
        if any(x in {'.git', '__pycache__', '.venv'} for x in rel.parts):
            continue
        if path.is_symlink():
            raise ValueError('symlink is not permitted: ' + str(rel))
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError('non-regular file: ' + str(rel))
        if str(rel) == 'public-release-lock.json':
            continue
        result[rel.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def verify(root=ROOT):
    lock = json.loads((root / 'public-release-lock.json').read_text())
    if inventory(root) != lock['files']:
        raise ValueError('public tree differs from lock (added, missing or modified file)')
    from jsonschema import Draft202012Validator
    schema = json.loads((root / 'schemas/task.schema.json').read_text())
    Draft202012Validator.check_schema(schema)
    packets = sorted((root / 'candidate/tasks').glob('*/public/external_task.json'))
    if len(packets) != 12:
        raise ValueError('expected exactly twelve tasks')
    candidate = json.loads((root / 'candidate/candidate-lock.json').read_text())
    for row in candidate['tasks']:
        public = root / 'candidate/tasks' / row['task_id'] / 'public'
        if inventory(public) != row['candidate_public_inventory']:
            raise ValueError('candidate packet mismatch: ' + row['task_id'])
    for packet in packets:
        task = json.loads(packet.read_text())
        Draft202012Validator(schema).validate(task)
        if task['packet_status'] != 'draft':
            raise ValueError('preview cannot claim frozen task')
    return {'status': 'VERIFIED_PUBLIC_PREVIEW', 'tasks': len(packets),
            'files': len(lock['files']), 'benchmark_ready': False,
            'meaning': 'Integrity/schema check only; not RTL correctness or admission.'}


def export(task_id, output, root=ROOT):
    verify(root)
    choices = {p.name: p for p in (root / 'candidate/tasks').iterdir() if p.is_dir()}
    if task_id not in choices:
        raise ValueError('unknown exact task id')
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError('refusing to overwrite output')
    # No repository clone or private material is implicitly added.
    shutil.copytree(choices[task_id] / 'public', output)
    return {'status': 'EXPORTED_PUBLIC_PREVIEW', 'task_id': task_id,
            'repository_projection_included': False, 'benchmark_ready': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('verify')
    sub.add_parser('list')
    ex = sub.add_parser('export-public')
    ex.add_argument('--task', required=True)
    ex.add_argument('--output', type=Path, required=True)
    sub.add_parser('evaluate', help='Fail closed: private evaluator not distributed in preview')
    args = parser.parse_args()
    try:
        if args.command == 'verify':
            result = verify()
        elif args.command == 'list':
            verify()
            result = [{'task_id': p.parent.parent.name,
                       'family': json.loads(p.read_text())['family']}
                      for p in sorted((ROOT / 'candidate/tasks').glob('*/public/external_task.json'))]
        elif args.command == 'export-public':
            result = export(args.task, args.output)
        else:
            print(json.dumps({'status': 'BLOCK', 'reason': 'v3 private evaluator, environment and admission bindings pending', 'score': None}))
            return 2
        print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({'status': 'BLOCK', 'reason': str(exc)}))
        return 2


if __name__ == '__main__':
    sys.exit(main())
