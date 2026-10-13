"""Materialize an explicit controller source-binding successor, never launch it.

Only the reviewed single-flight transport pair may change. Parent runner/policy,
budgets, prompts, public tasks, scores, approvals and historic receipts are not
edited. The v1 wire schema is retained; the source inventory gives a NEW runtime
identity. Declared closure is not a whole-runtime isolation certificate.
"""
import argparse
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import runpy
import stat
import sys

sys.dont_write_bytecode = True
TRANSPORT = 'benchmarks/golden12/execution/observed_controller_transport.py'
RUNNER = 'benchmarks/golden12/execution/run_controller_aware_resource_measurement.py'
POLICY = 'benchmarks/golden12/admission/release_freeze_policy_candidate.json'
POLICY_BUILDER = 'benchmarks/golden12/admission/build_release_freeze_policy_candidate.py'
POLICY_SCHEMA = 'benchmarks/golden12/admission/release_freeze_policy_candidate.schema.json'
OLD_TRANSPORT = '0aeff03b0bdf44f8a7a03c0d123c213b7f9a66579aa9bff0f3235c37eab47788'
NEW_TRANSPORT = '6f1e7a985d06325c1d372d196777b0ae6c22868dfef5207cfa1af39357bf5ecc'
PINS = {
    TRANSPORT: NEW_TRANSPORT,
    RUNNER: '82b8b6407e14a05a057e86da1a927bad9b8b1f4dbbeec582939d845800ad282a',
    POLICY: 'f8f423df08349e8b9808dce892154f817a950e29df8baf7d47df7c7f72e7a9d5',
    POLICY_BUILDER: '73407ae94f93f060bf00b91fd7e0022bc27faeb88f75055fc1158167bf78445a',
}


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_bytes(path, *, allow_shared_inode=False):
    """Bounded no-follow read. Only read-only authority snapshots allow hardlinks."""
    path = Path(os.path.abspath(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(leaf, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and (allow_shared_inode or info.st_nlink == 1), 'unsafe file')
            require(info.st_size <= 16 * 1024 * 1024, 'oversized file')
            value = stream.read(16 * 1024 * 1024 + 1)
            require(len(value) <= 16 * 1024 * 1024, 'oversized file')
            return value
    except OSError as error:
        raise ValueError('unsafe or unavailable file') from error
    finally:
        os.close(fd)


def decode(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result

    def invalid(_):
        raise ValueError('non-finite value')

    value = json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)

    def finite(item):
        if isinstance(item, float):
            require(math.isfinite(item), 'non-finite value')
        elif isinstance(item, dict):
            for child in item.values():
                finite(child)
        elif isinstance(item, list):
            for child in item:
                finite(child)

    finite(value)
    return value


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def render_runner(source):
    old, new = OLD_TRANSPORT.encode(), NEW_TRANSPORT.encode()
    require(source.count(old) == 1 and new not in source, 'ambiguous runner transition')
    return source.replace(old, new)


def require_policy_delta(old, new):
    expected = copy.deepcopy(old)
    binding = expected['guard_source_bindings']['observed_transport']
    require(binding == {'path': TRANSPORT, 'sha256': OLD_TRANSPORT}, 'unknown policy parent')
    binding['sha256'] = NEW_TRANSPORT
    require(new == expected, 'policy change exceeds transport binding')


def require_output_boundary(root, output):
    root, output = Path(root).resolve(), Path(output).resolve()
    require(root != output and root not in output.parents and output not in root.parents,
            'candidate overlaps authority')


def inventory(root):
    result = {}
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(), 'symlink in candidate')
        if path.is_dir():
            continue
        result[path.relative_to(root).as_posix()] = digest(read_bytes(path))
    return result


def selected_sources(root):
    inputs = {p: read_bytes(root / p, allow_shared_inode=True) for p in PINS}
    require(all(digest(inputs[p]) == pin for p, pin in PINS.items()), 'unreviewed parent/source pair')
    namespace = runpy.run_path(str(root / RUNNER))
    legacy = {}
    for path, expected in namespace['RUNTIME_SOURCE_CLOSURE']:
        relative = path.relative_to(root).as_posix()
        payload = read_bytes(path, allow_shared_inode=True)
        actual = digest(payload)
        require(actual == (NEW_TRANSPORT if relative == TRANSPORT else expected),
                'unrelated runtime closure drift: ' + relative)
        if relative == TRANSPORT:
            require(expected == OLD_TRANSPORT, 'unexpected transport parent')
        require(relative not in legacy, 'duplicate runtime source')
        legacy[relative] = expected
        inputs[relative] = payload
    inputs[POLICY_SCHEMA] = read_bytes(root / POLICY_SCHEMA, allow_shared_inode=True)
    require(TRANSPORT in legacy, 'transport not declared in legacy closure')
    policy_builder = runpy.run_path(str(root / POLICY_BUILDER))['build_policy']
    policy = policy_builder(repo_root=root)
    require_policy_delta(decode(inputs[POLICY]), policy)
    overlays = {RUNNER: render_runner(inputs[RUNNER]), POLICY: encoded(policy)}
    return inputs, legacy, overlays


def selection_document(inputs, legacy, overlays):
    hashes = {p: digest(b) for p, b in inputs.items()}
    return {
        'schema_version': 'rtlflowbench.controller_binding_successor.v1',
        'status': 'unselected_runtime_candidate_not_authorized',
        'builder_sha256': digest(read_bytes(Path(__file__))),
        'parent_input_sha256': hashes, 'parent_runtime_closure': legacy,
        'selected_source_sha256': {p: digest(b) for p, b in {**inputs, **overlays}.items()},
        'changed_paths': sorted(overlays),
        'transition': {'from_transport_sha256': OLD_TRANSPORT, 'to_transport_sha256': NEW_TRANSPORT,
                       'semantics': 'single-flight provider forwarding and usage settlement'},
        'policy_semantics_changed': False, 'runtime_execution_semantics_changed': True,
        'wire_schema_changed': False, 'budget_authorized': False,
        'benchmark_ready': False, 'adapter_ready': False, 'release_ready': False,
        'dependency_closure': 'declared_not_transitively_certified',
        'new_model_calls': 0, 'new_eda_executions': 0,
        'constraints': ['Uniform new runtime binding for affected compared systems.',
                        'No old receipt/signature reuse or checkpoint resume under changed source.',
                        'No provider/EDA launch or release is authorized by construction.'],
    }


def build(root, output):
    root, output = root.absolute(), output.absolute()
    require_output_boundary(root, output)
    require(not output.exists() and not output.is_symlink(), 'candidate output exists')
    inputs, legacy, overlays = selected_sources(root)
    selection = selection_document(inputs, legacy, overlays)
    output.mkdir(mode=0o700)
    source = output / 'source'
    for relative, payload in {**inputs, **overlays}.items():
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(payload)
    require(all(digest(read_bytes(root / p, allow_shared_inode=True)) == h
                for p, h in selection['parent_input_sha256'].items()), 'build-time source drift')
    require(inventory(source) == selection['selected_source_sha256'], 'copy-time drift')
    with (output / 'selection.json').open('xb') as stream:
        stream.write(encoded(selection))
    return selection


def verify(root, output, expected):
    root, output = root.absolute(), output.absolute()
    require_output_boundary(root, output)
    payload = read_bytes(output / 'selection.json')
    require(digest(payload) == expected, 'selection digest differs from trusted pin')
    selection = decode(payload)
    require(selection['schema_version'] == 'rtlflowbench.controller_binding_successor.v1'
            and selection['status'] == 'unselected_runtime_candidate_not_authorized', 'unknown candidate')
    require(selection['builder_sha256'] == digest(read_bytes(Path(__file__))), 'materializer drift')
    for field in ('budget_authorized', 'benchmark_ready', 'adapter_ready', 'release_ready'):
        require(selection[field] is False, 'candidate overclaims authority/readiness')
    inputs, legacy, overlays = selected_sources(root)
    require(selection == selection_document(inputs, legacy, overlays), 'selection metadata or policy drift')
    expected_files = {p: digest(b) for p, b in {**inputs, **overlays}.items()}
    require(selection['parent_input_sha256'] == {p: digest(b) for p, b in inputs.items()}, 'parent inventory drift')
    require(selection['parent_runtime_closure'] == legacy, 'parent closure drift')
    require(selection['changed_paths'] == sorted(overlays), 'overlay scope drift')
    require(selection['selected_source_sha256'] == expected_files, 'selection source inventory drift')
    require(inventory(output / 'source') == expected_files, 'candidate file drift or extra file')
    expected_all = {'selection.json': expected, **{'source/' + p: h for p, h in expected_files.items()}}
    require(inventory(output) == expected_all, 'unexpected candidate file')
    return {'status': 'binding_verified_not_launch_authorized', 'selection_sha256': expected,
            'source_count': len(expected_files), 'changed_paths': sorted(overlays),
            'benchmark_ready': False, 'adapter_ready': False, 'release_ready': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['build', 'verify'])
    parser.add_argument('--repo-root', type=Path, required=True)
    parser.add_argument('--candidate-root', type=Path, required=True)
    parser.add_argument('--expected-selection-sha256')
    args = parser.parse_args()
    if args.mode == 'build':
        value = build(args.repo_root, args.candidate_root)
        print(json.dumps({'status': value['status'], 'changed_paths': value['changed_paths']}))
    else:
        require(args.expected_selection_sha256 is not None, 'external selection pin required')
        print(json.dumps(verify(args.repo_root, args.candidate_root, args.expected_selection_sha256)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
