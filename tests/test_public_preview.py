import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import rtlflowbench as cli


class PreviewTests(unittest.TestCase):
    def test_integrity_and_twelve_schemas(self):
        report = cli.verify()
        self.assertEqual(report['tasks'], 12)
        self.assertFalse(report['benchmark_ready'])

    def test_candidate_not_admitted(self):
        lock = json.loads((ROOT / 'candidate/candidate-lock.json').read_text())
        for row in lock['tasks']:
            self.assertFalse(row['benchmark_ready'])
            self.assertGreater(len(row['gaps']), 0)

    def test_no_private_tree_or_reference_fifo(self):
        paths = list((ROOT / 'candidate/tasks').rglob('*'))
        self.assertFalse(any('private' in p.relative_to(ROOT).parts for p in paths))
        self.assertFalse(any(p.name == 'fifo_v3.sv' for p in paths))

    def test_export_identical_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / 'packet'
            task = 'G01-common-fifo-spec'
            cli.export(task, out)
            self.assertEqual(cli.inventory(out), cli.inventory(ROOT / 'candidate/tasks' / task / 'public'))
            with self.assertRaises(ValueError):
                cli.export(task, out)

    def test_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                cli.export('../..', Path(temp) / 'out')

    def test_describe_all_tasks_preserves_contracts(self):
        for path in sorted((ROOT / 'candidate/tasks').glob('*/public/external_task.json')):
            task = json.loads(path.read_text())
            report = cli.describe(task['task_id'])
            for key in ('submission_contract', 'budget', 'scoring_contract', 'evaluation_contract'):
                self.assertEqual(report[key], task[key])
            self.assertFalse(report['benchmark_ready'])
            self.assertFalse(report['repository_projection_included'])
            self.assertIn('spec/design_spec.md', report['public_files'])

    def test_describe_rejects_unknown_or_traversal(self):
        for task in ('../..', 'G99-unknown', 'G01'):
            with self.assertRaises(ValueError):
                cli.describe(task)

    def test_describe_is_read_only(self):
        before = cli.inventory(ROOT)
        cli.describe('G01-common-fifo-spec')
        self.assertEqual(before, cli.inventory(ROOT))

    def test_tamper_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'repo'
            shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns('.git', '__pycache__'))
            (root / 'README.md').write_text('changed')
            with self.assertRaises(ValueError):
                cli.verify(root)

    def test_added_file_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'repo'
            shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns('.git', '__pycache__'))
            (root / 'unlisted.txt').write_text('extra')
            with self.assertRaises(ValueError):
                cli.verify(root)

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'link').symlink_to(ROOT / 'README.md')
            with self.assertRaises(ValueError):
                cli.inventory(root)

    def test_evaluate_fails_closed(self):
        result = subprocess.run([sys.executable, str(ROOT / 'rtlflowbench.py'), 'evaluate'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)['status'], 'BLOCK')
        self.assertIsNone(json.loads(result.stdout)['score'])

    def test_package_scope_and_real_artifact_hash(self):
        spec = importlib.util.spec_from_file_location('packager', ROOT / 'tools/package_submission.py')
        package = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(package)
        task = json.loads((ROOT / 'candidate/tasks/G01-common-fifo-spec/public/external_task.json').read_text())
        # Synthetic unit-test metadata, not an experiment or passing RTL claim.
        metadata = {'schema_version': 'rtlflowbench.submission_metadata.v1',
                    'submission_id': 'unit-fixture', 'workflow': {
                        'name': 'unit-test', 'version': 'fixture', 'adapter_name': 'test',
                        'adapter_version': 'fixture', 'config_sha256': '0' * 64,
                        'model': {'provider': None, 'name': None}},
                    'attempt': {'attempt_id': 'fixture', 'attempt_index': 1, 'repeat_group_id': 'test', 'seed': 1},
                    'resource_usage': {'wall_time_seconds': 0, 'input_tokens': 0, 'output_tokens': 0,
                                       'llm_calls': 0, 'eda_calls': dict.fromkeys(['compile_or_lint', 'simulation', 'formal', 'synthesis'], 0),
                                       'human_interventions': 0, 'missing_measurements': []},
                    'network_access_observed': False, 'claims': ['unit-test only; not RTL PASS']}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'rtl').mkdir()
            (root / 'rtl/golden12_fifo.sv').write_text('// intentionally not a solution\n')
            receipt = package.package_submission(task=task, metadata=metadata, bundle_root=root)
            self.assertEqual(receipt['artifact']['files'][0]['sha256'], cli.inventory(root)['rtl/golden12_fifo.sv'])
            (root / 'outside.txt').write_text('outside scope')
            with self.assertRaises(ValueError):
                package.package_submission(task=task, metadata=metadata, bundle_root=root)


if __name__ == '__main__':
    unittest.main()
