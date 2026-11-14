# Copyright 2026 The Kruise Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import gzip
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class SummaryTest(unittest.TestCase):
    def test_cumulative_snapshots_and_retired_identity_are_not_double_counted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def data(n, errors=0):
                return {'bounds_ms': [1, 10], 'groups': {'hot': {
                    'requests': n, 'errors': errors, 'histogram': [n, 0, 0],
                    'queue_histogram': [n, 0, 0], 'error_types': {'PolicyViolation': errors},
                    'statuses': {'200': n}}}, 'samples': []}
            def write(name, value):
                with gzip.open(root / name, 'wt') as file:
                    json.dump(value, file)
            for second, n in [(100, 10), (160, 15)]:
                write('probes-%d.json.gz' % second, {'time': second, 'phase': 'baseline', 'items': [
                    {'uid': 'old', 'name': 'sandbox-a', 'data': data(n)}]})
            write('retired-old.json.gz', {'pod': {'uid': 'old', 'name': 'sandbox-a', 'group': 'a'}, 'final': data(20, 1)})
            write('probes-220.json.gz', {'time': 220, 'phase': 'replacement', 'items': [
                {'uid': 'new', 'name': 'sandbox-a', 'data': data(5)}]})
            subprocess.run([sys.executable, str(Path(__file__).with_name('summarize.py')),
                            '--evidence', str(root), '--output', str(root / 'output')],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            with gzip.open(root / 'output/summary.json.gz', 'rt') as file:
                result = json.load(file)
            self.assertEqual(result['identities_seen'], 2)
            self.assertEqual(result['groups']['hot']['requests'], 25)
            self.assertEqual(result['policy_violations'], 1)
            self.assertEqual(result['phases']['baseline']['delta']['hot:requests'], 15)


if __name__ == '__main__':
    unittest.main()
