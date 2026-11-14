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
import http.client
import http.server
import importlib.util
import json
from pathlib import Path
import threading
import unittest
from unittest.mock import patch


class ClientTest(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('client', Path(__file__).with_name('client.py'))
        self.client = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.client)

    def test_health_does_not_serialize_load_results(self):
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), self.client.API)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        conn = http.client.HTTPConnection(*server.server_address, timeout=2)
        try:
            with patch.object(self.client, 'status', side_effect=AssertionError('expensive snapshot')):
                conn.request('GET', '/health')
                response = conn.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(json.loads(response.read()), {'healthy': True})
            self.client.CONFIG['rate'] = 12
            conn.request('GET', '/status')
            self.assertEqual(json.loads(conn.getresponse().read())['config']['rate'], 12)
        finally:
            conn.close()
            server.shutdown()
            thread.join()
            server.server_close()

    def test_policy_violation_and_server_failure_count_separately(self):
        self.client.record('hot', 2, 1, self.client.PolicyViolation('unexpected allow'), 200)
        self.client.record('hot', 3, 1, AssertionError('upstream unavailable'), 503)
        stats = self.client.status()['groups']['hot']
        self.assertEqual(stats['requests'], 2)
        self.assertEqual(stats['errors'], 2)
        self.assertEqual(stats['error_types'], {'PolicyViolation': 1, 'AssertionError': 1})
        self.assertEqual(sum(stats['histogram']), 2)
        self.assertEqual(stats['statuses'], {'200': 1, '503': 1})


if __name__ == '__main__':
    unittest.main()
