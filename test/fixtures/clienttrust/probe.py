# Copyright 2026 The Kruise Authors
# SPDX-License-Identifier: Apache-2.0
"""Executed in each client container, with certificate verification enabled."""
import json
import os
import socket
import ssl
import subprocess
import sys

import httpx
import requests

host = sys.argv[1] if len(sys.argv) > 1 else "example.com"
url = "https://" + host
results = {"host": host, "env": {key: os.environ.get(key) for key in (
    "AGENTIO_TRUST_BUNDLE", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "CURL_CA_BUNDLE")}}

for library, call in (
    ("requests", lambda: requests.get(url, timeout=20)),
    ("httpx", lambda: httpx.get(url, timeout=20)),
):
    try:
        response = call()
        results[library] = {"status": response.status_code}
    except Exception as exc:
        results[library] = {"error": str(exc), "type": type(exc).__name__}

# A custom client explicitly loads the shared bundle, with automatic environment
# trust disabled. This also runs when no language-specific variables are injected.
try:
    custom_context = ssl.create_default_context(cafile=os.environ["AGENTIO_TRUST_BUNDLE"])
    response = httpx.get(url, verify=custom_context, trust_env=False, timeout=20)
    results["custom_client"] = {"status": response.status_code}
except Exception as exc:
    results["custom_client"] = {"error": str(exc), "type": type(exc).__name__}

try:
    context = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=20) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            certificate = tls.getpeercert()
            results["tls"] = {"issuer": certificate["issuer"],
                              "san": certificate["subjectAltName"], "version": tls.version()}
except Exception as exc:
    results["tls"] = {"error": str(exc)}

node_script = """
const https = require('https');
const request = https.get(process.argv[1], response => {
  console.log(JSON.stringify({status:response.statusCode,
    issuer:response.socket.getPeerCertificate().issuer,
    authorized:response.socket.authorized}));
  response.resume();
});
request.setTimeout(20000, () => request.destroy(new Error('timeout')));
request.on('error', error => {console.log(JSON.stringify({error:error.message,code:error.code}));process.exitCode=1;});
"""
for name, command in (
    ("node", ["node", "-e", node_script, url]),
    ("curl", ["curl", "--silent", "--show-error", "--max-time", "20",
              "-o", "/dev/null", "-w", "%{http_code}", url]),
):
    process = subprocess.run(command, text=True, capture_output=True, timeout=30)
    results[name] = {"exit": process.returncode, "stdout": process.stdout.strip(),
                     "stderr": process.stderr.strip()}
print(json.dumps(results, indent=2))
