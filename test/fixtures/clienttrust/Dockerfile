# Copyright 2026 The Kruise Authors
# SPDX-License-Identifier: Apache-2.0
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
RUN apt-get update && apt-get install -y --no-install-recommends nodejs curl openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir requests==2.32.5 httpx==0.28.1
COPY test/fixtures/clienttrust/probe.py /opt/clienttrust/probe.py
CMD ["sleep", "infinity"]
