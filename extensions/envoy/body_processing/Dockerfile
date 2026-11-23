# Build the module on Linux with build.sh first.
FROM envoyproxy/envoy:v1.40.2@sha256:8de97e654644827d62afdbf7e1d3dc9fee01a8690d410dd1c63a30dc6b6cecbb AS runtime
COPY target/release/libenvoy_agentio_body_processing.so /usr/local/lib/
