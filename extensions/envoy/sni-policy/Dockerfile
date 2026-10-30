# The module is built on Linux by build.sh before assembling this example image.
# This is an upstream Envoy integration image, not Agentio's patched gateway image.
FROM envoyproxy/envoy:v1.40.2@sha256:8de97e654644827d62afdbf7e1d3dc9fee01a8690d410dd1c63a30dc6b6cecbb
COPY target/release/libenvoy_agentio_sni_policy.so /usr/local/lib/
ENV ENVOY_DYNAMIC_MODULES_SEARCH_PATH=/usr/local/lib
