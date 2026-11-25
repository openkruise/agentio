\set ON_ERROR_STOP on
CREATE TABLE sandbox_policy (uid text PRIMARY KEY, revision bigint NOT NULL, body bytea NOT NULL);
INSERT INTO sandbox_policy
SELECT 'sandbox:' || lpad(i::text, 6, '0'), 1,
  convert_to(json_build_object('rules', json_build_array(json_build_object('name', 'egress', 'match',
    json_build_array(json_build_object('domains', array_prepend('tenant-' || i || '.example.net', common.domains))))))::text, 'UTF8')
FROM generate_series(0, 299999) AS i
CROSS JOIN (SELECT array_agg('service-' || j || '.sandbox.example.net' ORDER BY j) AS domains
            FROM generate_series(1, 20) AS j) AS common;
ANALYZE sandbox_policy;
SELECT count(*) AS rows, min(octet_length(body)), max(octet_length(body)),
       pg_database_size(current_database()) AS database_bytes FROM sandbox_policy;
SELECT version();
EXPLAIN ANALYZE SELECT revision,body FROM sandbox_policy WHERE uid='sandbox:004321';
