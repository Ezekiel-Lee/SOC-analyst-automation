# Splunk SPL examples

These are starting points, not guaranteed drop-in searches. `get_notable_index` is a Splunk ES macro commonly used in ES contexts; verify it exists in your deployment. Index names, fields, status values, and permissions vary. Configure a saved search that returns the normalised schema expected by `soc_l1.ingest`.

For ES integration:
1. Create a saved search in Splunk ES with a service-owned name, e.g. `SOC_L1_Notable_Export`.
2. Confirm its result fields and access permissions.
3. Test the saved search in Splunk Search.
4. Grant a dedicated service account only the minimum permissions required to run it.
5. Configure the REST endpoint in `.env`.
6. Test with a small, sanitised dataset before connecting operational data.
