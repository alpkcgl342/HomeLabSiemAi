# Sigma rules for Security Onion 3.x

The rules in `../zeek/` use the portable `product: zeek` logsource and raw Zeek field names.
Security Onion's Sigma pipeline (`sigma_so_pipeline.yaml`) has **no `product: zeek` mapping**, so
those rules would load but never match there.

The rules in this folder are written for Security Onion and were verified against real data
(Security Onion 3.4 EVAL, Suricata as metadata engine, `event.dataset: suricata.dns`):

* `logsource: category: network / service: dns` → the pipeline adds `tags:"dns"` and `event.category:"network"`
* `query` → mapped to `dns.query.name` by the pipeline
* `dns.query.type: request` → only the query, not the matching response (avoids duplicate alerts)
* `dns.query.type_name` → passed through unchanged (record type: A, AAAA, TXT ...)

Add them in SOC → Detections → **+** → Language *Sigma*, then **enable** the detection
(new custom detections start disabled). Use *CONVERT* → *TEST IN KIBANA* to check matches.
