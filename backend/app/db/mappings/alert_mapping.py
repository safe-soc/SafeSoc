"""
SafeSOC — OpenSearch Index Mapping
Defines field types for the safesoc-alerts index.
Applied when a new monthly index is created.
"""

ALERT_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "5s",
    },
    "mappings": {
        "properties": {
            # ── Identity ──────────────────────
            "alert_id": {"type": "keyword"},
            "tenant_id": {"type": "keyword"},

            # ── Source ────────────────────────
            "source": {"type": "keyword"},
            "log_type": {"type": "keyword"},

            # ── Timing ────────────────────────
            "timestamp": {"type": "date"},
            "ingested_at": {"type": "date"},

            # ── Host Context ──────────────────
            "host_id": {"type": "keyword"},
            "host_ip": {"type": "ip"},
            "host_os": {"type": "keyword"},

            # ── Event Context ─────────────────
            "user": {"type": "keyword"},
            "action": {"type": "keyword"},
            "description": {"type": "text"},
            "severity": {"type": "keyword"},

            # ── Detection Context ─────────────
            "rule_id": {"type": "keyword"},
            "mitre_technique": {"type": "keyword"},
            "mitre_tactic": {"type": "keyword"},

            # ── Network Context ───────────────
            "source_ip": {"type": "ip"},
            "source_port": {"type": "integer"},
            "destination_ip": {"type": "ip"},
            "destination_port": {"type": "integer"},
            "protocol": {"type": "keyword"},

            # ── File Context ──────────────────
            "file_path": {"type": "keyword"},
            "file_hash": {"type": "keyword"},
            "file_size": {"type": "long"},

            # ── Process Context ───────────────
            "process_name": {"type": "keyword"},
            "process_id": {"type": "integer"},
            "parent_process": {"type": "keyword"},
            "command_line": {"type": "text"},

            # ── Raw Data ──────────────────────
            "raw_log": {"type": "text", "index": False},

            # ── Enrichment ────────────────────
            "ti_enriched": {"type": "boolean"},
            "ti_result": {
                "properties": {
                    "source_ip": {"type": "ip"},
                    "file_hash": {"type": "keyword"},
                    "domain": {"type": "keyword"},
                    "vt_malicious": {"type": "integer"},
                    "vt_total": {"type": "integer"},
                    "abuse_confidence": {"type": "integer"},
                    "abuse_total_reports": {"type": "integer"},
                    "is_malicious": {"type": "boolean"},
                    "tags": {"type": "keyword"},
                }
            },
            "risk_score": {"type": "integer"},
            "anomaly_score": {"type": "float"},
        }
    },
}