#!/usr/bin/env python3

import json
import random
import datetime
from datetime import timedelta
import requests
import time
import uuid

# sample log: Oct 17 18:06:39 aks-sysnp-15701251-vmss000003 kernel: [3038376.504365] audit: type=1400 audit(1760724399.687:688206): apparmor="DENIED" operation="ptrace" profile="cri-containerd.apparmor.d" pid=3483198 comm="otelcol-contrib" requested_mask="read" denied_mask="read" peer="unconfined"

class LogDataGenerator:
    def __init__(self):
        # OpenTelemetry log data pools
        self.cluster_names = ['xyz-cluster1-ci-prod-us-east-1', 'abc-cluster2-dev-us-west-2', 'def-cluster3-staging-eu-west-1']
        self.regions = ['us-east-1', 'us-west-2', 'eu-west-1']
        self.envs = ['prod', 'dev', 'staging']
        self.log_files = ['/var/log/xyz/abc.log', '/var/log/containers/app.log', '/var/log/system/kernel.log']
        self.product_ids = ['pr123456', 'pr789012', 'pr345678']
        self.app_ids = ['ap123456', 'ap789012', 'ap345678']
        self.criticality_codes = ['5', '3', '1']
        self.k8s_criticality_codes = ['99', '95', '90']
        self.log_messages = [
            'Error finding unassigned IPs for ENI xyz',
            'Failed to allocate pod network interface',
            'Container runtime connection timeout',
            'Kubernetes API server unreachable',
            'Node memory pressure detected'
        ]
        self.callers = ['xyz/abc.go:702', 'network/eni.go:156', 'runtime/docker.go:289', 'api/client.go:445']
        self.log_levels = ['error', 'warn', 'info', 'debug']

    def generate_otel_log(self, timestamp):
        """Generate OpenTelemetry log entry matching the new format"""
        # Generate timestamps
        base_ts = timestamp.isoformat() + "Z"
        time_ts = (timestamp - timedelta(seconds=random.randint(1, 5))).isoformat() + "Z"
        observed_ts = base_ts

        # Select random values
        cluster_name = random.choice(self.cluster_names)
        region = random.choice(self.regions)
        env = random.choice(self.envs)
        product_id = random.choice(self.product_ids)
        app_id = random.choice(self.app_ids)
        log_file = random.choice(self.log_files)
        msg = random.choice(self.log_messages)
        caller = random.choice(self.callers)
        level = random.choice(self.log_levels)

        # Generate body as JSON string (like the example)
        body_content = {
            "msg": msg,
            "caller": caller,
            "level": level,
            "ts": time_ts
        }

        return {
            "traceId": "",
            "instrumentationScope": {
                "droppedAttributesCount": 0
            },
            "resource": {
                "droppedAttributesCount": 0,
                "attributes": {
                    "log_type": "EKS_node",
                    "k8s_label.productid": product_id,
                    "k8s_label.sourcetype": "unknown",
                    "productid": product_id,
                    "k8s.platform": "EKS",
                    "k8s_label.criticality_code": random.choice(self.k8s_criticality_codes),
                    "k8s.cluster.business.unit": "bu",
                    "criticality_code": random.choice(self.criticality_codes),
                    "sourcetype": "unknown",
                    "log_tier": "standard",
                    "applicationid": app_id,
                    "obs_namespace": "defaultv1"
                },
                "schemaUrl": ""
            },
            "flags": 0,
            "severityNumber": 0,
            "schemaUrl": "",
            "spanId": "",
            "severityText": "",
            "attributes": {
                "cluster.name": cluster_name,
                "cluster.region": region,
                "log.file.path": log_file,
                "cluster.env": env,
                "obs_body_length": len(json.dumps(body_content))
            },
            "time": time_ts,
            "droppedAttributesCount": 0,
            "observedTimestamp": observed_ts,
            "@timestamp": base_ts,
            "body": json.dumps(body_content)
        }

    def generate_log_entry(self, doc_id, timestamp):
        """Generate a log entry with OpenTelemetry format"""
        log_data = self.generate_otel_log(timestamp)

        return {
            "index": {"_id": str(doc_id)}
        }, log_data

def generate_bulk_data(num_docs, start_time):
    """Generate bulk indexing data"""
    generator = LogDataGenerator()

    for i in range(num_docs):
        # Generate timestamps spread over time
        timestamp = start_time + timedelta(seconds=random.randint(0, 86400 * 180))  # 6 month span

        index_meta, doc = generator.generate_log_entry(i + 1, timestamp)

        yield json.dumps(index_meta)
        yield json.dumps(doc)

def upload_to_opensearch(endpoint, index_name, username, password, batch_size=10000, total_docs=1000000):
    """Upload data to OpenSearch using bulk API"""

    start_time = datetime.datetime(2024, 10, 17, 18, 0, 0)

    # Create session for connection pooling
    session = requests.Session()
    if username and password:
        session.auth = (username, password)

    # Create index if it doesn't exist
    headers = {'Content-Type': 'application/json'}

    # Index mapping - exact match to specification in index_data_info.md
    mapping = {
        "mappings": {
            "dynamic_templates": [
                {
                    "resource_attributes": {
                        "path_match": "resource.attributes.*",
                        "mapping": {
                            "type": "keyword"
                        },
                        "match_mapping_type": "string"
                    }
                },
                {
                    "attributes": {
                        "path_match": "attributes.*",
                        "mapping": {
                            "type": "keyword"
                        },
                        "match_mapping_type": "string"
                    }
                },
                {
                    "log_fields": {
                        "path_match": "log.*",
                        "mapping": {
                            "norms": False,
                            "type": "text",
                            "fields": {
                                "keyword": {
                                    "ignore_above": 256,
                                    "type": "keyword"
                                }
                            }
                        },
                        "match_mapping_type": "string"
                    }
                }
            ],
            "properties": {
                "traceId": {
                    "type": "keyword"
                },
                "flags": {
                    "type": "byte"
                },
                "severityNumber": {
                    "type": "integer"
                },
                "body": {
                    "norms": False,
                    "type": "text"
                },
                "serviceName": {
                    "type": "keyword"
                },
                "schemaUrl": {
                    "type": "keyword"
                },
                "spanId": {
                    "type": "keyword"
                },
                "@timestamp": {
                    "type": "date"
                },
                "severityText": {
                    "type": "keyword"
                },
                "@version": {
                    "type": "keyword"
                },
                "attributes": {
                    "type": "object",
                    "properties": {
                        "time": {
                            "enabled": False,
                            "type": "object"
                        }
                    },
                    "dynamic": "false"
                },
                "resource": {
                    "type": "object",
                    "properties": {
                        "droppedAttributesCount": {"type": "long"},
                        "schemaUrl": {"type": "keyword"},
                        "attributes": {
                            "type": "object",
                            "dynamic": "false"
                        }
                    }
                },
                "instrumentationScope": {
                    "type": "object",
                    "properties": {
                        "droppedAttributesCount": {"type": "long"}
                    }
                },
                "droppedAttributesCount": {"type": "long"},
                "time": {
                    "type": "date"
                },
                "observedTimestamp": {
                    "type": "date"
                }
            }
        }
    }

    # Use composable index template to enforce exact mapping
    template_name = f"{index_name}-template"
    template = {
        "index_patterns": [index_name],
        "priority": 100,
        "template": {
            "mappings": mapping["mappings"]
        }
    }

    try:
        # Delete any existing template
        try:
            session.delete(f"{endpoint}/_index_template/{template_name}")
        except:
            pass

        # Create index template with high priority
        session.put(f"{endpoint}/_index_template/{template_name}",
                   json=template, headers=headers)
        print(f"Created index template: {template_name}")

        # Delete existing index if it exists
        try:
            session.delete(f"{endpoint}/{index_name}")
            print(f"Deleted existing index: {index_name}")
        except:
            pass

        # Create index (will inherit exact mapping from template)
        session.put(f"{endpoint}/{index_name}",
                   json={"settings": {"index.mapping.total_fields.limit": 2000}},
                   headers=headers)
        print(f"Created index: {index_name} with template mapping")
    except Exception as e:
        print(f"Index/template creation note: {e}")

    # Bulk upload in batches
    doc_count = 0
    batch_data = []

    for line in generate_bulk_data(total_docs, start_time):
        batch_data.append(line)

        if len(batch_data) >= batch_size * 2:  # *2 because each doc has 2 lines
            # Upload batch
            bulk_body = '\n'.join(batch_data) + '\n'

            response = session.post(
                f"{endpoint}/{index_name}/_bulk",
                data=bulk_body,
                headers={'Content-Type': 'application/x-ndjson'}
            )

            if response.status_code == 200:
                doc_count += batch_size
                print(f"Uploaded {doc_count:,} documents ({doc_count/total_docs*100:.1f}% complete)")
            else:
                print(f"Error uploading batch: {response.status_code} - {response.text}")

            batch_data = []
            time.sleep(0.1)  # Rate limiting

    # Upload remaining data
    if batch_data:
        bulk_body = '\n'.join(batch_data) + '\n'
        session.post(
            f"{endpoint}/{index_name}/_bulk",
            data=bulk_body,
            headers={'Content-Type': 'application/x-ndjson'}
        )
        print("Uploaded final batch")

if __name__ == "__main__":
    # Configuration
    OPENSEARCH_ENDPOINT = "https://your-opensearch-cluster.region.es.amazonaws.com"
    INDEX_NAME = "large-sample-logs"
    USERNAME = "your_username"  # or None for no auth
    PASSWORD = "your_password"  # or None for no auth

    # Generate N documents
    TOTAL_DOCS = 70_000_000
    BATCH_SIZE = 20000

    print(f"Starting bulk upload of {TOTAL_DOCS:,} documents to {INDEX_NAME}")
    upload_to_opensearch(
        OPENSEARCH_ENDPOINT,
        INDEX_NAME,
        USERNAME,
        PASSWORD,
        BATCH_SIZE,
        TOTAL_DOCS
    )
    print("Bulk upload complete!")
