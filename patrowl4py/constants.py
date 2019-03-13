# Assets
ASSET_TYPES = (
    ('ip', 'ip'),
    ('ip-range', 'ip-range'),       # 192.168.1.0-256
    ('ip-subnet', 'ip-subnet'),     # 192.168.1.0/24
    ('fqdn', 'fqdn'),
    ('domain', 'domain'),
    ('url', 'url'),
    ('keyword', 'keyword'),
    ('person', 'person'),
    ('organisation', 'organisation'),
    ('path', 'path'),
    ('application', 'application'),
)

ASSET_CRITICITIES = (
    ('low', 'low'),
    ('medium', 'medium'),
    ('high', 'high'),
)

# Findings
FINDING_SEVERITIES = (
    ('info', 'info'),
    ('low', 'low'),
    ('medium', 'medium'),
    ('high', 'high'),
    ('critical', 'critical')
)

FINDING_STATUS = (
    ('new', 'New'),
    ('ack', 'Acknowledged'),
    ('mitigated', 'Mitigated'),
    ('confirmed', 'Confirmed'),
    ('patched', 'Patched'),
    ('closed', 'Closed'),
    ('false-positive', 'False-Positive')
)

# Scans
SCAN_STATUS = ['created', 'started', 'finished', 'error', 'trashed']
