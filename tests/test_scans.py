from patrowl4py.api import PatrowlManagerApi


api = PatrowlManagerApi(
    url='http://my.patrowl.io:8000',
    auth_token='5a13cd99aaa7a4aeafe26ad6296519758b8e32a0'
)

# Scan definitions
print(api.get_scan_definitions())
print(api.get_scan_definition_by_id(1))

# Scans
print(api.get_scan_by_id(1))
print(api.get_scans(limit=10))
print(api.get_scans(limit=10, status="finished"))
