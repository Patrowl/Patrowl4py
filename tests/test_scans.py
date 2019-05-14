from patrowl4py.api import PatrowlManagerApi
import time


api = PatrowlManagerApi(
    url='http://my.patrowl.io:8000',
    auth_token='5a13cd99aaa7a4aeafe26ad6296519758b8e32a0'
)

# Scan definitions
print(api.add_scan_definition(
    engine_policy=1,
    engine_id=1,
    title="Patrowl4py single test scan ({})".format(time.time()),
    description="Patrowl4py test scan",
    scan_type="single",
    every=None,
    period=None,
    scheduled_at=None,
    start_scan="now",
    assets=[1, 1284],
    assetgroups=None
    # assetgroups=[7]
))
print(api.get_scan_definitions())
print(api.get_scan_definition_by_id(1))

# Scans
print(api.get_scan_by_id(1))
print(api.get_scans(limit=10))
print(api.get_scans(limit=10, status="finished"))
