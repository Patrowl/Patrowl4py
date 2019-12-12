from patrowl4py.api import PatrowlManagerApi
import random
import string

api = PatrowlManagerApi(
    url='http://my.patrowl.io:8000',
    auth_token='5a13cd99aaa7a4aeafe26ad6296519758b8e32a0'
)

# Assets
print(api.get_assets())
print(api.get_assets_stats())
print(api.get_asset_by_id(1))
print(api.ack_asset_by_id(1))
print(api.get_asset_findings_by_id(1))

rand_fqdn = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(16))
new_asset = api.add_asset(
    value=rand_fqdn, name="Test FQDN", datatype="fqdn",
    description="n/a", criticity="low", tags=["patrowl", "demo"]
)
print(new_asset)
print(api.delete_asset(new_asset['id']))
