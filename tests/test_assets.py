from patrowl4py.api import PatrowlManagerApi


api = PatrowlManagerApi(
    url='http://my.patrowl.io:8000',
    auth_token='5a13cd99aaa7a4aeafe26ad6296519758b8e32a0'
)

# Assets
print(api.get_assets())
print(api.get_assets_stats())
print(api.get_asset_by_id(1))
print(api.get_asset_findings_by_id(1))

# print(api.add_asset(
#     value="1.1.1.1", name="Test IP address", datatype="ip",
#     description="n/a", criticity="low", tags=["patrowl", "demo"]
# ))
print(api.delete_asset(1288))
