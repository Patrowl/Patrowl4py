from patrowl4py.api import PatrowlManagerApi
import random
import string

api = PatrowlManagerApi(
    url='http://my.patrowl.io:8000',
    auth_token='5a13cd99aaa7a4aeafe26ad6296519758b8e32a0'
)

# Assets groups
print(api.get_assetgroups())

rand = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(8))
new_assetgroup = api.add_assetgroup(
    name="Test AssetGroup via Patrowl4py ({})".format(rand), description="n/a", criticity="low",
    assets=[1, 1314], tags=["patrowl", "demo"]
)
print(new_assetgroup)
print(api.delete_assetgroup(new_assetgroup['id']))
