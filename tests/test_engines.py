from patrowl4py.api import PatrowlManagerApi

api = PatrowlManagerApi(
    url='http://my.patrowl.io:8000',
    auth_token='5a13cd99aaa7a4aeafe26ad6296519758b8e32a0'
)

# Engine instances
print(api.get_engines())
print(api.get_engine_by_id(1))
print(api.get_engine_instances())
print(api.get_engine_instance_by_id(1))

# Engine policies
print(api.get_engine_policies())
print(api.get_engine_policy(1))