from patrowl4py.api import PatrowlManagerApi

api = PatrowlManagerApi(
    url='http://my.patrowl.io:8000',
    auth_token='5a13cd99aaa7a4aeafe26ad6296519758b8e32a0'
)

# Alerting rules
print(api.get_alerting_rules())
print(api.get_alerting_rule(3))
# print(api.delete_alerting_rule(1))
print(api.duplicate_alerting_rule(3))