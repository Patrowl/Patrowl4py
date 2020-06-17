from patrowl4py.api import PatrowlManagerApi
import random
import string

api = PatrowlManagerApi(
    url='http://my.patrowl.io:8000',
    auth_token='5a13cd99aaa7a4aeafe26ad6296519758b8e32a0'
)

# Assets
print(api.get_teams())
print(api.get_team_by_id(1))

rand_name = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(16))
new_team = api.add_team(name=rand_name, is_active=False)
print(new_team)
print(api.delete_team(new_team['id']))
