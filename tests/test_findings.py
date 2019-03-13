from patrowl4py.api import PatrowlManagerApi


api = PatrowlManagerApi(
    url='http://my.patrowl.io:8000',
    auth_token='5a13cd99aaa7a4aeafe26ad6296519758b8e32a0'
)

# Findings
print(api.get_findings())
print(api.get_findings(status="new"))
print(api.get_findings(title="Nmap", severity="info"))
print(api.get_findings(severity="high", limit=1))
print(api.get_finding(1))
