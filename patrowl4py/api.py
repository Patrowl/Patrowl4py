#!/usr/bin/env python
"""
Patrowl4py api
"""

# Third party library imports
import requests
from slugify import slugify

# Own library imports
from patrowl4py.exceptions import PatrowlException
from patrowl4py.constants import *


class PatrowlManagerApi:
    """Python API for PatrowlManager."""

    def __init__(self, url, auth_token, proxies={}, ssl_verify=False, timeout=10):
        """
        Initialize a PatrowlManagerAPI object.

        :param url: PatrOwl Manager URL
        :param auth_token: The API key
        :param proxies: The HTTP/HTTPS proxy endpoints
        :param ssl_verify: SSL/TLS certificate verification
        :param timeout: Request timeout (in sec)
        """
        self.url = url
        self.sess = requests.Session()
        self.sess.headers['Authorization'] = 'Token {}'.format(auth_token)
        self.sess.proxies = proxies
        self.sess.verify = ssl_verify
        self.sess.timeout = timeout

    def patrowl_request(self, request, path, error_message, payload=None):
        """
        This function is fetching the response with GET method and
        handeling errors
        """
        try:
            req = request(self.url+path, data=payload)
            if not req.ok:
                raise PatrowlException("{}: {}".format(error_message, req.text))
            return req.json()
        except requests.exceptions.RequestException as err_msg:
            raise PatrowlException("{}: {}".format(error_message, err_msg))

    # Assets
    def get_assets(self):
        """
        Get all assets.

        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/assets/api/v1/list',
            'Unable to retrieve assets')

    def get_assets_stats(self):
        """
        Get statistics on assets.

        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/assets/api/v1/stats',
            'Unable to retrieve assets stats')

    def get_asset_by_value(self, value):
        """
        Get an asset identified by his value.

        :param value: Asset value
        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/assets/api/v1/by-value/{}'.format(value),
            'Unable to retrieve asset')

    def get_asset_by_id(self, asset_id):
        """
        Get an asset identified by his ID.

        :param asset_id: Asset ID
        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/assets/api/v1/by-id/{}'.format(asset_id),
            'Unable to retrieve asset')

    def ack_asset_by_id(self, asset_id):
        """
        Ack an asset identified by his ID.

        :param asset_id: Asset ID
        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/assets/api/v1/by-id/{}/ack'.format(asset_id),
            'Unable to ack asset')

    def get_asset_findings_by_id(self, asset_id):
        """
        Get findings found on an asset.

        :param asset_id: Asset ID
        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/assets/api/v1/by-id/{}/findings'.format(asset_id),
            'Unable to retrieve asset findings')

    def add_asset(self, value, name, datatype, description, criticity, exposure, tags=["All"], teams=[]):
        """
        Create an asset.

        :param value: Value of the asset
        :param name: Name of the asset
        :param description: Description
        :param criticity: Criticality (low, medium, high)
        :param exposure: Exposure (unknown, external, internal, restricted)
        :param tags: Categories/Tags
        :type tags: list of str
        :rtype: json
        """
        if not datatype or not any(datatype in d for d in ASSET_TYPES):
            raise PatrowlException("Unable to create asset (type error): {}".format(datatype))
        if not criticity or not any(criticity in c for c in ASSET_CRITICITIES):
            raise PatrowlException("Unable to create asset (criticity error): {}".format(criticity))
        if not exposure or not any(exposure in e for e in ASSET_EXPOSURES):
            raise PatrowlException("Unable to create asset (exposure error): {}".format(exposure))
        if tags is None or not isinstance(tags, list):
            raise PatrowlException("Unable to create asset (tags error - should be a list of strings): {}".format(tags))
        if teams is None or not isinstance(teams, list):
            raise PatrowlException("Unable to create asset (teams error - should be a list of strings): {}".format(teams))

        data = {
            "value": value,
            "name": name,
            "type": datatype,
            "description": description,
            "criticity": criticity,
            "exposure": exposure,
            "tags": tags,
            "teams": teams,
        }
        return self.patrowl_request(
            self.sess.put,
            '/assets/api/v1/add',
            'Unable to create asset',
            payload=data)

    def delete_asset(self, asset_id):
        """
        Delete an asset.

        :param asset_id: Asset ID
        :rtype: json
        """
        return self.patrowl_request(
            self.sess.delete,
            '/assets/api/v1/delete/{}'.format(asset_id),
            'Unable to delete asset')

    def get_assetgroups(self):
        """
        Get all asset groups.

        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/assets/api/v1/groups/list',
            'Unable to retrieve asset groups')

    def get_assetgroup_by_name(self, name):
        """
        Get an asset group identified by his Name.

        :param name: Asset group name
        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/assets/api/v1/groups/by-name/{}'.format(name),
            'Unable to retrieve asset group')

    def get_assetgroup_by_id(self, assetgroup_id):
        """
        Get an asset group identified by his ID.

        :param assetgroup_id: Asset group ID
        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/assets/api/v1/groups/by-id/{}'.format(assetgroup_id),
            'Unable to retrieve asset group')

    def add_assetgroup(self, name, description, criticity, assets, tags=["All"]):
        """
        Create an asset group.

        :param name: Name of the asset
        :param description: Description
        :param criticity: Criticity (low, medium, high)
        :param tags: Categories
        :type tags: list of str
        :param assets: Assets ID
        :type assets: list of int
        :rtype: json
        """
        if not criticity or not any(criticity in d for d in ASSET_CRITICITIES):
            raise PatrowlException("Unable to create asset (criticity error): {}".format(criticity))
        if tags is None or not isinstance(tags, list):
            raise PatrowlException("Unable to create asset (tags error): {}".format(tags))

        data = {
            "name": name,
            "description": description,
            "criticity": criticity,
            "assets": assets,
            "tags": tags
        }
        return self.patrowl_request(
            self.sess.put,
            '/assets/api/v1/groups/add',
            'Unable to create asset group',
            payload=data)

    def edit_assetgroup(self, assetgroup_id, name, description, criticity, assets, tags=["All"]):
        """
        Edit an asset group

        :param assetgroup_id: Asset group ID
        :param name: Name of the asset
        :param description: Description
        :param criticity: Criticity (low, medium, high)
        :type tags: list of str
        :param assets: Assets ID
        :type assets: list of int
        :rtype: json
        """
        if not criticity or not any(criticity in d for d in ASSET_CRITICITIES):
            raise PatrowlException("Unable to edit assetgroup (criticity error): {}".format(criticity))
        if tags is None or not isinstance(tags, list):
            raise PatrowlException("Unable to edit assetgroup (tags error): {}".format(tags))

        data = {
            "name": name,
            "description": description,
            "criticity": criticity,
            "assets": assets,
            "tags": tags
        }
        return self.patrowl_request(
            self.sess.post,
            '/assets/api/v1/groups/edit/{}'.format(assetgroup_id),
            'Unable to edit asset group',
            payload=data)

    def delete_assetgroup(self, assetgroup_id):
        """
        Delete an asset group.

        :param assetgroup_id: Asset group ID
        :rtype: json
        """
        return self.patrowl_request(
            self.sess.delete,
            '/assets/api/v1/groups/delete/{}'.format(assetgroup_id),
            'Unable to delete asset group')

    # Findings
    def get_findings(
            self,
            status=None,
            title=None,
            severity=None,
            engine_type=None,
            finding_type=None,
            limit=None):
        """
        Get findings.

        :param status: Status
        :param title: Title icontains
        :param severity: Severity
        :param limit: Max number of results to return
        :rtype: json
        """
        criterias = ""
        if limit:
            criterias += "&limit={}".format(limit)
        if title:
            criterias += "&_title={}&_title_cond=icontains".format(title)
        if status and any(status in a for a in FINDING_STATUS):
            criterias += "&_status={}&_status_cond=exact".format(status)
        if severity and any(severity in a for a in FINDING_SEVERITIES):
            criterias += "&_severity={}&_severity_cond=exact".format(severity)
        if engine_type:
            criterias += "&_engine={}".format(engine_type)
        if finding_type:
            criterias += "&_type={}&_type_cond=exact".format(finding_type)
        return self.patrowl_request(
            self.sess.get,
            '/findings/api/v1/list?{}'.format(criterias),
            'Unable to retrieve findings')

    def get_finding(self, finding_id):
        """
        Get a finding identified by his ID.

        :param finding_id: Finding ID
        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/findings/api/v1/by-id/{}'.format(finding_id),
            'Unable to retrieve finding')

    def ack_finding(self, finding_id):
        """
        Ack an finding identified by his ID.

        :param finding_id: Finding ID
        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/findings/api/v1/{}/ack'.format(finding_id),
            'Unable to ack finding')

    def add_finding(
            self,
            title,
            description,
            finding_type,
            severity,
            asset,
            status='new'):
        """
        Create a finding.

        :param title: Title of the finding
        :param description: Description of the finding
        :param finding_type: Type of the finding
        :param severity: Severity of the finding
        :rtype: json
        """

        data = {
            "title": title,
            "description": description,
            "type": finding_type,
            'severity': severity,
            'solution': '',
            'risk_info': '',
            'vuln_refs': '',
            'links': [],
            'tags': [],
            'status': status,
            'asset': asset,
        }
        return self.patrowl_request(
            self.sess.post,
            '/findings/api/v1/add',
            'Unable to create finding',
            payload=data)

    def update_finding(
            self,
            finding_id,
            scan=None,
            title=None,
            description=None,
            finding_type=None,
            severity=None):
        """
        Update a finding

        :param finding_id: ID of the finding
        :param title: Title of the finding
        :param description: Description of the finding
        :param finding_type: Type of the finding
        :param severity: Severity of the finding
        :rtype: json
        """
        criterias = ""
        if scan or scan == '':
            criterias += "&scan={}".format(scan)
        if title:
            criterias += "&title={}".format(title)
        if description:
            criterias += "&description={}".format(description)
        if finding_type:
            criterias += "&type={}".format(finding_type)
        if severity:
            criterias += "&severity={}".format(severity)
        return self.patrowl_request(
            self.sess.get,
            '/findings/api/v1/update/{}?{}'.format(finding_id, criterias),
            'Unable to update finding')

    def delete_finding(self, finding_id):
        """
        Create a finding

        :param finding_id: ID of the finding
        :rtype: json
        """
        data = {
            finding_id: "delete me"
        }
        return self.patrowl_request(
            self.sess.post,
            '/findings/api/v1/delete',
            'Unable to delete finding',
            payload=data)

    # Scans
    def get_scan_by_id(self, scan_id):
        """
        Get a scan identified by his ID.

        :param scan_id: Scan ID
        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/scans/api/v1/by-id/{}'.format(scan_id),
            'Unable to retrieve scan')

    def get_scans(self, status=None, title=None, limit=None):
        """
        Get performed scans.

        :param status: Status
        :param title: Title icontains
        :param limit: Max number of results to return
        :rtype: json
        """
        criterias = ""
        if limit:
            criterias += "&limit={}".format(limit)
        if title:
            criterias += "&_title={}&_title_cond=icontains".format(title)
        if status and status in SCAN_STATUS:
            criterias += "&_status={}&_status_cond=exact".format(status)
        return self.patrowl_request(
            self.sess.get,
            '/scans/api/v1/list?{}'.format(criterias),
            'Unable to retrieve scans')

    def delete_scan_by_id(self, scan_id):
        """
        Delete a scan by its ID

        :param scan_id: ID of the scan
        """
        return self.patrowl_request(
            self.sess.delete,
            '/scans/api/v1/delete/{}'.format(scan_id),
            'Unable to delete scan')

    def get_scan_definition_by_id(self, scan_id):
        """
        Get a scan definition identified by his ID.

        :param scan_id: Scan definition ID
        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/scans/api/v1/defs/by-id/{}'.format(scan_id),
            'Unable to retrieve scan')

    def get_scan_definitions(self):
        """
        Get scan definitions.

        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/scans/api/v1/defs/list',
            'Unable to retrieve scans definitions')

    def add_scan_definition(self, engine_policy, title, description,
        engine_id=None, scan_type="single", every=None, period=None,
        scheduled_at=None, start_scan="now", assets=None, assetgroups=None):
        """
        Create a scan definition.

        :param engine_policy: ID of the scan policy
        :param engine_id: ID of the engine of instance or None
        :param scan_type: single/scheduled/periodic
        :param every: [periodic scan] frequency
        :param period: [periodic scan] seconds/minutes/hours/days
        :param scheduled_at: [scheduled scan] datetime
        :param title: Title
        :param description: Description
        :param start_scan: now/later/scheduled
        :param assets: list of assets ID
        :param assetgroups: list of asset groups ID
        :rtype: json
        """
        if scan_type not in ["single", "scheduled", "periodic"]:
            raise PatrowlException("Unable to create scan (scan_type error): {}".format(scan_type))
        if scan_type == "scheduled" and period not in ["seconds", "minutes", "hours", "days"]:
            raise PatrowlException("Unable to create scan (scan_type/period error): {}".format(period))
        if start_scan not in ["now", "scheduled", "later"]:
            raise PatrowlException("Unable to create scan (start_scan error): {}".format(start_scan))
        if assets is not None and not isinstance(assets, list):
            raise PatrowlException("Unable to create scan (asset error): {}".format(assets))
        if assetgroups is not None and not isinstance(assetgroups, list):
            raise PatrowlException("Unable to create scan (assetgroup error): {}".format(assetgroups))

        data = {
            "engine_policy": engine_policy,
            "engine_id": engine_id,
            "scan_type": scan_type,
            "title": title,
            "description": description,
            "scan_type": scan_type,
            "every": every,
            "period": period,
            "scheduled_at": scheduled_at,
            "start_scan": start_scan,
            "assets": assets,
            "assetgroups": assetgroups
        }
        return self.patrowl_request(
            self.sess.post,
            '/scans/api/v1/defs/add',
            'Unable to create scan definition',
            payload=data)

    def delete_scan_definition(self, scan_id):
        """
        Delete a scan definition.

        :param scan_id: ID of the scan definition
        """
        return self.patrowl_request(
            self.sess.delete,
            '/scans/api/v1/defs/delete/{}'.format(scan_id),
            'Unable to delete scan definition')

    def run_scan_definitions(self, scan_id):
        """
        Run scan definitions

        :param scan_id: ID of the scan definition
        """
        return self.patrowl_request(
            self.sess.get,
            '/scans/api/v1/defs/run/{}'.format(scan_id),
            'Unable to run scans definitions')

    # Engines
    def get_engine_instances(self):
        """
        Get engine instances.

        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/engines/api/v1/instances/list',
            'Unable to retrieve engines')

    def get_engine_instance_by_id(self, engine_id):
        """
        Get a engine instance by his ID.

        :param engine_id: Engine instance ID
        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/engines/api/v1/instances/by-id/{}'.format(engine_id),
            'Unable to retrieve engine')

    def get_engines(self):
        """
        Get engines.

        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/engines/api/v1/list',
            'Unable to retrieve engines')

    def get_engine_by_id(self, engine_id):
        """
        Get a engine by his ID.

        :param engine_id: Engine ID
        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/engines/api/v1/by-id/{}'.format(engine_id),
            'Unable to retrieve engine')

    def get_engine_policies(self):
        """
        Get engine policies.

        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/engines/api/v1/policies/list',
            'Unable to retrieve engine policies')

    def get_engine_policy(self, engine_policy_id):
        """
        Get a engine policy by his ID.

        :param engine_policy_id: Engine policy ID
        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/engines/api/v1/policies/by-id/{}'.format(engine_policy_id),
            'Unable to retrieve engine policy')

    # Rules
    def get_alerting_rules(self):
        """
        Get rules.

        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/rules/api/v1/alerting/list',
            'Unable to retrieve alerting rules')

    def get_alerting_rule(self, rule_id):
        """
        Get an alerting rule by his ID.

        :param rule_id: Alerting rule ID
        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/rules/api/v1/alerting/by-id/{}'.format(rule_id),
            'Unable to retrieve alerting rule')

    def delete_alerting_rule(self, rule_id):
        """
        Delete an alerting rule by his ID.

        :param rule_id: Alerting rule ID
        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/rules/api/v1/alerting/delete/{}'.format(rule_id),
            'Unable to delete alerting rule')

    def duplicate_alerting_rule(self, rule_id):
        """
        Duplicate an alerting rule by his ID.

        :param rule_id: Alerting rule ID
        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/rules/api/v1/alerting/duplicate/{}'.format(rule_id),
            'Unable to duplicate alerting rule')

    # User
    def get_users(self):
        """
        Get users.

        :rtype: json
        """
        return self.patrowl_request(
            self.sess.get,
            '/users/api/v1/list',
            'Unable to get users')

    def get_user_by_id(self, user_id):
        """
        Get an user identified by his ID.

        :param user_id: User ID
        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/users/api/v1/details/{}".format(user_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to retrieve user details: {}".format(e))

    # Teams
    def get_teams(self):
        """
        Get teams (paginated).
        ** PRO EDITION**

        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/api-pro/v1/teams/").json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to get teams (pro edition only): {}".format(e))

    def get_team_by_id(self, team_id):
        """
        Get a team identified by his ID.
        ** PRO EDITION**

        :param team_id: Team ID
        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/api-pro/v1/teams/{}/".format(team_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to retrieve team details (pro edition only): {}".format(e))

    def delete_team_by_id(self, team_id):
        """
        Delete a team identified by his ID.
        ** PRO EDITION**

        :param team_id: Team ID
        :rtype: json
        """
        try:
            return self.sess.delete(self.url+"/api-pro/v1/teams/{}/".format(team_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to delete team details (pro edition only): {}".format(e))

    def add_team(self, name, is_active=True):
        """
        Create a team.
        ** PRO EDITION**

        :param name: Name of the team
        :param is_active: Activate the team
        :type is_active: boolean
        :rtype: json
        """

        data = {
            "name": name,
            "slug": slugify(name),
            'is_active': is_active,
        }
        try:
            return self.sess.post(self.url+"/api-pro/v1/teams/", data=data).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to create team (pro edition only): {}".format(e))

    def get_team_users(self):
        """
        Get team users (paginated).
        ** PRO EDITION**

        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/api-pro/v1/team-users/").json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to get teams (pro edition only): {}".format(e))

    def get_team_user_by_id(self, team_user_id):
        """
        Get a team user identified by his ID.
        ** PRO EDITION**

        :param team_user_id: Team user ID
        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/api-pro/v1/team-users/{}/".format(team_user_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to retrieve team user details (pro edition only): {}".format(e))

    def delete_team_user_by_id(self, team_user_id):
        """
        Delete a team user identified by his ID.
        ** PRO EDITION**

        :param team_user_id: Team user ID
        :rtype: json
        """
        try:
            return self.sess.delete(self.url+"/api-pro/v1/team-users/{}/".format(team_user_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to delete team user details (pro edition only): {}".format(e))

    def add_team_user(self, team_id, user_id, is_admin=False):
        """
        Create a team.
        ** PRO EDITION**

        :param team_id: Team ID
        :param user_id: User ID
        :param is_admin: admin role enabled
        :type is_admin: boolean
        :rtype: json
        """

        data = {
            "organization": team_id,
            "user": user_id,
            'is_admin': is_admin,
        }
        try:
            return self.sess.post(self.url+"/api-pro/v1/team-users/", data=data).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to create team user (pro edition only): {}".format(e))

    # Stats
    def get_global_stats(self):
        """
        Get global usage stats
        ** PRO EDITION**

        :rtype: json
        """

        try:
            return self.sess.get(self.url+"/api-pro/v1/admin/stats").json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to get global usage stats (pro edition only): {}".format(e))
