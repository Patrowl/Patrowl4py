import requests

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

    # Assets
    def get_assets(self):
        """
        Get all assets.

        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/assets/api/v1/list").json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to retrieve assets: {}".format(e))

    def get_assets_stats(self):
        """
        Get statistics on assets.

        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/assets/api/v1/stats").json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to retrieve asset: {}".format(e))

    def get_asset_by_id(self, asset_id):
        """
        Get an asset identified by his ID.

        :param asset_id: Asset ID
        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/assets/api/v1/by-id/{}".format(asset_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to retrieve asset: {}".format(e))

    def get_asset_findings_by_id(self, asset_id):
        """
        Get findings found on an asset.

        :param asset_id: Asset ID
        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/assets/api/v1/by-id/{}/findings".format(asset_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to retrieve findings: {}".format(e))

    def add_asset(self, value, name, datatype, description, criticity, tags=["All"]):
        """
        Create an asset

        :param value: Value of the asset
        :param name: Name of the asset
        :param description: Description
        :param criticity: Criticity (low, medium, high)
        :param tags: Categories
        :type tags: list of str
        :rtype: json
        """
        if not datatype or not any(datatype in d for d in ASSET_TYPES):
            raise PatrowlException("Unable to create asset (type error): {}".format(datatype))
        if not criticity or not any(criticity in d for d in ASSET_CRITICITIES):
            raise PatrowlException("Unable to create asset (criticity error): {}".format(criticity))
        if tags is None or not isinstance(tags, list):
            raise PatrowlException("Unable to create asset (tags error): {}".format(tags))

        data = {
            "value": value,
            "name": name,
            "type": datatype,
            "description": description,
            "criticity": criticity,
            "tags": tags
        }
        try:
            return self.sess.put(self.url+"/assets/api/v1/add", data=data).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to create asset (unknown): {}".format(e))

    def delete_asset(self, asset_id):
        """
        Delete an asset.

        :param asset_id: Asset ID
        :rtype: json
        """
        try:
            return self.sess.delete(self.url+"/assets/api/v1/delete/{}".format(asset_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to delete asset: {}".format(e))

    # Findings
    def get_findings(self, status=None, title=None, severity=None, scopes=None, limit=None):
        """
        Get findings.

        :param status: Status
        :param title: Title icontains
        :param severity: Severity
        :param scopes: Scopes ID
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
        try:
            return self.sess.get(self.url+"/findings/api/v1/list?{}".format(criterias)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to retrieve findings: {}".format(e))

    def get_finding(self, finding_id):
        """
        Get a finding identified by his ID.

        :param finding_id: Finding ID
        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/findings/api/v1/by-id/{}".format(finding_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to retrieve findings: {}".format(e))

    # Scans
    def get_scan_by_id(self, scan_id):
        """
        Get a scan identified by his ID.

        :param scan_id: Scan ID
        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/scans/api/v1/by-id/{}".format(scan_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to retrieve scan: {}".format(e))

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
        try:
            return self.sess.get(self.url+"/scans/api/v1/list?{}".format(criterias)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to retrieve scans: {}".format(e))

    def get_scan_definition_by_id(self, scan_id):
        """
        Get a scan definition identified by his ID.

        :param scan_id: Scan definition ID
        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/scans/api/v1/defs/by-id/{}".format(scan_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to retrieve scan: {}".format(e))

    def get_scan_definitions(self):
        """
        Get scan definitions.

        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/scans/api/v1/defs/list").json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to retrieve scans definitions: {}".format(e))


    def add_scan_definition(self, engine_policy, title, description,
        engine_id=None, scan_type="single", every=None, period=None,
        scheduled_at=None, start_scan="now", assets=None, assetgroups=None):
        """
        Create a scan definition

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
        try:
            return self.sess.post(self.url+"/scans/api/v1/defs/add", data=data).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to create scan definition (unknown): {}".format(e))


    # Engines
    def get_engine_instances(self):
        """
        Get engine instances.

        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/engines/api/v1/instances/list").json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to retrieve engines: {}".format(e))

    def get_engine_instance_by_id(self, engine_id):
        """
        Get a engine instance by his ID.

        :param engine_id: Engine instance ID
        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/engines/api/v1/instances/by-id/{}".format(engine_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to retrieve engine: {}".format(e))

    def get_engines(self):
        """
        Get engines.

        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/engines/api/v1/list").json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to retrieve engines: {}".format(e))

    def get_engine_by_id(self, engine_id):
        """
        Get a engine by his ID.

        :param engine_id: Engine ID
        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/engines/api/v1/by-id/{}".format(engine_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to retrieve engine: {}".format(e))

    def get_engine_policies(self):
        """
        Get engine policies.

        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/engines/api/v1/policies/list").json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to retrieve engine policies: {}".format(e))

    def get_engine_policy(self, engine_policy_id):
        """
        Get a engine policy by his ID.

        :param engine_policy_id: Engine policy ID
        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/engines/api/v1/policies/by-id/{}".format(engine_policy_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to retrieve engine policy: {}".format(e))

    # Rules
    def get_alerting_rules(self):
        """
        Get rules.

        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/rules/api/v1/alerting/list").json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to retrieve alerting rules: {}".format(e))

    def get_alerting_rule(self, rule_id):
        """
        Get an alerting rule by his ID.

        :param rule_id: Alerting rule ID
        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/rules/api/v1/alerting/by-id/{}".format(rule_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to retrieve alerting rule: {}".format(e))

    def delete_alerting_rule(self, rule_id):
        """
        Delete an alerting rule by his ID.

        :param rule_id: Alerting rule ID
        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/rules/api/v1/alerting/delete/{}".format(rule_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to delete alerting rule: {}".format(e))

    def duplicate_alerting_rule(self, rule_id):
        """
        Duplicate an alerting rule by his ID.

        :param rule_id: Alerting rule ID
        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/rules/api/v1/alerting/duplicate/{}".format(rule_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to delete alerting rule: {}".format(e))
