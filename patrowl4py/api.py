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

        :param status: Status
        :param title: Title icontains
        :param scan_id: Scan ID
        :rtype: json
        """
        try:
            return self.sess.get(self.url+"/scans/api/v1/by-id/{}".format(scan_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlException("Unable to retrieve asset: {}".format(e))

    def get_scans(self, status=None, title=None, limit=None):
        """
        Get performed scans.

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
