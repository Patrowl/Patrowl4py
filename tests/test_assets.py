from patrowl4py.api import PatrowlManagerApi
import pytest
import random
import string

api = PatrowlManagerApi(
    url='http://localhost:8001',
    auth_token='a4218191e1d5ad27ad40dbce0360e4f05e92ceb0'
)
pytest.new_asset = {}
pytest.rand_fqdn = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(16))

# Assets
# print(api.get_assets())
# print(api.get_assets_stats())
# print(api.get_asset_by_id(1))
# print(api.ack_asset_by_id(1))
# print(api.get_asset_findings_by_id(1))
# print(api.delete_asset(new_asset['id']))


@pytest.mark.run('first')
def test_asset_add():
    pytest.new_asset = api.add_asset(
        value=pytest.rand_fqdn, name="Test FQDN", datatype="fqdn",
        description="n/a", criticity="low", tags=["patrowl", "demo"],
        exposure="external", teams=[]
    )


@pytest.mark.run(after=['test_asset_add'])
def test_asset_add_errors_value():
    with pytest.raises(Exception):
        # Bad value (already exists)
        r = api.add_asset(
            value=pytest.rand_fqdn, name="Test FQDN", datatype="fqdn",
            description=None, criticity="low", tags=["patrowl", "demo"],
            exposure="external", teams=[]
        )
        if r['status'] == "error":
            raise Exception()


def test_asset_add_errors_datatype():
    with pytest.raises(Exception):
        # Bad datatype
        api.add_asset(
            value=pytest.rand_fqdn, name="Test FQDN", datatype="bad",
            description="n/a", criticity="low", tags=["patrowl", "demo"],
            exposure="external", teams=[]
        )


def test_asset_add_errors_criticity():
    with pytest.raises(Exception):
        # Bad criticity
        api.add_asset(
            value=pytest.rand_fqdn, name="Test FQDN", datatype="fqdn",
            description="n/a", criticity="bad", tags=["patrowl", "demo"],
            exposure="external", teams=[]
        )


def test_asset_add_errors_exposure():
    with pytest.raises(Exception):
        # Bad exposure
        api.add_asset(
            value=pytest.rand_fqdn, name="Test FQDN", datatype="fqdn",
            description="n/a", criticity="low", tags=["patrowl", "demo"],
            exposure="bad", teams=[]
        )


@pytest.mark.run(after=['test_asset_add'])
def test_asset_by_id():
    api.get_asset_by_id(pytest.new_asset['id'])


@pytest.mark.run(after=['test_asset_add'])
def test_ack_asset_by_id():
    api.ack_asset_by_id(pytest.new_asset['id'])


@pytest.mark.run(after=['test_asset_add'])
def test_asset_findings_by_id():
    api.get_asset_findings_by_id(pytest.new_asset['id'])


@pytest.mark.run(after=['get_asset_findings_by_id'])
def test_asset_delete():
    api.delete_asset(pytest.new_asset['id'])
