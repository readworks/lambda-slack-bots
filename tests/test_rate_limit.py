import boto3
import pytest
from moto import mock_aws

from slack_bots.sg_ip_updater import rate_limit

TABLE = "ratelimit-test"


@pytest.fixture
def table(monkeypatch):
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-west-2")
        ddb.create_table(
            TableName=TABLE,
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        monkeypatch.setattr(rate_limit, "_ddb", ddb)
        yield ddb


def test_allows_up_to_limit(table):
    assert rate_limit.reserve(TABLE, "U1", 3) is True
    assert rate_limit.reserve(TABLE, "U1", 3) is True
    assert rate_limit.reserve(TABLE, "U1", 3) is True


def test_blocks_over_limit(table):
    for _ in range(3):
        rate_limit.reserve(TABLE, "U1", 3)
    assert rate_limit.reserve(TABLE, "U1", 3) is False


def test_limit_is_per_user(table):
    for _ in range(3):
        rate_limit.reserve(TABLE, "U1", 3)
    assert rate_limit.reserve(TABLE, "U2", 3) is True


def test_release_returns_a_slot(table):
    for _ in range(3):
        rate_limit.reserve(TABLE, "U1", 3)
    assert rate_limit.reserve(TABLE, "U1", 3) is False

    rate_limit.release(TABLE, "U1")
    assert rate_limit.reserve(TABLE, "U1", 3) is True