import hashlib
import hmac
import json
import time

import boto3
import pytest
from moto import mock_aws

from slack_bots.sg_ip_updater import main, ssm

SECRET = "8f742231b10e8888abcd99yyyzzz85a5"
USER_ID = "U12345"


def _sign(ts, body):
    basestring = f"v0:{ts}:{body}".encode()
    return "v0=" + hmac.new(SECRET.encode(), basestring, hashlib.sha256).hexdigest()


CHANNEL_ID = "C0SECURITY"


def _event(text, user_id=USER_ID, channel_id=CHANNEL_ID, signed=True):
    ts = str(int(time.time()))
    body = f"user_id={user_id}&channel_id={channel_id}&text={text}&command=%2Fsetip"
    sig = _sign(ts, body) if signed else "v0=bad"
    return {
        "headers": {
            "X-Slack-Request-Timestamp": ts,
            "X-Slack-Signature": sig,
        },
        "body": body,
        "isBase64Encoded": False,
    }


@pytest.fixture
def aws(monkeypatch):
    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-west-2")
        ssm_client = boto3.client("ssm", region_name="us-west-2")

        ssm_client.put_parameter(Name="slack-sg-bot-signing-secret", Value=SECRET, Type="SecureString")

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        gid = ec2.create_security_group(GroupName="t", Description="t", VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=gid,
            IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                "IpRanges": [{"CidrIp": "9.9.9.9/32", "Description": "ben"}],
            }],
        )

        # Point module clients + config at the moto-backed resources.
        monkeypatch.setattr(main, "_ec2", ec2)
        monkeypatch.setattr(ssm, "_ssm", ssm_client)
        monkeypatch.setattr(main, "_signing_secret", None)
        monkeypatch.setenv("TARGET_SECURITY_GROUP_IDS", gid)
        monkeypatch.setenv("WHITELIST", json.dumps({USER_ID: "ben"}))
        monkeypatch.setenv("ALLOWED_CHANNEL_ID", CHANNEL_ID)

        yield {"ec2": ec2, "gid": gid}


def _current_cidr(ec2, gid):
    rules = ec2.describe_security_group_rules(
        Filters=[{"Name": "group-id", "Values": [gid]}]
    )["SecurityGroupRules"]
    return [r["CidrIpv4"] for r in rules if not r["IsEgress"]]


def test_happy_path_updates_ip(aws):
    resp = main.handler(_event("1.2.3.4"), None)

    assert resp["statusCode"] == 200
    assert "1.2.3.4/32" in json.loads(resp["body"])["text"]
    assert _current_cidr(aws["ec2"], aws["gid"]) == ["1.2.3.4/32"]


def test_bad_signature_returns_401(aws):
    resp = main.handler(_event("1.2.3.4", signed=False), None)

    assert resp["statusCode"] == 401
    assert _current_cidr(aws["ec2"], aws["gid"]) == ["9.9.9.9/32"]


def test_unauthorized_user(aws):
    resp = main.handler(_event("1.2.3.4", user_id="UNOPE"), None)

    assert resp["statusCode"] == 200
    assert "not authorized" in json.loads(resp["body"])["text"].lower()
    assert _current_cidr(aws["ec2"], aws["gid"]) == ["9.9.9.9/32"]


def test_invalid_ip(aws):
    resp = main.handler(_event("not-an-ip"), None)

    assert resp["statusCode"] == 200
    assert "not a valid" in json.loads(resp["body"])["text"].lower()
    assert _current_cidr(aws["ec2"], aws["gid"]) == ["9.9.9.9/32"]


def test_wrong_channel_rejected(aws):
    resp = main.handler(_event("1.2.3.4", channel_id="C0WRONG"), None)

    assert resp["statusCode"] == 200
    assert "designated channel" in json.loads(resp["body"])["text"].lower()
    assert _current_cidr(aws["ec2"], aws["gid"]) == ["9.9.9.9/32"]


def test_private_ip_rejected(aws):
    resp = main.handler(_event("10.0.0.5"), None)

    assert "not a valid" in json.loads(resp["body"])["text"].lower()
    assert _current_cidr(aws["ec2"], aws["gid"]) == ["9.9.9.9/32"]