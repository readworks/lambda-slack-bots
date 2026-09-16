import boto3
import pytest
from moto import mock_aws

from slack_bots.sg_ip_updater import security_groups


@pytest.fixture
def ec2():
    with mock_aws():
        yield boto3.client("ec2", region_name="us-west-2")


def _make_group(ec2, entries):
    """entries: list of (description, port). Each becomes an ingress rule at 9.9.9.9/32."""
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    gid = ec2.create_security_group(GroupName="t", Description="t", VpcId=vpc)["GroupId"]
    for i, (desc, port) in enumerate(entries):
        ec2.authorize_security_group_ingress(
            GroupId=gid,
            IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                "IpRanges": [{"CidrIp": f"9.9.{i}.9/32", "Description": desc}],
            }],
        )
    return gid


def _cidrs_for(ec2, gid, description):
    rules = security_groups.find_person_rules(ec2, gid, description)
    return sorted(r["CidrIpv4"] for r in rules)


def test_updates_matching_rule(ec2):
    gid = _make_group(ec2, [("ben", 22)])

    results = security_groups.update_ip(ec2, [gid], "ben", "1.2.3.4/32")

    assert results == {gid: 1}
    assert _cidrs_for(ec2, gid, "ben") == ["1.2.3.4/32"]


def test_updates_all_rules_for_person(ec2):
    gid = _make_group(ec2, [("ben", 22), ("ben", 443)])

    results = security_groups.update_ip(ec2, [gid], "ben", "1.2.3.4/32")

    assert results == {gid: 2}
    assert _cidrs_for(ec2, gid, "ben") == ["1.2.3.4/32", "1.2.3.4/32"]


def test_leaves_other_people_untouched(ec2):
    gid = _make_group(ec2, [("ben", 22), ("alice", 22)])

    security_groups.update_ip(ec2, [gid], "ben", "1.2.3.4/32")

    assert _cidrs_for(ec2, gid, "alice") == ["9.9.1.9/32"]


def test_no_matching_rule_reports_zero(ec2):
    gid = _make_group(ec2, [("alice", 22)])

    results = security_groups.update_ip(ec2, [gid], "ben", "1.2.3.4/32")

    assert results == {gid: 0}