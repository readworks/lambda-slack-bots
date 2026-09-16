"""Swap a person's IP in EC2 security group ingress rules.

A person "owns" the ingress rules whose Description equals their identifier.
We update those rules in place (preserving protocol/port/rule-id) so only the
allowed CIDR changes.
"""


def find_person_rules(ec2, group_id: str, description: str) -> list[dict]:
    """Return ingress rules in a group whose Description matches `description`."""
    paginator = ec2.get_paginator("describe_security_group_rules")
    rules = []
    for page in paginator.paginate(
        Filters=[{"Name": "group-id", "Values": [group_id]}]
    ):
        for rule in page["SecurityGroupRules"]:
            if not rule.get("IsEgress") and rule.get("Description") == description:
                rules.append(rule)
    return rules


def _swap_cidr(ec2, group_id: str, rule: dict, cidr: str) -> None:
    ec2.modify_security_group_rules(
        GroupId=group_id,
        SecurityGroupRules=[
            {
                "SecurityGroupRuleId": rule["SecurityGroupRuleId"],
                "SecurityGroupRule": {
                    "IpProtocol": rule["IpProtocol"],
                    "FromPort": rule["FromPort"],
                    "ToPort": rule["ToPort"],
                    "CidrIpv4": cidr,
                    "Description": rule.get("Description", ""),
                },
            }
        ],
    )


def update_ip(ec2, group_ids: list[str], description: str, cidr: str) -> dict:
    """Update every ingress rule owned by `description` to the new `cidr`.

    Returns {group_id: rules_updated_count}. A group with no matching rule maps
    to 0 (skipped) rather than erroring — we never create rules here.
    """
    results: dict[str, int] = {}
    for group_id in group_ids:
        rules = find_person_rules(ec2, group_id, description)
        for rule in rules:
            _swap_cidr(ec2, group_id, rule, cidr)
        results[group_id] = len(rules)
    return results