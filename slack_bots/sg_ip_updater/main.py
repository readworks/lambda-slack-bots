"""Slack slash-command Lambda: `/setip <ip>` swaps the caller's IP in target
security groups.

Wired to a Lambda Function URL (auth NONE); we authenticate every request by
verifying Slack's signature. Slack includes the invoking user_id, which we map
via a whitelist to the identifier used as the ingress-rule Description.
"""

import base64
import ipaddress
import json
import logging
import os
from urllib.parse import parse_qs

import boto3

from slack_bots.sg_ip_updater import rate_limit, security_groups, slack_verify
from slack_bots.sg_ip_updater.ssm import get_parameter

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

SIGNING_SECRET_PARAM = os.environ.get("SIGNING_SECRET_PARAM", "slack-sg-bot-signing-secret")

# Sentinel "user" whose daily counter tracks the global cap across everyone.
GLOBAL_KEY = "__global__"

_ec2 = boto3.client("ec2")
_signing_secret: str | None = None


def _target_group_ids() -> list[str]:
    raw = os.environ.get("TARGET_SECURITY_GROUP_IDS", "")
    return [g.strip() for g in raw.split(",") if g.strip()]


def _signing_secret_value() -> str:
    global _signing_secret
    if _signing_secret is None:
        _signing_secret = get_parameter(SIGNING_SECRET_PARAM)
    return _signing_secret


def _whitelist_value() -> dict[str, str]:
    return json.loads(os.environ.get("WHITELIST", "{}"))


def _ephemeral(text: str, status: int = 200) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"response_type": "ephemeral", "text": text}),
    }


def _raw_body(event: dict) -> str:
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8")
    return body


def _validated_cidr(text: str) -> str | None:
    try:
        ip = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    if ip.version != 4 or ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
        return None
    return f"{ip}/32"


def handler(event, context):
    logger.info("Handler invoked")
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    raw_body = _raw_body(event)

    if not slack_verify.verify(
        _signing_secret_value(),
        headers.get("x-slack-request-timestamp", ""),
        headers.get("x-slack-signature", ""),
        raw_body,
    ):
        logger.warning("Slack signature verification failed")
        return {"statusCode": 401, "body": "invalid signature"}

    form = {k: v[0] for k, v in parse_qs(raw_body).items()}
    user_id = form.get("user_id", "")
    text = form.get("text", "")
    logger.info(
        "Request: user_id=%s user_name=%s channel=%s command=%s text=%r",
        user_id, form.get("user_name"), form.get("channel_id"), form.get("command"), text,
    )

    allowed_channel = os.environ.get("ALLOWED_CHANNEL_ID", "")
    if allowed_channel and form.get("channel_id") != allowed_channel:
        logger.info("Command used in disallowed channel %s", form.get("channel_id"))
        return _ephemeral(":no_entry: This command can only be used in the designated channel.")

    description = _whitelist_value().get(user_id)
    if not description:
        logger.info("Unauthorized user %s", user_id)
        return _ephemeral(":no_entry: You are not authorized to update security groups.")

    cidr = _validated_cidr(text)
    if not cidr:
        return _ephemeral(f":x: `{text}` is not a valid public IPv4 address. Usage: `/setip 1.2.3.4`")

    rate_table = os.environ.get("RATE_LIMIT_TABLE", "")
    if rate_table:
        per_day = int(os.environ.get("RATE_LIMIT_PER_DAY", "3"))
        total_per_day = int(os.environ.get("RATE_LIMIT_TOTAL_PER_DAY", "50"))
        if not rate_limit.reserve(rate_table, user_id, per_day):
            logger.info("Per-user rate limit hit for %s", user_id)
            return _ephemeral(f":hourglass: Daily limit reached ({per_day} updates/day). Try again tomorrow.")
        if not rate_limit.reserve(rate_table, GLOBAL_KEY, total_per_day):
            rate_limit.release(rate_table, user_id)  # don't consume the per-user slot
            logger.warning("Global rate limit hit (%s/day)", total_per_day)
            return _ephemeral(f":hourglass: The global daily limit for this tool ({total_per_day}/day) has been reached.")

    group_ids = _target_group_ids()
    try:
        results = security_groups.update_ip(_ec2, group_ids, description, cidr)
    except Exception:
        # The action failed, so hand the reserved slots back.
        if rate_table:
            rate_limit.release(rate_table, user_id)
            rate_limit.release(rate_table, GLOBAL_KEY)
        logger.exception("Failed updating security groups for %s", description)
        return _ephemeral(":warning: Something went wrong updating the security groups. Check the logs.")

    updated = sum(results.values())
    skipped = [g for g, n in results.items() if n == 0]
    logger.info("Updated %s -> %s across %s: %s", description, cidr, group_ids, results)
    lines = [f":white_check_mark: Updated *{description}* access to `{cidr}` — {updated} rule(s) across {len(group_ids)} group(s)."]
    if skipped:
        lines.append(f":information_source: No matching rule in: {', '.join(skipped)}")
    return _ephemeral("\n".join(lines))