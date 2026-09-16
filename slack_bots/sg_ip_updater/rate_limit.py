"""Per-person daily rate limiting backed by DynamoDB.

One item per user per UTC day, keyed `{user_id}#{YYYY-MM-DD}`, holding an atomic
`count`. Reserving a slot is a single conditional UpdateItem, so it is correct
under concurrent invocations. Items self-expire via the `expireAt` TTL.
"""

import datetime

import boto3
from botocore.exceptions import ClientError

_ddb = boto3.resource("dynamodb")


def _key(user_id: str) -> str:
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    return f"{user_id}#{today}"


def _ttl_epoch() -> int:
    # Counters only matter for the current day; keep the row ~2 days for cleanup.
    now = datetime.datetime.now(datetime.timezone.utc)
    return int((now + datetime.timedelta(days=2)).timestamp())


def reserve(table_name: str, user_id: str, limit: int) -> bool:
    """Atomically consume one of the user's daily slots.

    Returns True if a slot was available (and consumed), False if the user is at
    the limit.
    """
    table = _ddb.Table(table_name)
    try:
        table.update_item(
            Key={"pk": _key(user_id)},
            UpdateExpression="SET #c = if_not_exists(#c, :zero) + :one, expireAt = :ttl",
            ConditionExpression="attribute_not_exists(#c) OR #c < :limit",
            ExpressionAttributeNames={"#c": "count"},
            ExpressionAttributeValues={":zero": 0, ":one": 1, ":limit": limit, ":ttl": _ttl_epoch()},
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise


def release(table_name: str, user_id: str) -> None:
    """Give back a reserved slot (best effort) when the action ultimately failed."""
    table = _ddb.Table(table_name)
    try:
        table.update_item(
            Key={"pk": _key(user_id)},
            UpdateExpression="SET #c = #c - :one",
            ConditionExpression="#c > :zero",
            ExpressionAttributeNames={"#c": "count"},
            ExpressionAttributeValues={":one": 1, ":zero": 0},
        )
    except ClientError:
        pass