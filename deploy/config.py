"""Shared deploy config. Referenced by both the app and build stacks so the
Lambda's target groups and the IAM policy that scopes access to them stay in
sync.

STUB: fill TARGET_SECURITY_GROUP_IDS with the real sg-ids before deploying.
"""

# Security groups the bot is allowed to modify.
TARGET_SECURITY_GROUP_IDS: list[str] = [
    "sg-0035a3a4aab535df9", # Kibana
    "sg-75a77e11", # web-qa-loadbalancer
]

# Whitelist: Slack user_id -> the Description on that person's SG ingress rules.
# Find a user_id in Slack: profile -> More -> Copy member ID.
# STUB: add one entry per authorized person before deploying.
WHITELIST: dict[str, str] = {
    "U04MJRX6N13": "ben",
    "UM0CTDA0N": "caitlyn",
    "UC5F7SVL4": "manjula",
    "U03GRHGURNJ": "paola",
}

# Restrict the command to a single Slack channel (defense-in-depth on top of the
# whitelist). Get the id from the channel's "View channel details" in Slack.
# Empty string = allow from anywhere. STUB: set before deploying.
ALLOWED_CHANNEL_ID = "C0C1XPEBV1D"

# Rate limits and the DynamoDB table that tracks them. Per-person cap plus a
# global daily cap (this is a public Function URL, so bound total blast radius).
RATE_LIMIT_PER_DAY = 3
RATE_LIMIT_TOTAL_PER_DAY = 50
RATE_LIMIT_TABLE = "slack-sg-ip-updater-ratelimit"

# Lambda log verbosity (DEBUG/INFO/WARNING/ERROR).
LOG_LEVEL = "INFO"

# SSM parameter holding the Slack app signing secret (kept out of git).
SIGNING_SECRET_PARAM = "slack-sg-bot-signing-secret"

# Placeholder used to build a valid IAM resource ARN while the list is empty,
# so `cdk synth` works before the real ids are filled in.
_IAM_GROUP_IDS = TARGET_SECURITY_GROUP_IDS or ["sg-STUB"]