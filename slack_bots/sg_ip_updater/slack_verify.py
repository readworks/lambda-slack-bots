import hashlib
import hmac
import time

# Reject requests whose timestamp is older than this (replay protection).
MAX_SKEW_SECONDS = 60 * 5


def verify(signing_secret: str, timestamp: str, signature: str, raw_body: str) -> bool:
    """Verify a Slack request signature.

    Slack signs `v0:{timestamp}:{raw_body}` with HMAC-SHA256 keyed on the app
    signing secret. See https://api.slack.com/authentication/verifying-requests-from-slack
    """
    if not signing_secret or not timestamp or not signature:
        return False

    try:
        if abs(time.time() - int(timestamp)) > MAX_SKEW_SECONDS:
            return False
    except ValueError:
        return False

    basestring = f"v0:{timestamp}:{raw_body}".encode()
    expected = "v0=" + hmac.new(signing_secret.encode(), basestring, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)