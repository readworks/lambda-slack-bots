import hashlib
import hmac
import time

from slack_bots.sg_ip_updater import slack_verify

SECRET = "8f742231b10e8888abcd99yyyzzz85a5"


def sign(timestamp, body, secret=SECRET):
    basestring = f"v0:{timestamp}:{body}".encode()
    return "v0=" + hmac.new(secret.encode(), basestring, hashlib.sha256).hexdigest()


def test_valid_signature():
    ts = str(int(time.time()))
    body = "user_id=U1&text=1.2.3.4"
    assert slack_verify.verify(SECRET, ts, sign(ts, body), body)


def test_bad_signature():
    ts = str(int(time.time()))
    body = "user_id=U1&text=1.2.3.4"
    assert not slack_verify.verify(SECRET, ts, "v0=deadbeef", body)


def test_wrong_secret():
    ts = str(int(time.time()))
    body = "user_id=U1"
    assert not slack_verify.verify(SECRET, ts, sign(ts, body, "other"), body)


def test_stale_timestamp():
    ts = str(int(time.time()) - 600)
    body = "user_id=U1"
    assert not slack_verify.verify(SECRET, ts, sign(ts, body), body)


def test_missing_fields():
    assert not slack_verify.verify(SECRET, "", "", "body")
    assert not slack_verify.verify("", "123", "sig", "body")


def test_non_numeric_timestamp():
    body = "user_id=U1"
    assert not slack_verify.verify(SECRET, "notanumber", sign("notanumber", body), body)