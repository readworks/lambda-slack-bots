import boto3

_ssm = boto3.client("ssm")


def get_parameter(name: str, with_decryption: bool = True) -> str:
    """Read a single parameter value from SSM Parameter Store."""
    resp = _ssm.get_parameter(Name=name, WithDecryption=with_decryption)
    return resp["Parameter"]["Value"]