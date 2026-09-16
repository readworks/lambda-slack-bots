import json
import os

import aws_cdk as cdk
from aws_cdk import (
    Stack,
    Duration,
    CfnOutput,
    aws_lambda as _lambda,
    aws_iam as iam,
)
from constructs import Construct

import config

# Package root (parent of deploy/), so the asset resolves no matter where cdk runs.
PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class SlackBotsAppStack(Stack):
    """Application stack: the Slack-bot Lambda functions and their triggers."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Execution role is owned by the build stack (admin-deployed) and imported
        # immutable here, so this CI-deployed stack needs no IAM role permissions.
        lambda_role = iam.Role.from_role_arn(
            self, "SgIpUpdaterLambdaRole",
            f"arn:aws:iam::{self.account}:role/slack-sg-ip-updater-lambda",
            mutable=False,
        )

        sg_ip_updater = _lambda.Function(
            self, "SgIpUpdaterFunction",
            function_name="slack-sg-ip-updater",
            runtime=_lambda.Runtime.PYTHON_3_14,
            handler="slack_bots.sg_ip_updater.main.handler",
            code=_lambda.Code.from_asset(PACKAGE_ROOT,
                bundling=cdk.BundlingOptions(
                    image=_lambda.Runtime.PYTHON_3_14.bundling_image,
                    command=[
                        "bash", "-c",
                        "pip install uv && UV_CACHE_DIR=/tmp/uv-cache uv pip install --system -r pyproject.toml --target /asset-output && " +
                        "rsync -av --exclude='__pycache__' --exclude='*.pyc' --exclude='.venv' " +
                        "--exclude='.git' --exclude='deploy' --exclude='tests' --exclude='node_modules' " +
                        "--exclude='cdk.out' --exclude='.pytest_cache' --exclude='*.iml' " +
                        "--exclude='.python-version' --exclude='.node-version' --exclude='.gitignore' " +
                        "--exclude='README.md' --exclude='buildspec.yml' --exclude='*.json' " +
                        "--exclude='setup_parameters.sh' --exclude='uv.lock' . /asset-output/"
                    ]
                ),
                exclude=[
                    ".git/**",
                    "tests/**",
                    "deploy/**",
                    "node_modules/**",
                    ".venv/**",
                    "__pycache__/**",
                    "cdk.out/**",
                    ".pytest_cache/**",
                    "*.iml",
                    "*.pyc",
                    "**/*.pyc",
                ]
            ),
            timeout=Duration.seconds(10),
            memory_size=128,
            role=lambda_role,
            environment={
                "TARGET_SECURITY_GROUP_IDS": ",".join(config.TARGET_SECURITY_GROUP_IDS),
                "SIGNING_SECRET_PARAM": config.SIGNING_SECRET_PARAM,
                "ALLOWED_CHANNEL_ID": config.ALLOWED_CHANNEL_ID,
                "WHITELIST": json.dumps(config.WHITELIST),
            },
            retry_attempts=0,
        )

        # Public URL Slack posts the slash command to. Auth is handled in-code by
        # verifying the Slack request signature, so the URL itself is unauthenticated.
        function_url = sg_ip_updater.add_function_url(
            auth_type=_lambda.FunctionUrlAuthType.NONE,
        )

        CfnOutput(
            self, "SgIpUpdaterFunctionUrl",
            value=function_url.url,
            description="Slack slash-command Request URL for /setip",
        )