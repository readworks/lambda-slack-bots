import aws_cdk as cdk
from aws_cdk import (
    Stack,
    RemovalPolicy,
    aws_codebuild as codebuild,
    aws_iam as iam,
    aws_sns as sns,
    aws_sns_subscriptions as subscriptions,
    aws_dynamodb as dynamodb,
)
from constructs import Construct

import config

ACCOUNT_ID = "487007042145"
REGION = "us-west-2"


class SlackBotsBuildStack(Stack):
    """Build stack: CodeBuild CI/CD pipeline plus the admin-owned Lambda
    execution role (imported immutable by the app stack)."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        github_source = codebuild.Source.git_hub(
            owner="readworks",
            repo="lambda-slack-bots",
            webhook=True,
            webhook_filters=[
                codebuild.FilterGroup.in_event_of(codebuild.EventAction.PUSH).and_branch_is("main")
            ],
            branch_or_ref="refs/heads/main",
            report_build_status=True,
        )

        code_build_role = iam.Role(
            self, "CodeBuildRole",
            assumed_by=iam.ServicePrincipal("codebuild.amazonaws.com")
        )

        sg_arns = [
            f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}:security-group/{sg}"
            for sg in config._IAM_GROUP_IDS
        ]
        param_arns = [
            f"arn:aws:ssm:{REGION}:{ACCOUNT_ID}:parameter/{config.SIGNING_SECRET_PARAM}",
        ]
        rate_limit_table_arn = f"arn:aws:dynamodb:{REGION}:{ACCOUNT_ID}:table/{config.RATE_LIMIT_TABLE}"

        # Lambda execution role for the sg-ip-updater function. Owned here (admin
        # deployed) so the CI/CodeBuild role never needs to create or mutate IAM
        # roles — only to pass this one. The app stack imports it by ARN (immutable).
        lambda_role = iam.Role(
            self, "SgIpUpdaterLambdaRole",
            role_name="slack-sg-ip-updater-lambda",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"),
            ],
        )

        # Describe has no resource-level scoping; modify is scoped to the target SGs.
        lambda_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["ec2:DescribeSecurityGroupRules"],
                resources=["*"],
            )
        )
        # ModifySecurityGroupRules authorizes against BOTH the security group and
        # each security-group-rule. Rule ARNs don't embed the group and aren't
        # known ahead of time, so we allow all rule ARNs — the specific-group
        # constraint still limits which groups' rules can actually be modified.
        lambda_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["ec2:ModifySecurityGroupRules"],
                resources=sg_arns + [f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}:security-group-rule/*"],
            )
        )

        # Read the signing secret from SSM, decrypting the SecureString.
        lambda_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["ssm:GetParameter"],
                resources=param_arns,
            )
        )
        lambda_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["kms:Decrypt"],
                resources=["*"],
                conditions={"StringEquals": {"kms:ViaService": f"ssm.{REGION}.amazonaws.com"}},
            )
        )

        # Rate-limit counters. Durable infra owned here (not the app stack), so
        # app-stack deploys never need DynamoDB table-management permissions.
        # TTL (`expireAt`) auto-purges old day rows.
        dynamodb.Table(
            self, "RateLimitTable",
            table_name=config.RATE_LIMIT_TABLE,
            partition_key=dynamodb.Attribute(name="pk", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="expireAt",
            removal_policy=RemovalPolicy.DESTROY,
        )

        # The function only needs UpdateItem on that table.
        lambda_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:UpdateItem"],
                resources=[rate_limit_table_arn],
            )
        )

        # CodeBuild logging permissions
        code_build_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                resources=[
                    f"arn:aws:logs:{REGION}:{ACCOUNT_ID}:log-group:/aws/codebuild/slack-sg-ip-updater:*",
                ]
            )
        )

        # CloudFormation permissions scoped to the CDK stacks
        code_build_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "cloudformation:CreateStack",
                    "cloudformation:UpdateStack",
                    "cloudformation:DeleteStack",
                    "cloudformation:DescribeStacks",
                    "cloudformation:DescribeStackEvents",
                    "cloudformation:GetTemplate",
                    "cloudformation:CreateChangeSet",
                    "cloudformation:DescribeChangeSet",
                    "cloudformation:ExecuteChangeSet",
                    "cloudformation:DeleteChangeSet",
                    "cloudformation:GetTemplateSummary",
                ],
                resources=[
                    f"arn:aws:cloudformation:{REGION}:{ACCOUNT_ID}:stack/SlackBotsAppStack/*",
                    f"arn:aws:cloudformation:{REGION}:{ACCOUNT_ID}:stack/CDKToolkit/*",
                ]
            )
        )

        # S3 permissions for CDK assets bucket
        code_build_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:ListBucket",
                    "s3:GetBucketLocation",
                ],
                resources=[
                    f"arn:aws:s3:::cdk-*-assets-{ACCOUNT_ID}-{REGION}",
                    f"arn:aws:s3:::cdk-*-assets-{ACCOUNT_ID}-{REGION}/*",
                ]
            )
        )

        # Lambda permissions scoped to the function, including its Function URL
        # config and the resource-based invoke permission CDK adds for the URL.
        code_build_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "lambda:CreateFunction",
                    "lambda:UpdateFunctionCode",
                    "lambda:UpdateFunctionConfiguration",
                    "lambda:DeleteFunction",
                    "lambda:GetFunction",
                    "lambda:GetFunctionConfiguration",
                    "lambda:AddPermission",
                    "lambda:RemovePermission",
                    "lambda:TagResource",
                    "lambda:UntagResource",
                    "lambda:ListTags",
                    "lambda:CreateFunctionUrlConfig",
                    "lambda:UpdateFunctionUrlConfig",
                    "lambda:DeleteFunctionUrlConfig",
                    "lambda:GetFunctionUrlConfig",
                    "lambda:PutFunctionEventInvokeConfig",
                    "lambda:DeleteFunctionEventInvokeConfig",
                    "lambda:PutFunctionConcurrency",
                    "lambda:DeleteFunctionConcurrency",
                ],
                resources=[
                    f"arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:slack-sg-ip-updater",
                ]
            )
        )

        # CloudWatch alarm CRUD for the app stack's Lambda Errors alarm. Put/Delete
        # and tagging are scoped to the alarm; DescribeAlarms has no resource-level
        # scoping so it must be on "*".
        code_build_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "cloudwatch:PutMetricAlarm",
                    "cloudwatch:DeleteAlarms",
                    "cloudwatch:TagResource",
                    "cloudwatch:UntagResource",
                    "cloudwatch:ListTagsForResource",
                ],
                resources=[
                    f"arn:aws:cloudwatch:{REGION}:{ACCOUNT_ID}:alarm:slack-sg-ip-updater-errors",
                ]
            )
        )
        code_build_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["cloudwatch:DescribeAlarms"],
                resources=["*"],
            )
        )

        # The app stack imports the Lambda execution role and passes it to the
        # function, so CI only needs to pass and read that one role.
        code_build_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "iam:PassRole",
                    "iam:GetRole",
                ],
                resources=[lambda_role.role_arn]
            )
        )

        # CDK's default synthesizer hands CloudFormation the bootstrap
        # cfn-exec-role to mutate stack resources, so CI must be allowed to pass it.
        code_build_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["iam:PassRole"],
                resources=[
                    f"arn:aws:iam::{ACCOUNT_ID}:role/cdk-hnb659fds-cfn-exec-role-{ACCOUNT_ID}-{REGION}",
                ]
            )
        )

        # SSM read permission for CDK context lookups
        code_build_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["ssm:GetParameter"],
                resources=[
                    f"arn:aws:ssm:{REGION}:{ACCOUNT_ID}:parameter/cdk-bootstrap/*",
                ]
            )
        )

        lambda_deploy_project = codebuild.Project(
            self, "SlackBotsDeployProject",
            project_name="slack-sg-ip-updater",
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.STANDARD_7_0,
                compute_type=codebuild.ComputeType.SMALL,
            ),
            source=github_source,
            role=code_build_role,
            build_spec=codebuild.BuildSpec.from_source_filename("buildspec.yml"),
            timeout=cdk.Duration.minutes(15),
        )

        # Notify on build failures via SNS email, mirroring the sibling packages.
        build_error_topic = sns.Topic(
            self, "BuildSNSTopic",
            display_name="Slack bots build failures",
            topic_name="slack-bots-build-errors",
        )
        build_error_topic.add_subscription(
            subscriptions.EmailSubscription("dev@readworks.org")
        )

        lambda_deploy_project.notify_on_build_failed(
            "BuildFailedNotification",
            build_error_topic,
        )