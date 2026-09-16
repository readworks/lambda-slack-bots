#!/usr/bin/env python3
import aws_cdk as cdk
from slack_bots_build_stack import SlackBotsBuildStack
from slack_bots_app_stack import SlackBotsAppStack

app = cdk.App()

aws_env = cdk.Environment(account='487007042145', region='us-west-2')


def tag(stack) -> None:
    cdk.Tags.of(stack).add("project", "slack-bots")
    cdk.Tags.of(stack).add("env", "prod")
    cdk.Tags.of(stack).add("VantaOwner", "ben@readworks.org")


# Build stack for CI/CD and the (admin-owned) Lambda execution role
build = SlackBotsBuildStack(app, "SlackBotsBuildStack", env=aws_env)

# Application stack for the Lambda functions
app_stack = SlackBotsAppStack(app, "SlackBotsAppStack", env=aws_env)

for stack in (build, app_stack):
    tag(stack)

app.synth()