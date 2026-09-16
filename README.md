# lambda-slack-bots

Home for ReadWorks Slack bots running on AWS Lambda. Follows the
build-stack / app-stack CDK model used across the `lambda-*` packages
(account `487007042145`, region `us-west-2`, `uv`-based bundling).

## Bots

### sg-ip-updater (`/setip`)

Lets whitelisted people update their own IP in specific EC2 security groups
from Slack. A user runs the slash command:

```
/setip 1.2.3.4
```

and the bot swaps the CIDR of that person's existing ingress rules to
`1.2.3.4/32` in every target security group. It updates rules **in place**
(matching on the rule's `Description`); it never creates or deletes rules.

**Flow:** Slack posts the slash command to the Lambda's Function URL → the
Lambda verifies the Slack request signature → maps the caller's `user_id` to
their rule identifier via a whitelist → validates the IP → finds and updates
their rules.

Auth is handled two ways: only Slack can call the URL (HMAC signature check),
and only whitelisted `user_id`s can make changes (the whitelist).

## Project structure

```
slack_bots/sg_ip_updater/   # Lambda source
  main.py                   # slash-command handler
  slack_verify.py           # Slack signature + replay check
  security_groups.py        # find rule by description, swap CIDR
  ssm.py                    # SSM parameter reader
deploy/                     # CDK app (build + app stacks)
tests/                      # pytest (moto-mocked)
buildspec.yml               # CodeBuild CI/CD
```

## Configuration

| What | Where | Notes |
|---|---|---|
| Target security groups | `deploy/config.py` → `TARGET_SECURITY_GROUP_IDS` | Set on the Lambda env + scopes the IAM policy. Redeploy to change. |
| Whitelist | `deploy/config.py` → `WHITELIST` | `{"<slack_user_id>": "<rule-description>"}`. Redeploy to change. |
| Allowed channel | `deploy/config.py` → `ALLOWED_CHANNEL_ID` | Restrict the command to one channel (empty = anywhere). Slack registers slash commands workspace-wide, so this is enforced in-code. |
| Slack signing secret | SSM `slack-sg-bot-signing-secret` (SecureString) | From the Slack app's Basic Information page. The only secret. |

Each whitelisted person must already have an ingress rule in each target group
whose **Description equals their identifier** (the value in the whitelist).

## Deploy

The **build stack** (CI/CD pipeline + Lambda execution role) is deployed once,
manually, by an admin. Thereafter every push to `main` redeploys the **app
stack** via CodeBuild.

Run from the package root:

```bash
npm install
uv sync --extra cdk
uv run npx cdk deploy SlackBotsBuildStack    # once, by an admin
uv run npx cdk deploy SlackBotsAppStack      # or let CI do it on push to main
```

## One-time Slack app setup

1. Deploy the app stack, then copy the `SgIpUpdaterFunctionUrl` stack output.
2. Create a Slack app (https://api.slack.com/apps) in the workspace.
3. **Slash Commands** → create `/setip`, Request URL = the Function URL.
4. **OAuth & Permissions** → add the `commands` scope, install to the workspace.
5. **Basic Information** → copy the **Signing Secret** and store it in SSM
   (see `setup_parameters.sh`). Add authorized users to `WHITELIST` in
   `deploy/config.py`.

## Tests

```bash
uv sync --extra test
uv run pytest
```