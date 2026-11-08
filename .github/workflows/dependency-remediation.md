---
description: |
  Weekly and on-demand dependency analysis and remediation. Groups Dependabot
  findings, updates compatible dependencies, runs the repository's real checks,
  and opens a draft PR. Never dismisses alerts or auto-merges.

on:
  schedule: weekly
  workflow_dispatch:

permissions:
  actions: read
  contents: read
  issues: read
  pull-requests: read
  security-events: read

max-turns: 6
max-ai-credits: 100
max-daily-ai-credits: 200

engine:
  id: codex
  model: deepseek-chat
  env:
    OPENAI_BASE_URL: https://api.deepseek.com/v1
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}

network: defaults

tools:
  github:
    toolsets: [repos, issues, pull_requests, code_security]
  bash: true

safe-outputs:
  create-pull-request:
    draft: true
    title-prefix: "[dependency-remediation] "
    labels: [automation, dependencies]
    max: 3
  push-to-pull-request-branch:
    target: "*"
    required-title-prefix: "[dependency-remediation] "
    max: 2
  create-issue:
    title-prefix: "[dependency-remediation] "
    labels: [automation, dependencies]
    max: 2

timeout-minutes: 30
---

# Dependency Analysis and Remediation

Analyze the repository's dependency alerts, manifests and lockfiles. Prefer
minimal, upstream-compatible updates. Do not dismiss, suppress or fabricate an
alert. Do not merge a PR or change branch protection.

## Procedure

1. Read live Dependabot alerts and the repository's declared dependency policy.
2. Group alerts by ecosystem, package and compatible upgrade family.
3. Inspect transitive chains before changing a manifest or lockfile.
4. Update only the smallest compatible set needed for the finding.
5. Run the repository's actual build, tests, formatting and security checks.
6. If checks pass, open one draft PR per compatible group with the exact commands
   and results in the PR body. Include unresolved upstream blockers explicitly.
7. If checks fail, update an existing open remediation PR or issue instead of
   creating a duplicate. Record the failing command and dependency chain.
8. Never claim an alert is fixed until the lockfile or manifest and exact-head
   checks prove it. Keep native or provider gaps as BLOCKED.
