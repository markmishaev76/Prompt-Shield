---
on:
  issues:
    types: [opened, reopened]

permissions:
  contents: read
  issues: read
  pull-requests: read

safe-outputs:
  add-labels:
  add-comment:
    max: 1

engine: claude

tools:
  github:
---

# Issue Triage

Automatically triage and label new issues for the Prompt-Shield repository.

## Context

Prompt-Shield is a multi-layered defense system against indirect prompt injection attacks targeting AI agents. It provides:
- A 4-layer detection pipeline (trusted filter, data filter, injection detector, prompt fence)
- 65+ detection patterns for prompt injection attacks
- A GitHub Action for CI/CD integration
- A Python library and CLI tool

## Instructions

When a new issue is opened or reopened:

1. **Read the issue** title, body, and any labels already applied.

2. **Classify the issue** into one of these categories and apply the matching label:
   - `bug` — Something is broken or not working as expected
   - `enhancement` — A new feature request or improvement suggestion
   - `documentation` — Relates to docs, README, or inline documentation
   - `security` — Security vulnerability report or security-related concern
   - `detection-pattern` — Request for new detection patterns or false positive/negative reports
   - `integration` — Related to GitHub Action, GitLab webhook, or other integrations
   - `performance` — Performance issue or optimization request
   - `question` — General question about usage or behavior

3. **Assess priority** and apply one of:
   - `priority: critical` — Security vulnerabilities, data loss, or complete breakage
   - `priority: high` — Major functionality broken, blocking users
   - `priority: medium` — Important but has workaround
   - `priority: low` — Nice to have, minor issues

4. **Add a brief comment** acknowledging the issue, summarizing what category it falls into, and noting any immediate observations (e.g., "This appears to be a false positive in the base64 detection pattern" or "This looks like it relates to the trusted_filter layer").

5. If the issue mentions specific detection patterns, layers, or components, add relevant context about which part of the codebase is likely involved.

## Guidelines

- Be concise and helpful in the comment
- Don't make promises about timeline or fixes
- If the issue is unclear, label it as `question` and ask for clarification in the comment
- For security-related issues, always apply both `security` and `priority: critical` labels
