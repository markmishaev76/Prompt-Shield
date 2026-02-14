---
on:
  schedule: daily

permissions:
  contents: read
  issues: read
  pull-requests: read

safe-outputs:
  create-issue:
    title-prefix: "[repo status] "
    labels: [report]

engine: claude

tools:
  github:
---

# Daily Repo Status Report

Create a daily status report for Prompt-Shield maintainers.

## Instructions

Generate a concise daily report covering:

### Activity Summary
- New and closed issues (with counts)
- New and merged pull requests (with counts)
- Commits pushed to main (with count and key contributors)
- New releases, if any

### Detection Pattern Health
- Any issues related to false positives or false negatives
- New detection pattern requests
- Pattern coverage concerns raised in issues

### CI/CD Status
- Recent CI failures or flaky tests
- Docker build status
- Any dependency-related issues

### Security
- Any security-related issues or reports
- Prompt injection attempts detected by the self-scan workflow
- Open security items that need attention

### Action Items
- Issues that need maintainer attention (high priority, stale, or unresponded)
- PRs awaiting review
- Suggested next steps

## Format

- Use markdown with clear sections and bullet points
- Link to relevant issues and PRs using #number format
- Keep it scannable — maintainers should get the picture in under 2 minutes
- Include date in the issue title: "[repo status] Daily Report - YYYY-MM-DD"
