# CloakPII — Xiaohongshu SkillHub agent skill

`SKILL.md` here is the **Agent Skill** published to Xiaohongshu (小红书) SkillHub.
It teaches an AI assistant how to drive the `cloakpii` CLI to mask PII, encrypt
files (AES-256-GCM), and generate PIPL / PDPA / GDPR compliance reports.

It is a thin wrapper around this project's CLI — not a copy of the code.

## Published

| Field | Value |
|-------|-------|
| Platform | 小红书 SkillHub |
| Skill ID (immutable) | `cloakpii` |
| Platform skill_id | 2591 |
| First version | 3121 |
| Category tag | 编程开发 |
| Status | submitted (in review) |

## Updating the published skill

Edit `SKILL.md`, then re-publish with the `skillhub-upload` CLI (Node ≥ 18,
requires a prior `skillhub-upload login`):

```bash
skillhub-upload publish skillhub/cloakpii --agent --source original --tag 编程开发
```

Use `--dry-run` first to preview the payload before a real submit.
