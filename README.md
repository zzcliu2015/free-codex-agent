# free-codex-agent

A local batch tool for Codex Agent Identity generation and optional sub2api import.

## Features

- Batch import multiple `accessToken`, `session.json`, or existing `auth.json` files.
- Register and export multiple Agent Identity `auth.json` files.
- Export local summaries: `summary.json`, `summary.csv`, and `errors.jsonl`.
- Web UI with upload/paste input, real-time logs, stop button, and saved sub2api config.
- Optional immediate import to a selected sub2api group after each successful registration.
- Test sub2api connection, load groups, and test imported accounts.

## Install

```bash
pip install -r requirements.txt
```

## Start Web UI

```bash
python codex_agent_web.py
```

Default URL:

```text
http://127.0.0.1:8765
```

## CLI Usage

Generate locally:

```bash
python codex_agent.py --batch tokens.txt --out-dir results
```

Generate and import to sub2api:

```bash
python codex_agent.py ^
  --batch tokens.txt ^
  --out-dir results ^
  --sub-url "https://your-sub-url" ^
  --sub-email "admin@example.com" ^
  --sub-import ^
  --sub-group-id 3
```

Test sub2api connection:

```bash
python codex_agent.py ^
  --sub-url "https://your-sub-url" ^
  --sub-email "admin@example.com" ^
  --sub-test
```

## sub2api APIs Used

- `POST /api/v1/auth/login`
- `GET /api/v1/admin/groups/all`
- `POST /api/v1/admin/accounts/import/codex-session`
- `POST /api/v1/admin/accounts/:id/test`

## Output Layout

```text
results/
  YYYYMMDD-HHMMSS/
    auth/
      001_xxx_auth.json
    sub_import_payload.json
    sub_import_result.json
    summary.json
    summary.csv
    errors.jsonl
```

## Security Notes

- `auth.json` and `*_auth.json` contain `agent_private_key`; do not commit them.
- `results/`, token files, session files, and generated auth files are ignored by `.gitignore`.
- The Web UI saves only sub2api config in browser `localStorage`; it does not save pasted AT content.

## 熊猫GPT交流

Scan the QR code to join the community:

![熊猫GPT交流群二维码](web_assets/qr_group.png)

群号: `1106538918`
