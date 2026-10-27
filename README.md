# Security news bot

A small Python bot that collects the day's cybersecurity news from trusted sources and writes a short
AI daily brief with links to every source. It runs once a day on GitHub Actions, for free.

**See it live:** [sanaullahniazi.com/security-news](https://sanaullahniazi.com/security-news/)

## What it does

1. Reads the RSS and Atom feeds of The Hacker News, BleepingComputer, Krebs on Security, SecurityWeek,
   The Record, CISA advisories, SANS ISC, the Google Security Blog and Schneier on Security. It keeps only
   the headline, link, date and a short excerpt, never the full article.
2. Adds the newest entries of CISA's Known Exploited Vulnerabilities catalog.
3. Asks an AI model to write a short brief in its own words from today's headlines: Google Gemini (free
   tier) with a `GEMINI_API_KEY`, or Claude with an `ANTHROPIC_API_KEY`.

Only the Python standard library is needed (plus `pip install anthropic` for Claude).

```sh
python3 scripts/security_news.py             # collect news and write the brief
python3 scripts/security_news.py --no-brief  # news only, no API key needed
```

## What's where

| Path | Contents |
|---|---|
| `scripts/security_news.py` | The bot |
| `ci/security-news.yml` | The daily GitHub Action (runs in the website repository) |
| `_data/security_news.json` | The latest collected headlines |
| `_briefs/` | The daily briefs |
| `security-news/`, `_includes/pages/security-news.html`, `_layouts/brief.html` | The web page templates |

## How this repository is kept up to date

This repository is an automatic mirror. The main copy lives in my website repository,
[Sanaullah-Niazi/portfolio](https://github.com/Sanaullah-Niazi/portfolio), and a GitHub Action copies these
files here every time the website changes. Please open an issue here for bugs or ideas: pull requests
can't be merged in this repository, because the next sync would overwrite them. I'll make the fix on the
website and it will show up here within minutes.

## License

[MIT](LICENSE) © Sana Ullah Khan. The website itself, its design and its other content are not covered by
this license.
