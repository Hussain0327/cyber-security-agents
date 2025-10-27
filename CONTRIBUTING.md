# Contributing

## What We’re Focused On Right Now

* [ ] **File output** — agents should actually write and update files, not just talk about it.
* [ ] **Cost** — 5 calls per task is too expensive; need smarter ways to cut that down.
* [ ] **Real tasks** — push it with bigger, multi-file changes and refactor tests.
* [ ] **Stability** — better error handling and recovery when something breaks.

## How to Get Started Fast

1. Fork the repo
2. Run `pip install -e .`
3. Copy `.env.example` to `.env` and drop in your OpenAI key
4. Run a quick task:

   ```bash
   python -m sec_agents.cli --provider openai swe run "your task"
   ```

## Where Help Matters Most

* **Testing** — Run tough, messy tasks. Break things. Tell us what failed.
* **Cost** — Smarter workflows to make each run cheaper.
* **UI** — A simple web interface so people don’t need the CLI.
* **Docs** — More examples, clear tutorials, real use cases.
