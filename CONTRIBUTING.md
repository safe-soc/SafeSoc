# Contributing to SafeSOC

Thanks for your interest in contributing. SafeSOC started as a final-year academic project and has since grown into something meant to stay maintainable and adoptable beyond that — this guide covers how to get set up and what a good pull request looks like.

## Before you start

- Check [`PRODUCT_ROADMAP.md`](PRODUCT_ROADMAP.md) and [`docs/roadmap-issues.md`](docs/roadmap-issues.md) for planned work and current status, so you're not duplicating something already in flight.
- For a substantial change (new feature, architectural change), open an issue first to discuss the approach before writing code — it saves everyone rework.
- Small fixes (typos, docs, obvious bugs) can go straight to a pull request.

## Development setup

```bash
git clone https://github.com/safe-soc/SafeSoc.git
cd SafeSoc
./scripts/install.sh          # Linux/macOS
./scripts/install.ps1         # Windows
```

This starts the full backend stack (OpenSearch, PostgreSQL, Redis, FastAPI backend, Celery worker/beat) via Docker Compose. See [`docs/deployment.md`](docs/deployment.md) for manual/non-Docker setup, and [`docs/testing.md`](docs/testing.md) for how the test suite is structured.

To provision a demo tenant with realistic data:

```bash
python injector/demo.py
```

For the frontend:

```bash
cd frontend
npm install
npm run dev
```

## Coding standards

Follow [`docs/coding-standards.md`](docs/coding-standards.md) — it documents the conventions already observed throughout the codebase (module header docstrings, the `routers/` → `services/` → `db/` layering, `core/enums.py` for fixed vocabularies, structured logging via `app.utils.logger.get_logger`, and more). New code should match the surrounding code's style, not introduce a new one.

If your change adds or modifies backend behavior, keep the relevant `docs/` file (`architecture.md`, `api-design.md`, `database-schema.md`, `requirements.md`) in sync — including moving something from **Planned**/**Partial** to **Implemented** — per this repo's Implemented/Partial/Planned documentation discipline. If it adds a new environment variable, update `.env.example` too.

## Running tests

Backend:

```bash
cd backend
pytest
```

The full suite runs offline — no live OpenSearch/Postgres/Redis/Docker required; external dependencies are mocked at their call sites. `.github/workflows/ci.yml` runs this on every push/PR.

Frontend:

```bash
cd frontend
npm run build     # tsc -b && vite build
npm run lint
```

If your change touches runtime UI behavior, also verify it manually in a browser against a running backend — the automated suite covers logic, not visual/interactive correctness.

## Commit and PR conventions

- Write commit messages that explain *why*, not just *what* — the diff already shows what changed.
- Keep commits reasonably scoped; one logical change per commit is easier to review than one commit doing five unrelated things.
- Open your PR against `main` and fill out [`.github/pull_request_template.md`](.github/pull_request_template.md) (auto-populated when you open a PR) — it includes a checklist covering docs sync, `.env.example` updates, and secrets.
- CI (`.github/workflows/ci.yml`) must pass before merge.

## Reporting bugs and requesting features

Use the issue templates under `.github/ISSUE_TEMPLATE/` when opening a new issue — they prompt for the information that's actually needed to act on a report (repro steps, environment, expected vs. actual behavior).

## Security issues

Do **not** open a public issue for a security vulnerability. See [`SECURITY.md`](SECURITY.md) for the private disclosure process.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you're expected to uphold it.
