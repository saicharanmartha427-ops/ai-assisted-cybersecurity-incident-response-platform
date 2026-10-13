# Verification status for this ZIP revision

## Checks performed during packaging

- ZIP archive structure is readable.
- `python -m py_compile backend/app.py backend/test_backend.py` passed.
- The backend and frontend source were reviewed for the LLM configuration path.

## Not verified in this packaging environment

- Backend pytest suite: not run because Flask is not installed in the packaging environment.
- Frontend production build: not run because `frontend/node_modules` is not present and package downloads are unavailable here.
- Live Generative AI request: not run because no provider API key was supplied.
- Cloud deployment: not performed.

## Required before submission/demo

1. Install `backend/requirements-dev.txt` and run `python -m pytest -q` from `backend/`.
2. Run `npm install` and `npm run build` from `frontend/`.
3. If demonstrating live LLM enrichment, configure a valid `OPENAI_API_KEY` in `backend/.env`, restart Flask, and verify Settings reports `Configured`. Do not include `.env` or the key in the submitted ZIP/repository.
4. Demonstrate a suspicious event, inspect its LLM explanation and investigation steps, and explain that the statistical/rule detector—not the LLM—makes the initial suspicious/not-suspicious decision.
5. Change demo passwords and set a persistent random `JWT_SECRET` before any deployment.
