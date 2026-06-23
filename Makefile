api-dev:
	cd apps/api && uvicorn app.main:app --reload --port 8000

web-dev:
	cd apps/web && npm run dev

api-install:
	cd apps/api && pip install -e ../../packages/rule_engine && pip install -e .

test:
	cd apps/api && pytest

compose-up:
	docker compose up --build

compose-down:
	docker compose down
