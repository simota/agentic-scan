.PHONY: dev test lint protos deploy-heroku

dev:
	flask --app server.app run

test:
	python -m pytest tests

lint:
	npx eslint web/src

protos:
	sh scripts/gen_protos.sh

deploy-heroku:
	git push heroku main
