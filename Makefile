.PHONY: check unit bench consumer e2e lint lint-fix

check:
	bash scripts/check.sh

lint:
	bash scripts/lint.sh run --timeout=5m ./...

lint-fix:
	bash scripts/lint.sh run --fix --timeout=5m ./...

unit:
	GOWORK=off go test -race ./...

bench:
	@test -n "$(API_TEST_DATABASE_URL)" || (echo 'API_TEST_DATABASE_URL is required' >&2; exit 1)
	GOWORK=off go test . -run '^$$' -bench 'BenchmarkPostgres' -benchmem -benchtime=500ms -count=1

consumer:
	bash scripts/consumer-probe.sh

e2e:
	bash scripts/e2e.sh
