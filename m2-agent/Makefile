AGENT   ?= http://192.168.110.185:7800
BROKER  ?= http://192.168.110.25:7700
PM      ?= http://192.168.110.185:3000

.PHONY: build test test-integration test-destructive lint

build:
	GOOS=linux GOARCH=amd64 go build -o m2-agent-linux .

test:
	go vet ./...

test-integration:
	go test -v -tags integration -timeout 60s ./test/... \
		-run . \
		-count=1 \
		2>&1 | tee test/last_run.log

test-destructive:
	TEST_DESTRUCTIVE=1 go test -v -tags integration -timeout 30s ./test/... \
		-run 'TestAgentReboot|TestAgentPoweroff' \
		-count=1

# Rebuild and redeploy to Proxmox
deploy:
	$(MAKE) build
	scp -i ~/.ssh/id_ed25519 m2-agent-linux root@192.168.110.185:/usr/local/bin/m2-agent
	ssh -i ~/.ssh/id_ed25519 root@192.168.110.185 "systemctl restart m2-agent && sleep 2 && systemctl status m2-agent --no-pager"

# Run tests immediately after deploy
deploy-test: deploy test-integration

lint:
	go vet ./...
