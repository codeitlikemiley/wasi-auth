.PHONY: help provider-tools test-spicedb-live test-cedar-live test-components

help:
	@echo "Available targets:"
	@echo "  make provider-tools    - Install checksum-pinned SpiceDB and zed under target/provider-tools"
	@echo "  make test-spicedb-live - Run the real SpiceDB provider matrix"
	@echo "  make test-cedar-live   - Run the native Cedar PDP contract"
	@echo "  make test-components   - Run final-WASI component contracts"

provider-tools:
	bash ./scripts/install-provider-tools.sh

test-spicedb-live: provider-tools
	SPICEDB_BIN="$(CURDIR)/target/provider-tools/spicedb" \
	ZED_BIN="$(CURDIR)/target/provider-tools/zed" \
		bash ./scripts/test-spicedb-live.sh

test-cedar-live:
	bash ./scripts/test-cedar-pdp-live.sh

test-components:
	bash ./scripts/build-components.sh
	bash ./scripts/check-component-contracts.sh
