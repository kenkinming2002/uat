PREFIX?=/usr/local
TARGET?=release

.PHONY: all
all:
	cargo build --profile $(TARGET)

.PHONY: install
install:
	install -D -m755 ./target/$(TARGET)/uat                    "$(PREFIX)/bin/uat"
	install -D -m644 ./data/lib/systemd/system/uat.service     "$(PREFIX)/lib/systemd/system/uat.service"
