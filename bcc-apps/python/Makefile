
.PHONY: format
format:
	black .
	VERSION_CONTROL=none indent -linux  *.c

.PHONY: install-deps
install-deps:
	pip install black --user
