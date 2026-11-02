include ../constants.mk

all: image

image-name:
	@echo "$(FACT_CHECKER_IMAGE_NAME)"

image:
	@test -f model.joblib || { \
		echo "model.joblib is missing; train it with train.py --save first"; \
		exit 1; \
	}
	$(DOCKER) build \
		-f Containerfile \
		-t $(FACT_CHECKER_IMAGE_NAME) \
		$(CURDIR)

benchmark:
	./checker_bench.py $(CHECKER_BENCH_ARGS)

test:
	./test_checker.py

lint:
	ruff check .
	pyright .

.PHONY: image image-name benchmark test lint all
