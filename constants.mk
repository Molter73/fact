RUST_VERSION ?= stable

FACT_TAG ?= $(shell git describe --always --tags --abbrev=10 --dirty)
FACT_VERSION ?= $(FACT_TAG)

FACT_REGISTRY ?= quay.io/mmoltras/fact
FACT_COMPENDIUM_REGISTRY ?= quay.io/mmoltras/fact-compendium

FACT_IMAGE_NAME ?= $(FACT_REGISTRY):$(FACT_TAG)
FACT_COMPENDIUM_IMAGE_NAME ?= $(FACT_COMPENDIUM_REGISTRY):$(FACT_TAG)

CLANG_FMT ?= $(shell which clang-format)

DOCKER ?= docker
