include ../constants.mk

all: pytest

pytest: grpc-gen
	pytest --image="${FACT_IMAGE_NAME}" --junit-xml=results.xml

PYOUT = $(CURDIR)

ARTIFACTS=
ARTIFACTS += ../fact-api/proto/fact-api/process.proto
ARTIFACTS += ../fact-api/proto/fact-api/file.proto
ARTIFACTS += ../fact-api/proto/fact-api/fact_iservice.proto

grpc-gen: ${ARTIFACTS}
	python3 -m grpc_tools.protoc \
		-I../fact-api/proto \
		--python_out=${PYOUT} \
		--pyi_out=${PYOUT} \
		--grpc_python_out=${PYOUT} \
		${ARTIFACTS}

clean:
	rm -rf logs/
	rm -rf logs.tar.gz
	rm -f results.xml

.PHONY: all pytest grpc-gen clean
