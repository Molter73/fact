all: mock-server

mock-server: grpc-gen
	./server.py

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

.PHONY: all mock-server grpc-gen
