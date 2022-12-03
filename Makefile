clean:
	rm pkg/authServer/*

gen:
	protoc --proto_path=proto proto/*.proto --go-grpc_out=pkg --go_out=pkg

test:
	go test -cover -race ./...

.PHONY: clean gen test