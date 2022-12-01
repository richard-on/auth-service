protoc-gen:
	protoc proto/*.proto --go-grpc_out=pkg --go_out=pkg