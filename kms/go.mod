module github.com/minio/kms-go/kms

go 1.26

toolchain go1.26.9

require (
	aead.dev/mem v0.2.0
	aead.dev/mtls v0.4.0
	google.golang.org/protobuf v1.36.12
)

tool google.golang.org/protobuf/cmd/protoc-gen-go
