module github.com/minio/kms-go/kms

go 1.24

require (
	aead.dev/mem v0.2.0
	aead.dev/mtls v0.2.1
	google.golang.org/protobuf v1.33.0
)

require github.com/google/go-cmp v0.6.0 // indirect

tool google.golang.org/protobuf/cmd/protoc-gen-go
