build-ContactApp:
	GOARCH=$(GOARCH) GOOS=$(GOOS) go build -tags lambda.norpc -o $(ARTIFACTS_DIR)/bootstrap ./cmd/
