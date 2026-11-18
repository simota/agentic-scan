#!/bin/sh
# Generate gRPC stubs from proto/ (the proto/ directory was removed in 2024).
protoc --python_out=server/gen proto/*.proto
