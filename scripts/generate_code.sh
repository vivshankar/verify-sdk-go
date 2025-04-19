mkdir -p bin/openapi
echo "Modify the OpenAPI definitions to fix issues..."
go run cmd/openapi_transform/transform.go > bin/openapi/openapi.json
echo "Generate client code..."
cd cmd/tools
go generate