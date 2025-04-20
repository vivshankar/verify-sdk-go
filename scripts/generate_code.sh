mkdir -p bin/openapi
echo "Modify the OpenAPI definitions to fix issues..."
go run cmd/openapi_transform/transform.go > bin/openapi/openapi.json
echo "Generate client code..."
cd cmd/tools
go generate
echo "Adding yaml tags"
cd ../..
go run cmd/gen_transform/transform.go > bin/openapi.gen.go
mv bin/openapi.gen.go internal/openapi/openapi.gen.go