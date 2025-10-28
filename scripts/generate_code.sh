mkdir -p bin/openapi
echo "Generate client code..."
cd cmd/tools
echo "#################################"
echo "            GEN CODE "
echo "#################################"
go generate