//go:build tools
// +build tools

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	_ "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen"
)

const openapiFile = "openapi_latest.json"

func main() {
	// load the openapi file
	jsonFile, err := os.Open(openapiFile)
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Successfully opened ", openapiFile)
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	// read our opened jsonFile as a byte array.
	byteValue, _ := ioutil.ReadAll(jsonFile)

	// unmarshal into a map
	var m map[string]interface{}
	err = json.Unmarshal(byteValue, &m)
	if err != nil {
		fmt.Println(err)
		return
	}
}
