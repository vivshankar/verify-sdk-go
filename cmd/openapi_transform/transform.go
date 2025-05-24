package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const openapiFile = "openapi/openapi_latest.json"

func main() {
	dir, _ := os.Getwd()
	// load the openapi file
	jsonFile, err := os.Open(dir + "/" + openapiFile)
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
		return
	}

	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	// read our opened jsonFile as a byte array.
	byteValue, _ := io.ReadAll(jsonFile)

	// unmarshal into a map
	var m map[string]any
	err = json.Unmarshal(byteValue, &m)
	if err != nil {
		fmt.Println(err)
		return
	}

	//addNoPointerParameter(m)
	b, err := json.MarshalIndent(m, "", "    ")
	if err != nil {
		fmt.Println(err)
		return
	}
	content := string(b)
	_, err = fmt.Fprintf(os.Stdout, "%s\n", content)
	if err != nil {
		fmt.Println(err)
	}
}

/*
// can't use this because of https://github.com/oapi-codegen/oapi-codegen/issues/1302
func addNoPointerParameter(m map[string]any) {
	if typeProp, ok := m["type"].(string); ok {
		if typeProp == "string" || typeProp == "int" || typeProp == "boolean" {
			m["x-go-type-skip-optional-pointer"] = true
		} else if typeProp == "array" {
			// don't enumerate the items
			return
		}
	}

	for _, v := range m {
		switch t := v.(type) {
		case []any:
			for _, val := range t {
				if mval, ok := val.(map[string]any); ok {
					addNoPointerParameter(mval)
				}
			}
		case map[string]any:
			addNoPointerParameter(t)
		}
	}
}
*/
