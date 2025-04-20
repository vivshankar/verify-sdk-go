package main

import (
	"fmt"
	"io"
	"os"
	"regexp"
)

const genFile = "internal/openapi/openapi.gen.go"

var (
	regexJSONTags *regexp.Regexp = regexp.MustCompile("`json:(.*)`")
)

func main() {
	dir, _ := os.Getwd()
	// load the openapi file
	f, err := os.Open(dir + "/" + genFile)
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
		return
	}

	// defer the closing of our jsonFile so that we can parse it later on
	defer f.Close()

	// read our opened jsonFile as a byte array.
	byteValue, _ := io.ReadAll(f)
	b := regexJSONTags.ReplaceAll(byteValue, []byte("`json:$1 yaml:$1`"))

	content := string(b)
	_, err = fmt.Fprintf(os.Stdout, "%s\n", content)
	if err != nil {
		fmt.Println(err)
	}
}
