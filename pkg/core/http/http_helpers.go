package http

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
)

func MultipartBuffer(ctx context.Context, files map[string][]byte, fields map[string]string) (*bytes.Buffer, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	defer writer.Close()

	for fileName, data := range files {
		part, err := writer.CreateFormFile(fileName, fileName)
		if err != nil {
			return nil, err
		}

		_, err = io.Copy(part, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
	}

	for name, value := range fields {
		if err := writer.WriteField(name, value); err != nil {
			return nil, err
		}
	}

	return body, nil
}
