package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func simpleReq[T any](client *http.Client, ctx context.Context, url string, headers map[string]string) (*T, error) {
	var decodedRes T

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	for key, value := range headers {
		req.Header.Add(key, value)
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("request failed with status: %s", res.Status)
		}
		return nil, fmt.Errorf("request failed with status: %s and body: %s", res.Status, body)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, &decodedRes)
	if err != nil {
		return nil, err
	}

	return &decodedRes, nil
}
