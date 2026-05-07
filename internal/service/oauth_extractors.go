package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/tinyauthapp/tinyauth/internal/model"
)

type GithubEmailResponse []struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

type GithubUserInfoResponse struct {
	Login string `json:"login"`
	Name  string `json:"name"`
	ID    int    `json:"id"`
}

func defaultExtractor(client *http.Client, url string) (*model.Claims, error) {
	return simpleReq[model.Claims](client, url, nil)
}

func githubExtractor(client *http.Client, _ string) (*model.Claims, error) {
	var user model.Claims

	userInfo, err := simpleReq[GithubUserInfoResponse](client, "https://api.github.com/user", map[string]string{
		"accept": "application/vnd.github+json",
	})
	if err != nil {
		return nil, err
	}

	userEmails, err := simpleReq[GithubEmailResponse](client, "https://api.github.com/user/emails", map[string]string{
		"accept": "application/vnd.github+json",
	})
	if err != nil {
		return nil, err
	}

	if len(*userEmails) == 0 {
		return nil, errors.New("no emails found")
	}

	for _, email := range *userEmails {
		if email.Primary && email.Verified {
			user.Email = email.Email
			break
		}
	}

	// Use first available email if no primary email was found
	if user.Email == "" {
		for _, email := range *userEmails {
			if email.Verified {
				user.Email = email.Email
				break
			}
		}
	}

	if user.Email == "" {
		return nil, errors.New("no verified email found")
	}

	user.PreferredUsername = userInfo.Login
	user.Name = userInfo.Name
	user.Sub = strconv.Itoa(userInfo.ID)

	return &user, nil
}

func simpleReq[T any](client *http.Client, url string, headers map[string]string) (*T, error) {
	var decodedRes T

	req, err := http.NewRequest("GET", url, nil)
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
		return nil, fmt.Errorf("request failed with status: %s", res.Status)
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
