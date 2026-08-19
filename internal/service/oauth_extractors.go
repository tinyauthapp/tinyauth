package service

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/tinyauthapp/tinyauth/internal/model"
)

type GithubEmailResponse []struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

type GithubUserinfoResponse struct {
	Login string `json:"login"`
	Name  string `json:"name"`
	ID    int    `json:"id"`
}

func defaultExtractor(client *http.Client, ctx context.Context, url string) (*model.Claims, error) {
	return simpleReq[model.Claims](client, ctx, url, nil)
}

func githubExtractor(client *http.Client, ctx context.Context, _ string) (*model.Claims, error) {
	var user model.Claims

	userInfo, err := simpleReq[GithubUserinfoResponse](client, ctx, "https://api.github.com/user", map[string]string{
		"accept": "application/vnd.github+json",
	})
	if err != nil {
		return nil, err
	}

	userEmails, err := simpleReq[GithubEmailResponse](client, ctx, "https://api.github.com/user/emails", map[string]string{
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
