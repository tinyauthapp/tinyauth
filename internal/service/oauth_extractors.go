package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"golang.org/x/oauth2"
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

type TelegramUserinfoClaims struct {
	Login string `json:"preferred_username"`
	Name  string `json:"name"`
	ID    string `json:"id"`
	jwt.RegisteredClaims
}

func defaultExtractor(client *http.Client, ctx context.Context, url string, mapClaims MapClaims) (*model.Claims, error) {
	claims, err := simpleReq[map[string]any](client, ctx, url, nil)
	if err != nil {
		return nil, err
	}
	return new(mapClaims(*claims)), nil
}

func githubExtractor(client *http.Client, ctx context.Context, _ string, _ MapClaims) (*model.Claims, error) {
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

func telegramExtractor(client *http.Client, _ context.Context, _ string, _ MapClaims) (*model.Claims, error) {
	transport, ok := client.Transport.(*oauth2.Transport)
	if !ok {
		return nil, fmt.Errorf("client transport is not oauth2.Transport")
	}

	token, err := transport.Source.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get token from source: %w", err)
	}

	rawToken := token.Extra("id_token")
	if rawToken == nil {
		return nil, fmt.Errorf("id_token absent in token response")
	}

	idToken, ok := rawToken.(string)
	if !ok {
		return nil, fmt.Errorf("id_token is not a string")
	}

	claims := TelegramUserinfoClaims{}
	jwtToken, _, err := jwt.NewParser().ParseUnverified(idToken, &claims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse jwt: %w", err)
	}
	if jwtToken.Valid {
		return nil, fmt.Errorf("token not valid")
	}

	var user model.Claims
	user.PreferredUsername = claims.Login
	user.Email = claims.ID + "@telegram"
	user.Name = claims.Name
	user.Sub = claims.Subject
	return &user, nil
}
