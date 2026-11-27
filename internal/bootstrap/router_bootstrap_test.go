package bootstrap

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

func TestServeWaitsForActiveRequestDuringShutdown(t *testing.T) {
	const waitTimeout = 5 * time.Second

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	finishRequest := sync.OnceFunc(func() { close(releaseRequest) })
	defer finishRequest()

	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-releaseRequest
		w.WriteHeader(http.StatusNoContent)
	})}
	shutdownStarted := make(chan struct{})
	server.RegisterOnShutdown(func() { close(shutdownStarted) })

	log := logger.NewLogger().WithWriter(io.Discard)
	log.Init()
	app := &BootstrapApp{log: log}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- app.serve(listener, server, ctx, "http") }()

	requestDone := make(chan error, 1)
	go func() {
		client := &http.Client{Timeout: waitTimeout}
		response, err := client.Get("http://" + listener.Addr().String())
		if err != nil {
			requestDone <- err
			return
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			requestDone <- fmt.Errorf("unexpected response status: %s", response.Status)
			return
		}
		requestDone <- nil
	}()

	select {
	case <-requestStarted:
	case err := <-requestDone:
		t.Fatalf("request returned before reaching the handler: %v", err)
	case <-time.After(waitTimeout):
		t.Fatal("request did not reach the handler")
	}

	cancel()
	select {
	case <-shutdownStarted:
	case <-time.After(waitTimeout):
		t.Fatal("server did not start shutting down")
	}
	select {
	case err := <-serveDone:
		t.Fatalf("serve returned while the request was still active: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	finishRequest()
	if err := <-requestDone; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(waitTimeout):
		t.Fatal("serve did not return after the request finished")
	}
}
