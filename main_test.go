package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestHappyPath(t *testing.T) {
	httpServer := http.Server{Addr: ":8000"}
	config := HasherAppConfig{
		workerCount:      30,
		queueSize:        10000,
		blockOnFullQueue: false,
		delayString:      "10ms",
	}
	post, get, _, _, _ := createHasherAppInstance(&httpServer, config)

	data := url.Values{}
	data.Set("password", "angryMonkey")
	req, _ := http.NewRequest("POST", "/hash", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

	rr := httptest.NewRecorder()
	post.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Reference POST failed: got status %v instead of %v", status, http.StatusOK)
	}
	expected := "1"
	if rr.Body.String() != expected {
		t.Errorf("Reference POST failed: got body %v want %v",
			rr.Body.String(), expected)
	}

	rr = httptest.NewRecorder()
	post.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Reference POST failed: got status %v instead of %v", status, http.StatusOK)
	}
	expected = "2"
	if rr.Body.String() != expected {
		t.Errorf("Reference POST failed: got body %v want %v",
			rr.Body.String(), expected)
	}

	DELAY, _ := time.ParseDuration(config.delayString)
	DELAY = 2 * DELAY
	time.Sleep(DELAY)

	getReq, _ := http.NewRequest("GET", "/hash/1", nil)
	rr = httptest.NewRecorder()
	get.ServeHTTP(rr, getReq)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Reference POST failed: got status %v instead of %v", status, http.StatusOK)
	}
	expected = "ZEHhWB65gUlzdVwtDQArEyx+KVLzp/aTaRaPlBzYRIFj6vjFdqEb0Q5B8zVKCZ0vKbZPZklJz0Fd7su2A+gf7Q=="
	if rr.Body.String() != expected {
		t.Errorf("Reference POST failed: got body %v want %v",
			rr.Body.String(), expected)
	}
}

func TestPostNoData(t *testing.T) {
	httpServer := http.Server{Addr: ":8000"}
	config := HasherAppConfig{
		workerCount:      30,
		queueSize:        10000,
		blockOnFullQueue: false,
		delayString:      "10ms",
	}
	post, _, _, _, _ := createHasherAppInstance(&httpServer, config)

	req, _ := http.NewRequest("POST", "/hash", nil)

	rr := httptest.NewRecorder()
	post.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Reference POST failed: got status %v instead of %v", status, http.StatusOK)
	}
}

func TestPostExtraData(t *testing.T) {
	httpServer := http.Server{Addr: ":8000"}
	config := HasherAppConfig{
		workerCount:      30,
		queueSize:        10000,
		blockOnFullQueue: false,
		delayString:      "10ms",
	}
	post, _, _, _, _ := createHasherAppInstance(&httpServer, config)

	data := url.Values{}
	data.Set("password", "angryMonkey")
	data.Set("ignoreMe", "okay!")
	req, _ := http.NewRequest("POST", "/hash", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

	rr := httptest.NewRecorder()
	post.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Reference POST failed: got status %v instead of %v", status, http.StatusOK)
	}
	expected := "1"
	if rr.Body.String() != expected {
		t.Errorf("Reference POST failed: got body %v want %v",
			rr.Body.String(), expected)
	}

	data.Add("password", "uhoh")
	req, _ = http.NewRequest("POST", "/hash", bytes.NewBufferString(data.Encode()))
	rr = httptest.NewRecorder()
	post.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Reference POST failed: got status %v instead of %v", status, http.StatusBadRequest)
	}
}

func TestNotReady(t *testing.T) {
	httpServer := http.Server{Addr: ":8000"}
	config := HasherAppConfig{
		workerCount:      30,
		queueSize:        10000,
		blockOnFullQueue: false,
		delayString:      "5s",
	}
	post, get, _, _, _ := createHasherAppInstance(&httpServer, config)

	data := url.Values{}
	data.Set("password", "angryMonkey")
	req, _ := http.NewRequest("POST", "/hash", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

	rr := httptest.NewRecorder()
	post.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Reference POST failed: got status %v instead of %v", status, http.StatusOK)
	}
	expected := "1"
	if rr.Body.String() != expected {
		t.Errorf("Reference POST failed: got body %v want %v",
			rr.Body.String(), expected)
	}

	getReq, _ := http.NewRequest("GET", "/hash/1", nil)
	rr = httptest.NewRecorder()
	get.ServeHTTP(rr, getReq)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Reference POST failed: got status %v instead of %v", status, http.StatusBadRequest)
	}

	getReq, _ = http.NewRequest("GET", "/hash/2", nil)
	rr = httptest.NewRecorder()
	get.ServeHTTP(rr, getReq)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Reference POST failed: got status %v instead of %v", status, http.StatusBadRequest)
	}
}

func TestStats(t *testing.T) {
	httpServer := http.Server{Addr: ":8000"}
	config := HasherAppConfig{
		workerCount:      30,
		queueSize:        10000,
		blockOnFullQueue: false,
		delayString:      "10ms",
	}
	post, _, stats, _, _ := createHasherAppInstance(&httpServer, config)

	data := url.Values{}
	data.Set("password", "angryMonkey")
	req, _ := http.NewRequest("POST", "/hash", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

	rr := httptest.NewRecorder()
	post.ServeHTTP(rr, req)

	rr = httptest.NewRecorder()
	post.ServeHTTP(rr, req)

	rr = httptest.NewRecorder()
	post.ServeHTTP(rr, req)

	rr = httptest.NewRecorder()
	post.ServeHTTP(rr, req)

	DELAY, _ := time.ParseDuration(config.delayString)
	DELAY = 2 * DELAY
	time.Sleep(DELAY)

	statsReq, _ := http.NewRequest("GET", "/stats", nil)
	rr = httptest.NewRecorder()
	stats.ServeHTTP(rr, statsReq)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Reference POST failed: got status %v instead of %v", status, http.StatusOK)
	}

	var statResponse StatResponse
	err := json.Unmarshal(rr.Body.Bytes(), &statResponse)
	if err != nil {
		t.Error("Problem with stat response format, could not be marshalled.", err)
	}
}
