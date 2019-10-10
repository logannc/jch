package main

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type StatResponse struct {
	Total   uint   `json:"total"`
	Average uint64 `json:"average"`
}

type HashOrder struct {
	id             uint64
	availableAfter time.Time
	password       string
}

type HasherAppConfig struct {
	workerCount      int
	queueSize        uint
	blockOnFullQueue bool
}

type HasherAppState struct {
	storage      map[uint64]string
	runningTime  uint64
	sync.RWMutex        // only locks `storage`, `runningTime`. The others are atomic.
	lastId       uint64 // the current value is the number last given out (and the number of received valid requests)
	tasks        chan HashOrder
	wg           sync.WaitGroup
}

func createHasherAppInstance(srv *http.Server, config HasherAppConfig) (http.HandlerFunc, http.HandlerFunc, http.HandlerFunc, http.HandlerFunc, func()) {
	var state HasherAppState
	state.storage = make(map[uint64]string)
	state.tasks = make(chan HashOrder, config.queueSize)
	FIVE_SECONDS, _ := time.ParseDuration("5s")

	worker := func() {
		for order := range state.tasks {
			time.Sleep(time.Until(order.availableAfter))
			startTime := time.Now()
			hasher := sha512.New()
			hasher.Write([]byte(order.password))
			// StdEncoding instead of URLEncoding to match reference/requirements
			hash := base64.StdEncoding.EncodeToString(hasher.Sum(nil))
			state.Lock()
			state.storage[order.id] = hash
			state.runningTime += uint64(time.Since(startTime).Microseconds())
			state.Unlock()
		}
		state.wg.Done()
	}

	state.wg.Add(config.workerCount)
	for i := 0; i < config.workerCount; i++ {
		go worker()
	}

	hashPostHandler := func(writer http.ResponseWriter, req *http.Request) {
		startTime := time.Now()
		if http.MethodPost != req.Method {
			http.Error(writer, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		req.ParseForm()
		if passwords, present := req.Form["password"]; present {
			if len(passwords) != 1 {
				http.Error(writer, "400 Bad Request", http.StatusBadRequest)
				return
			}
			password := passwords[0]
			id := atomic.AddUint64(&state.lastId, 1)
			availableAfter := startTime.Add(FIVE_SECONDS)
			order := HashOrder{id: id, availableAfter: availableAfter, password: password}
			if config.blockOnFullQueue {
				state.tasks <- order
				fmt.Fprintln(writer, id)
			} else {
				select {
					case state.tasks <- order:
						fmt.Fprintln(writer, id)
					default:
						http.Error(writer, "429 Too Many Requests", http.StatusTooManyRequests)
				}
			}
		} else {
			http.Error(writer, "400 Bad Request", http.StatusBadRequest)
		}
	}

	hashGetHandler := func(writer http.ResponseWriter, req *http.Request) {
		if http.MethodGet != req.Method {
			http.Error(writer, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		path := req.URL.Path
		components := strings.Split(path, "/")
		if (len(components) != 3) || (components[1] != "hash") {
			http.Error(writer, "400 Bad Request", http.StatusBadRequest)
			return
		}
		ticket, err := strconv.Atoi(components[len(components)-1])
		if err != nil {
			http.Error(writer, "400 Bad Request", http.StatusBadRequest)
			return
		}
		state.RLock()
		defer state.RUnlock()
		if hash, ok := state.storage[uint64(ticket)]; ok {
			fmt.Fprintln(writer, hash)
		} else {
			http.Error(writer, "400 Bad Request", http.StatusBadRequest)
		}
	}

	hashStatsHandler := func(writer http.ResponseWriter, req *http.Request) {
		if http.MethodGet != req.Method {
			http.Error(writer, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		}
		var response StatResponse
		state.RLock()
		defer state.RUnlock()
		processed := len(state.storage)
		if processed > 0 {
			response = StatResponse{Total: uint(processed), Average: state.runningTime / uint64(processed)}
		}
		msg, _ := json.Marshal(response)
		fmt.Fprintln(writer, string(msg))
	}

	hashShutdownHandler := func(writer http.ResponseWriter, req *http.Request) {
		fmt.Fprintln(writer, "ok")
		go srv.Shutdown(context.Background()) // in goroutine so response succeeds
	}

	waiter := func() {
		ONE_SECOND, _ := time.ParseDuration("1s")
		// There is a very brief period during which
		// a POST /hash request can be connected but not
		// yet have been rejected or sent a message on the channel
		// By the time this has been called, `http.Server.Shutdown()` has been called
		// so we only need to wait long enough for all outstanding open connections
		// to get through that period, then wait on the workers.
		time.Sleep(ONE_SECOND)
		close(state.tasks)
		state.wg.Wait()
	}

	return hashPostHandler, hashGetHandler, hashStatsHandler, hashShutdownHandler, waiter
}

func main() {
	httpServer := http.Server{Addr: ":8000"}
	config := HasherAppConfig{
		workerCount: 20,
		queueSize: 1000,
		blockOnFullQueue: false,
	}
	post, get, stats, shutdown, waiter := createHasherAppInstance(&httpServer, config)
	http.HandleFunc("/hash", post)
	http.HandleFunc("/hash/", get)
	http.HandleFunc("/stats", stats)
	http.HandleFunc("/shutdown", shutdown)
	httpServer.ListenAndServe()
	waiter()
}
