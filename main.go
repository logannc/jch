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

type HasherAppState struct {
	storage      map[uint64]string
	runningTime  uint64
	sync.RWMutex        // only locks `storage`, `runningTime`. The others are atomic.
	lastId       uint64 // the current value is the number last given out (and the number of received valid requests)
	wg           sync.WaitGroup
}

func createHasherAppInstance(srv *http.Server) (http.HandlerFunc, http.HandlerFunc, http.HandlerFunc, http.HandlerFunc, func()) {
	var state HasherAppState
	state.storage = make(map[uint64]string)
	FIVE_SECONDS, _ := time.ParseDuration("5s")

	hashPostHandler := func(writer http.ResponseWriter, req *http.Request) {
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
			state.wg.Add(1)
			// At this point, I'm pretty happy with this version.
			// AVG 6 microseconds and I can't seem to saturate it, no noticeable memory growth.
			// Performance at scale is actually better than I expected.
			// Maybe because I've been writing too much Python.
			time.AfterFunc(FIVE_SECONDS, func() {
				startTime := time.Now()
				hasher := sha512.New()
				hasher.Write([]byte(password))
				// StdEncoding instead of URLEncoding to match reference/requirements
				hash := base64.StdEncoding.EncodeToString(hasher.Sum(nil))
				state.Lock()
				defer state.Unlock()
				state.storage[id] = hash
				state.runningTime += uint64(time.Since(startTime).Microseconds())
				state.wg.Done()
			})
			fmt.Fprintln(writer, id)
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
		response := StatResponse{Total: 0, Average: 0}
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
		// yet have been rejected or wg.Add(1)
		// By the time this has been called, `http.Server.Shutdown()` has been called
		// so we only need to wait long enough for all outstanding open connections
		// to get through that period, then wait on the workers.
		time.Sleep(ONE_SECOND)
		state.wg.Wait()
	}

	return hashPostHandler, hashGetHandler, hashStatsHandler, hashShutdownHandler, waiter
}

func main() {
	httpServer := http.Server{Addr: ":8000"}
	post, get, stats, shutdown, waiter := createHasherAppInstance(&httpServer)
	http.HandleFunc("/hash", post)
	http.HandleFunc("/hash/", get)
	http.HandleFunc("/stats", stats)
	http.HandleFunc("/shutdown", shutdown)
	httpServer.ListenAndServe()
	waiter()
}
