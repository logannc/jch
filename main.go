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

// Response Type for /stats
type StatResponse struct {
	Total   uint   `json:"total"`
	Average uint64 `json:"average"`
}

// Type for the task queue for processing hash requests
type HashOrder struct {
	id             uint64
	availableAfter time.Time
	password       string
}

type HasherAppConfig struct {
	// number of goroutine workers
	workerCount int
	// size of buffered channel
	queueSize uint
	// whether to block or discard request when channel is full
	blockOnFullQueue bool
	// how long to wait before processing a request - time.ParseDuration(delayString)
	delayString      string
}

type HasherAppState struct {
	storage     map[uint64]string
	runningTime uint64
	// only locks `storage`, `runningTime`. The others are atomic.
	sync.RWMutex
	// the current value is the number last given out (and the number of received valid requests)
	lastId uint64
	tasks  chan HashOrder
	wg     sync.WaitGroup
}

// Returns 4 `http.HandlerFunc`s which you can mount (mostly) wherever
// you like and a waiter method to indicate all requests have been processed.
// (POST, GET, STATS, SHUTDOWN, waiter)
// POST - POST with form `password=string` to receive an id to later request the hashed password
// GET - GET /hash/<id:int> returns a previously requested hash of a password if `delayString` duration has elapsed
// STATS - GET this route to get the number of requests made and the average processing time
// SHUTDOWN - returns 'ok' and prohibits new connections. after all requests are processed, exits the server.
// waiter - use after `http.ListenAndServe()` to wait for all requests being processed to complete.
//
// As an aside, I haven't used Go recently so I'm not sure I like this closure-state approach.
// It does neatly encapsulate the application state.
// I'd also like to look into moving the function definitions out of the this
// instantiation method, creating closures which call methods defined elsewhere
// but due to my infamiliarity with Go memory semantics and time constraints,
// this will have to suffice.
func createHasherAppInstance(srv *http.Server, config HasherAppConfig) (http.HandlerFunc, http.HandlerFunc, http.HandlerFunc, http.HandlerFunc, func()) {
	var state HasherAppState
	state.storage = make(map[uint64]string)
	// I don't really like this. I believe buffered queues preallocate their
	// memory. What I'd really like is some bounded ring buffer that does not
	// preallocate memory (i.e., resizes). Unbounded queues are not good,
	// but I shouldn't need an entirely static one.
	//
	// Though, even an unbounded channel would likely be fine here for most
	// applications. Either it'll be small enough most of the time,
	// or there is a chance of spiking and you have to drop requests
	// to keep from OOMing. If the latter happens, I, personally, want
	// to avoid dropping the requests so I'd have it use Redis or something
	// to persist the queue, which would avoid this whole business.
	//
	// Of course, then you wouldn't have microsecond response times,
	// but thats the price of scale.
	state.tasks = make(chan HashOrder, config.queueSize)
	DELAY, _ := time.ParseDuration(config.delayString)

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
			availableAfter := startTime.Add(DELAY)
			order := HashOrder{id: id, availableAfter: availableAfter, password: password}
			if config.blockOnFullQueue {
				state.tasks <- order
				fmt.Fprint(writer, id)
			} else {
				select {
					case state.tasks <- order:
						fmt.Fprint(writer, id)
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
		// This part is kind of not complete.
		// I kind of wanted my implementation to be able to be mounted anywhere.
		// It just returns handlers and you mount them somewhere. But the built in
		// router is not good enough, it would let weird routes hit this handler.
		// So we do some checking to make sure that /hash/test/3 doesn't work, etc
		numComponents := len(components)
		if (numComponents != 3) || (components[numComponents-2] != "hash") {
			http.Error(writer, "400 Bad Request", http.StatusBadRequest)
			return
		}
		ticket, err := strconv.Atoi(components[numComponents-1])
		if err != nil {
			http.Error(writer, "400 Bad Request", http.StatusBadRequest)
			return
		}
		state.RLock()
		defer state.RUnlock()
		if hash, ok := state.storage[uint64(ticket)]; ok {
			fmt.Fprint(writer, hash)
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
			// I thought about returning a float
			// we're typically at like 6 microseconds on my machine, so
			// plus or minus one unit is actually kind of big.
			// But the reference returns an int.
			//
			// If we could return a float, then I might do
			// runningTime += math.Log(elapsed)
			// average = math.Exp(runningTime/processed)
			// to get the geometric mean. It handles outliers better
			// and if we're only looking at ONE statistical descriptor
			// the geometric mean or the median are going to be better.
			// If we wanted a more complete story of our processing time
			// (i.e., what percent of requests were longer than 5 seconds)
			// we would need more sophisticated techniques.
			// Alternatively, we might use some kind of moving average, etc.
			//
			// Also, Total should maybe be state.lastId?
			response = StatResponse{Total: uint(processed), Average: state.runningTime / uint64(processed)}
		}
		msg, _ := json.Marshal(response)
		fmt.Fprint(writer, string(msg))
	}

	hashShutdownHandler := func(writer http.ResponseWriter, req *http.Request) {
		fmt.Fprint(writer, "ok")
		go srv.Shutdown(context.Background()) // in goroutine so THIS response succeeds
		// does not cancel other open connections
	}

	waiter := func() {
		ONE_SECOND, _ := time.ParseDuration("1s")
		// There is a very brief period during which
		// a POST /hash request has an open TCP connection but
		// yet has not been rejected or sent a message on the channel.
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
		workerCount:      30,
		queueSize:        10000,
		blockOnFullQueue: false,
		delayString:      "5s",
	}
	post, get, stats, shutdown, waiter := createHasherAppInstance(&httpServer, config)
	http.HandleFunc("/hash", post)
	http.HandleFunc("/hash/", get)
	http.HandleFunc("/stats", stats)
	http.HandleFunc("/shutdown", shutdown)
	httpServer.ListenAndServe()
	waiter()
}
