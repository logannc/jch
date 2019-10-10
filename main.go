package main

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type HashOrder struct {
	availableAfter time.Time
	hash           string
}

type StatResponse struct {
	Total   uint   `json:"total"`
	Average uint64 `json:"average"`
}

type HasherAppState struct {
	sync.RWMutex
	storage     []HashOrder
	runningTime uint64
	shutdown    bool
}

func createHasherAppInstance() (http.HandlerFunc, http.HandlerFunc, http.HandlerFunc, http.HandlerFunc) {
	var state HasherAppState
	FIVE_SECONDS, err := time.ParseDuration("5s")
	if err != nil {
		panic(err)
	}

	// I originally had runningTime not be locked by the mutex for slightly increased performance
	// at the cost of the stats having a small chance of being incorrect if it was called during
	// a particularly long delay at the location indicated below.
	// In practice, this might be a trade off we're willing to make,
	// particularly to decouple logging/timing from implementation details
	// runningTimeWrapper := func(fn http.HandlerFunc) http.HandlerFunc {
	// 	return func(writer http.ResponseWriter, req *http.Request) {
	// 		startTime := time.Now()
	// 		fn(writer, req)
	//		>>> DELAY HERE
	// 		atomic.AddUint64(&state.runningTime, uint64(time.Since(startTime).Microseconds()))
	// 	}
	// }

	shutdownWrapper := func(fn http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			state.RLock()
			reject := state.shutdown
			state.RUnlock()
			if reject {
				http.Error(writer, "503 Service Unavailable", http.StatusServiceUnavailable)
			} else {
				fn(writer, req)
			}
		}
	}

	hashPostHandler := func(writer http.ResponseWriter, req *http.Request) {
		startTime := time.Now()
		if http.MethodPost != req.Method {
			http.Error(writer, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		state.RLock()
		reject := state.shutdown
		state.RUnlock()
		if reject {
			http.Error(writer, "503 Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		req.ParseForm()
		if password, present := req.Form["password"]; present {
			if len(password) != 1 {
				http.Error(writer, "400 Bad Request", http.StatusBadRequest)
				return
			}
			hasher := sha512.New()
			hasher.Write([]byte(password[0]))
			// StdEncoding instead of URLEncoding to match reference/requirements
			hash := base64.StdEncoding.EncodeToString(hasher.Sum(nil))
			order := HashOrder{availableAfter: startTime.Add(FIVE_SECONDS), hash: hash}
			state.Lock()
			state.storage = append(state.storage, order)
			ticket := len(state.storage)
			fmt.Fprintf(writer, "%d", ticket)
			// I am not 100% sure of the semantics of Go's type conversion
			// but these durations will always be small positive integers, so even the most naive type replacement works
			// (i.e., not twos complement negative numbers)
			state.runningTime += uint64(time.Since(startTime).Microseconds())
			state.Unlock()
		} else {
			http.Error(writer, "400 Bad Request", http.StatusBadRequest)
		}
	}

	hashGetHandler := func(writer http.ResponseWriter, req *http.Request) {
		startTime := time.Now()
		if http.MethodGet != req.Method {
			http.Error(writer, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		path := req.URL.Path
		components := strings.Split(path, "/")
		if (len(components) != 3) || (components[1] != "hash") {
			http.Error(writer, "400 Bad Request - 1", http.StatusBadRequest)
			return
		}
		ticket, err := strconv.Atoi(components[len(components)-1])
		if err != nil {
			http.Error(writer, "400 Bad Request - 2", http.StatusBadRequest)
			return
		}
		// Deeper go question: Is this RLock necessary?
		// It is certainly correct WITH the RLock
		// but it is also possible that it could be correct without the lock
		// it would depend on how Go handles slice reallocation and when it garbage
		// collects old slices. I know that Go intelligently reallocates
		// i.e., doubles capacity then 25% per alloc eventually
		// but I don't know what it does with the OLD one.
		// In any case, if you could guarantee that the slice wasn't garbage collected here,
		// we could omit the RLock because the storage is append only.
		state.RLock()
		if len(state.storage) < ticket {
			http.Error(writer, "400 Bad Request - 3", http.StatusBadRequest)
		} else {
			order := state.storage[ticket-1]
			if startTime.After(order.availableAfter) {
				fmt.Fprintf(writer, "%s", order.hash)
			} else {
				http.Error(writer, "400 Bad Request - 4", http.StatusBadRequest)
			}
		}
		state.RUnlock()
	}

	hashStatsHandler := func(writer http.ResponseWriter, req *http.Request) {
		if http.MethodGet != req.Method {
			http.Error(writer, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		}
		response := StatResponse{Total: 0, Average: 0}
		// Similar argument about the RLock and about runningTime not being behind a mutex.
		// we could omit them here for slight performance wins at the cost of
		// being slightly inaccurate, sometimes.
		state.RLock()
		total := len(state.storage)
		if total > 0 {
			response = StatResponse{Total: uint(total), Average: state.runningTime / uint64(total)}
		}
		state.RUnlock()
		msg, err := json.Marshal(response)
		if err != nil {
			println(msg, err)
		}
		fmt.Fprintf(writer, "%s", string(msg))
	}

	hashShutdownHandler := func(writer http.ResponseWriter, req *http.Request) {
		state.Lock()
		state.shutdown = true
		state.Unlock()
	}

	return shutdownWrapper(hashPostHandler), shutdownWrapper(hashGetHandler), shutdownWrapper(hashStatsHandler), hashShutdownHandler
}

func main() {
	post, get, stats, shutdown := createHasherAppInstance()
	http.HandleFunc("/hash", post)
	http.HandleFunc("/hash/", get)
	http.HandleFunc("/stats", stats)
	http.HandleFunc("/shutdown", shutdown)
	log.Fatal(http.ListenAndServe(":8000", nil))
}