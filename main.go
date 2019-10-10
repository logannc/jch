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
	"sync/atomic"
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

// type HasherAppState struct {
// 	sync.RWMutex
// 	storage []Hash
// }

func initializeServer() (http.HandlerFunc, http.HandlerFunc, http.HandlerFunc) {
	storage := make([]HashOrder, 0)
	var lock sync.RWMutex
	var runningTime uint64
	FIVE_SECONDS, err := time.ParseDuration("5s")
	if err != nil {
		panic(err)
	}

	runningTimeWrapper := func(fn http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			startTime := time.Now()
			fn(writer, req)
			// I am not 100% sure of the semantics of Go's type conversion
			// but these durations will always be small positive integers, so even the most naive type replacement works
			// (i.e., not twos complement negative numbers)
			atomic.AddUint64(&runningTime, uint64(time.Since(startTime).Microseconds()))
		}
	}

	hashPostHandler := func(writer http.ResponseWriter, req *http.Request) {
		startTime := time.Now()
		if http.MethodPost != req.Method {
			http.Error(writer, "405 Method Not Allowed", http.StatusMethodNotAllowed)
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
			// TODO : this hash does not match
			// I produce ZEHhWB65gUlzdVwtDQArEyx-KVLzp_aTaRaPlBzYRIFj6vjFdqEb0Q5B8zVKCZ0vKbZPZklJz0Fd7su2A-gf7Q==
			//                                  |     |                                                   |
			// they give ZEHhWB65gUlzdVwtDQArEyx+KVLzp/aTaRaPlBzYRIFj6vjFdqEb0Q5B8zVKCZ0vKbZPZklJz0Fd7su2A+gf7Q==
			hash := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
			order := HashOrder{availableAfter: startTime.Add(FIVE_SECONDS), hash: hash}
			lock.Lock()
			storage = append(storage, order)
			ticket := len(storage)
			lock.Unlock()
			fmt.Fprintf(writer, "%d", ticket)
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
		ticket, err := strconv.Atoi(components[2])
		if err != nil {
			http.Error(writer, "400 Bad Request - 2", http.StatusBadRequest)
			return
		}
		lock.RLock()
		if len(storage) < ticket {
			http.Error(writer, "400 Bad Request - 3", http.StatusBadRequest)
		} else {
			order := storage[ticket-1]
			if startTime.After(order.availableAfter) {
				fmt.Fprintf(writer, "%s", order.hash)
			} else {
				http.Error(writer, "400 Bad Request - 4", http.StatusBadRequest)
			}
		}
		lock.RUnlock()
	}

	hashStatsHandler := func(writer http.ResponseWriter, req *http.Request) {
		if http.MethodGet != req.Method {
			http.Error(writer, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		}
		response := StatResponse{Total: 0, Average: 0}
		lock.RLock()
		total := len(storage)
		if total > 0 {
			response = StatResponse{Total: uint(total), Average: runningTime / uint64(total)}
		}
		lock.RUnlock()
		msg, err := json.Marshal(response)
		if err != nil {
			println(msg, err)
		}
		fmt.Fprintf(writer, "%s", string(msg))
	}

	return runningTimeWrapper(hashPostHandler), hashGetHandler, hashStatsHandler
}

func main() {
	post, get, stats := initializeServer()
	http.HandleFunc("/hash", post)
	http.HandleFunc("/hash/", get)
	http.HandleFunc("/stats", stats)
	log.Fatal(http.ListenAndServe(":8000", nil))
}
