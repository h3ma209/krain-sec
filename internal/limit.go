package internal

import (
	"net/http"
	"os"
	"strconv"
	"sync"
)

// chanSem is a simple counting semaphore (buffered channel).
type chanSem chan struct{}

func newChanSem(n int) chanSem {
	if n < 1 {
		n = 1
	}
	return make(chanSem, n)
}

func (s chanSem) tryAcquire() bool {
	select {
	case s <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s chanSem) release() {
	select {
	case <-s:
	default:
	}
}

var (
	httpSemOnce  sync.Once
	httpSem      chanSem
	mysqlSemOnce sync.Once
	mysqlSem     chanSem
)

func envIntLimit(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return def
	}
	return n
}

func httpInflightSem() chanSem {
	httpSemOnce.Do(func() {
		httpSem = newChanSem(envIntLimit("MAX_HTTP_INFLIGHT", 64))
	})
	return httpSem
}

func mysqlDecoySem() chanSem {
	mysqlSemOnce.Do(func() {
		mysqlSem = newChanSem(envIntLimit("MAX_MYSQL_DECOY", 16))
	})
	return mysqlSem
}

// limitHTTPInflight rejects with 503 when too many requests are in flight.
func limitHTTPInflight(next http.Handler) http.Handler {
	sem := httpInflightSem()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sem.tryAcquire() {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "service busy", http.StatusServiceUnavailable)
			return
		}
		defer sem.release()
		next.ServeHTTP(w, r)
	})
}
