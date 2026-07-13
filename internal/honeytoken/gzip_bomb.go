package honeytoken

import (
	"compress/gzip"
	"fmt"
	"net/http"
	"time"
)

func GzipBomb(w http.ResponseWriter, r *http.Request) {
	gzipWriter := gzip.NewWriter(w)
	defer gzipWriter.Close()

	chunk := make([]byte, 10*1024)
	totalLoops := 100000
	for i := 0; i < totalLoops; i++ {
		_, err := gzipWriter.Write(chunk)
		if err != nil {
			// If the attacker's tool crashes or they close the connection, stop streaming immediately
			fmt.Println("[HONEYPOT] Attacker connection disconnected or tool crashed.")
			return
		}
		time.Sleep(1 * time.Millisecond)
	}
}
