package honeytoken

import (
	"compress/gzip"
	"net/http"
	"time"
)

func GzipBomb(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=\"CORP-PROD-SRV05-syslog.tgz\"")
	w.WriteHeader(http.StatusOK)

	gzipWriter := gzip.NewWriter(w)
	defer gzipWriter.Close()

	chunk := make([]byte, 8*1024)
	// ~16MB uncompressed budget; exit on cancel
	const totalLoops = 2000
	deadline := time.After(12 * time.Second)
	for i := 0; i < totalLoops; i++ {
		select {
		case <-r.Context().Done():
			return
		case <-deadline:
			return
		default:
		}
		if _, err := gzipWriter.Write(chunk); err != nil {
			return
		}
		if i%25 == 0 {
			time.Sleep(1 * time.Millisecond)
		}
	}
}
