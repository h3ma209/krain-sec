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

	chunk := make([]byte, 10*1024)
	// ~50MB uncompressed max; stop early on client cancel or short deadline
	const totalLoops = 5000
	for i := 0; i < totalLoops; i++ {
		select {
		case <-r.Context().Done():
			return
		default:
		}
		if _, err := gzipWriter.Write(chunk); err != nil {
			return
		}
		if i%50 == 0 {
			time.Sleep(1 * time.Millisecond)
		}
	}
}
