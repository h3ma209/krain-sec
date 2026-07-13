package internal

import (
	"net/http"
	"path"
	"strings"

	"krain-sec/internal/honeytoken"
)

// 1x1 transparent GIF
var pixelGIF = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff, 0xff,
	0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
}

func honeytokenBeacon(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/t/")
	token = path.Base(token)
	srcIP, _ := r.Context().Value("IP").(string)

	meta, ok := honeytoken.Lookup(token)
	if !ok {
		honeytoken.LogHit("beacon_unknown", token, srcIP, r.UserAgent())
		http.NotFound(w, r)
		return
	}

	honeytoken.LogHit("beacon", meta.ID, srcIP, "ua="+r.UserAgent())
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.Write(pixelGIF)
}

func honeytokenDownload(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/downloads/")
	name = path.Base(name)
	srcIP, _ := r.Context().Value("IP").(string)

	var token string
	switch name {
	case "breakglass.txt", "VPN_Breakglass_Credentials.txt":
		token = honeytoken.TokenBreakglass
	case "aws-keys.csv", "corp-prod-readonly.csv":
		token = honeytoken.TokenAWSKeys
	case "runbook.txt", "CORP_Incident_Response_Runbook.txt":
		token = honeytoken.TokenRunbook
	case "id_rsa", "id_rsa_deploy":
		token = honeytoken.TokenSSHKey
	default:
		http.NotFound(w, r)
		return
	}

	content, meta, ok := honeytoken.Content(token)
	if !ok {
		http.NotFound(w, r)
		return
	}

	honeytoken.LogHit("http_download", token, srcIP, "file="+meta.Filename)
	w.Header().Set("Content-Type", meta.ContentType)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+meta.Filename+"\"")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(content))
}
