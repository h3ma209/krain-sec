package honeytoken

import (
	"fmt"
	"hash/fnv"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"
)

var dirFileTemplates = []string{
	"CORP-PROD-SRV05-syslog-%s.log",
	"CORP-PROD-SRV05-auth-%s.log.gz",
	"console-export-%s.tar.gz",
	"nginx-access-%s.log",
	"firewall-deny-%s.csv",
	"sensor-pack-%s.zip",
	"jwt-secrets-backup-%s.enc",
	"id_rsa_deploy_%s.bak",
	"vpn-breakglass-%s.txt",
	"inventory-%s.yml",
	"siem-forwarder-%s.dump",
	"okta-scim-sync-%s.json",
	"pcap-vpn-edge-%s.pcap",
	"db-snapshot-krain-%s.sql.gz",
	"audit-trail-%s.csv",
	"threat-intel-ioc-%s.txt",
	"corp-agent-config-%s.conf",
	"tls-private-%s.pem",
	"grafana-export-%s.json",
	"kubernetes-kubeconfig-%s",
}

// InfiniteDirListing serves an endless Apache-style directory index.
// "Next" / subfolder links never run out — path brute-forcers keep crawling.
func InfiniteDirListing(w http.ResponseWriter, r *http.Request) {
	page := parsePage(r)
	root := listingRoot(r.URL.Path)

	srcIP, _ := r.Context().Value("IP").(string)
	glog.Infof("dirtrap path=%s page=%d ip=%s ua=%q", r.URL.Path, page, srcIP, r.UserAgent())
	if page >= 5 {
		glog.Warningf("dirtrap deep-crawl path=%s page=%d ip=%s", r.URL.Path, page, srcIP)
	}

	now := time.Now().UTC()
	titlePath := root + "/"

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	var b strings.Builder
	b.Grow(8 << 10)
	fmt.Fprintf(&b, `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
<head><title>Index of %s</title></head>
<body>
<h1>Index of %s</h1>
<pre>Name                                           Last modified      Size  Description
<hr>
`, titlePath, titlePath)

	if page > 1 {
		fmt.Fprintf(&b, `<a href="%s/?C=%d">Parent Directory</a>
`, root, page-1)
	} else {
		fmt.Fprintf(&b, `<a href="/">Parent Directory</a>
`)
	}

	folders := []struct {
		name, href string
	}{
		{fmt.Sprintf("archive-%04d/", page), fmt.Sprintf("%s/archive-%04d/?C=%d", root, page, page+1)},
		{fmt.Sprintf("weekly-%s/", now.AddDate(0, 0, -page).Format("2006-01-02")), fmt.Sprintf("%s/weekly/?C=%d", root, page+1)},
		{"incident-exports/", fmt.Sprintf("%s/incident-exports/?C=%d", root, page+1)},
		{"console-snapshots/", fmt.Sprintf("%s/console-snapshots/?C=%d", root, page+1)},
		{".snapshot/", fmt.Sprintf("%s/.snapshot/?C=%d", root, page+1)},
	}
	for _, f := range folders {
		mod := now.Add(-time.Duration(page*7) * time.Hour).Format("02-Jan-2006 15:04")
		fmt.Fprintf(&b, `<a href="%s">%-46s</a> %s    -  
`, f.href, f.name, mod)
	}

	seed := hashSeed(root, page)
	for i := 0; i < 36; i++ {
		day := now.AddDate(0, 0, -(page*36 + i)).Format("20060102")
		tpl := dirFileTemplates[(seed+uint32(i))%uint32(len(dirFileTemplates))]
		name := fmt.Sprintf(tpl, day)
		size := fakeSize(seed, uint32(i))
		mod := now.Add(-time.Duration(page*36+i) * time.Hour).Format("02-Jan-2006 15:04")
		// File links recurse into another listing page — no dead ends.
		href := fmt.Sprintf("%s/%s?C=%d", root, name, page+1)
		fmt.Fprintf(&b, `<a href="%s">%-46s</a> %s  %6s  
`, href, name, mod, size)
	}

	fmt.Fprintf(&b, `<hr></pre>
<p><a href="%s/?C=%d">Next 40 entries &raquo;</a> &nbsp; <em>Showing offset %d</em></p>
<p><small>Apache/2.4.58 (Ubuntu) Server at %s Port 443</small></p>
</body></html>
`, root, page+1, (page-1)*40, "CORP-PROD-SRV05.internal")

	_, _ = w.Write([]byte(b.String()))
}

func parsePage(r *http.Request) int {
	for _, key := range []string{"C", "c", "page"} {
		if v := r.URL.Query().Get(key); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				return n
			}
		}
	}
	// /backup/archive-0003/page/12/ style crumbs
	parts := strings.Split(r.URL.Path, "/")
	for i, p := range parts {
		if p == "page" && i+1 < len(parts) {
			if n, err := strconv.Atoi(parts[i+1]); err == nil && n > 0 {
				return n
			}
		}
	}
	return 1
}

func listingRoot(urlPath string) string {
	urlPath = path.Clean("/" + strings.TrimPrefix(urlPath, "/"))
	parts := strings.Split(strings.Trim(urlPath, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return "/backup"
	}
	switch parts[0] {
	case "backup", "reports", "archive", "exports":
		return "/" + parts[0]
	default:
		return "/" + parts[0]
	}
}

func hashSeed(root string, page int) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(root))
	_, _ = fmt.Fprintf(h, ":%d", page)
	return h.Sum32()
}

func fakeSize(seed, i uint32) string {
	n := (seed*31 + i*17) % 900000
	switch {
	case n < 40:
		return "-"
	case n < 1024:
		return fmt.Sprintf("%d", n+64)
	case n < 1024*80:
		return fmt.Sprintf("%dK", n/1024+1)
	default:
		return fmt.Sprintf("%dM", n/(1024*200)+1)
	}
}
