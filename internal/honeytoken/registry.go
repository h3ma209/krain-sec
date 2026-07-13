package honeytoken

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/golang/glog"
)

// Stable plant IDs — unique per bait, never grant real access.
const (
	TokenBreakglass = "ht-brk-a7f3c91e"
	TokenAWSKeys    = "ht-aws-b2e84d10"
	TokenSSHKey     = "ht-ssh-c91e4472"
	TokenRunbook    = "ht-rbk-d55e102a"
)

// Canary credentials — locked / non-functional on real systems.
const (
	CanaryVPNUser = "svc-breakglass-prod"
	CanaryVPNPass = "Ks-Honey-Break-a7f3c91e!"
	CanaryAWSKey  = "AKIAIOSFODNN7HONEY01"
	CanaryAWSSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY/ht-aws-b2e84d10"
)

type Meta struct {
	ID          string
	Kind        string
	Label       string
	Filename    string
	ContentType string
}

var registry = map[string]Meta{
	TokenBreakglass: {
		ID: TokenBreakglass, Kind: "credentials", Label: "VPN break-glass",
		Filename: "VPN_Breakglass_Credentials.txt", ContentType: "text/plain; charset=utf-8",
	},
	TokenAWSKeys: {
		ID: TokenAWSKeys, Kind: "aws_keys", Label: "AWS readonly keys",
		Filename: "corp-prod-readonly.csv", ContentType: "text/csv; charset=utf-8",
	},
	TokenSSHKey: {
		ID: TokenSSHKey, Kind: "ssh_key", Label: "Deploy SSH key",
		Filename: "id_rsa", ContentType: "application/x-pem-file",
	},
	TokenRunbook: {
		ID: TokenRunbook, Kind: "runbook", Label: "Incident runbook",
		Filename: "CORP_Incident_Response_Runbook.txt", ContentType: "text/plain; charset=utf-8",
	},
}

var (
	hitMu sync.Mutex
	hits  []Hit
)

type Hit struct {
	Token  string
	Kind   string
	SrcIP  string
	Detail string
}

func Lookup(token string) (Meta, bool) {
	token = normalizeToken(token)
	m, ok := registry[token]
	return m, ok
}

func normalizeToken(token string) string {
	token = strings.TrimSpace(token)
	token = strings.TrimSuffix(token, ".gif")
	token = strings.TrimSuffix(token, ".png")
	token = strings.TrimPrefix(token, "/")
	return token
}

// BaseURL used inside planted files (beacon / verify links).
func BaseURL() string {
	if v := os.Getenv("HONEYTOKEN_BASE_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://127.0.0.1:8080"
}

func BeaconURL(token string) string {
	return fmt.Sprintf("%s/t/%s.gif", BaseURL(), token)
}

func LogHit(kind, token, srcIP, detail string) {
	token = normalizeToken(token)
	hitMu.Lock()
	hits = append(hits, Hit{Token: token, Kind: kind, SrcIP: srcIP, Detail: detail})
	hitMu.Unlock()
	glog.Warningf("HONEYTOKEN_HIT kind=%s token=%s src=%s detail=%q", kind, token, srcIP, detail)
}

func Content(token string) (string, Meta, bool) {
	m, ok := Lookup(token)
	if !ok {
		return "", Meta{}, false
	}
	switch token {
	case TokenBreakglass:
		return breakglassTXT(), m, true
	case TokenAWSKeys:
		return awsKeysCSV(), m, true
	case TokenSSHKey:
		return fakeSSHKey(), m, true
	case TokenRunbook:
		return runbookTXT(), m, true
	default:
		return "", Meta{}, false
	}
}

func breakglassTXT() string {
	return fmt.Sprintf(`# CORP break-glass credentials — PRODUCTION
# Classification: RESTRICTED
# Host plant: CORP-PROD-SRV05.internal
# Plant-ID: %s
# Rotated: 2026-07-01 · Owner: SOC on-call
#
# WARNING: Use only during declared Sev-1 when IdP SSO is unavailable.
# All use is audited. Do not copy to personal devices.

vpn_gateway: %s
idp: %s
username: %s
password: %s
otp_seed: JBSWY3DPEHPK3PXP
jump_host: %s

# Post-use verification (SOC telemetry pixel — do not remove)
verify_url: %s
`, TokenBreakglass, "CORP-PROD-VPN01.internal", "CORP-PROD-IDP01.internal",
		CanaryVPNUser, CanaryVPNPass, "CORP-PROD-JMP02.internal", BeaconURL(TokenBreakglass))
}

func awsKeysCSV() string {
	return fmt.Sprintf(`access_key_id,secret_access_key,account_alias,role,plant_id,notes
%s,%s,corp-prod,ReadOnlyAudit,%s,break-glass SIEM export — rotate after use
`, CanaryAWSKey, CanaryAWSSecret, TokenAWSKeys)
}

func fakeSSHKey() string {
	// Non-functional PEM-shaped decoy; token embedded in comment for tracking.
	return fmt.Sprintf(`-----BEGIN OPENSSH PRIVATE KEY-----
# plant-id: %s
# host: CORP-PROD-SRV05.internal → CORP-PROD-BLD09.internal
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBHoneyTokenDeployKeyPlaceholderDoNotUse%sAAAAgQDHoneyToken
DeployKeyPlaceholderMaterialNotARealKey%sAAAAAtzc2gtZW
QyNTUxOQAAACBHoneyTokenDeployKeyPlaceholderDoNotUse%sAAAAIEHoneyToken
DeployKeyPlaceholderMaterialNotARealKey%sAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
`, TokenSSHKey, TokenSSHKey, TokenSSHKey, TokenSSHKey, TokenSSHKey)
}

func runbookTXT() string {
	return fmt.Sprintf(`CORP Incident Response Runbook — Production
==========================================
Tenant: CORP-PROD-TENANT-01
Plant-ID: %s
Last updated: 2026-07-08

1. Acknowledge Sev-1 in Operations Console.
2. Isolate host via CORP-PROD-JMP02.internal.
3. Collect triage pack from affected node.
4. If IdP down, use break-glass VPN creds on CORP-PROD-SRV05
   (see Documents/VPN_Breakglass_Credentials.txt).
5. Notify #soc-warroom and page on-call.

Attachment beacon (status check):
%s
`, TokenRunbook, BeaconURL(TokenRunbook))
}

// PathToToken maps SSH/home relative paths to plant IDs.
func PathToToken(relPath string) (string, bool) {
	relPath = strings.TrimPrefix(relPath, "./")
	relPath = strings.TrimPrefix(relPath, "~/")
	relPath = strings.TrimPrefix(relPath, "/home/admin/")
	switch relPath {
	case "Documents/VPN_Breakglass_Credentials.txt":
		return TokenBreakglass, true
	case "aws_keys/corp-prod-readonly.csv":
		return TokenAWSKeys, true
	case ".config/corp/id_rsa", ".ssh/id_rsa_deploy":
		return TokenSSHKey, true
	case "Documents/CORP_Incident_Response_Runbook.txt":
		return TokenRunbook, true
	default:
		return "", false
	}
}
