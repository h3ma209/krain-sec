package internal

// Production-style identifiers. Honeypot sits one hop past live peers
// (e.g. CORP-PROD-SRV04.internal → this node is SRV05).
const (
	HostFQDN   = "CORP-PROD-SRV05.internal"
	HostShort  = "CORP-PROD-SRV05"
	Domain     = "internal"
	OrgUnit    = "CORP"
	Env        = "PROD"
	TenantID   = "CORP-PROD-TENANT-01"
	SSHVersion = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
)

// Fleet peers shown in decoy UI / MOTD — sequential, same naming standard.
const (
	PeerSRV04 = "CORP-PROD-SRV04.internal"
	PeerWS042 = "CORP-PROD-WS042.internal"
	PeerVPN01 = "CORP-PROD-VPN01.internal"
	PeerIDP01 = "CORP-PROD-IDP01.internal"
	PeerBLD09 = "CORP-PROD-BLD09.internal"
	PeerJMP02 = "CORP-PROD-JMP02.internal"
)
