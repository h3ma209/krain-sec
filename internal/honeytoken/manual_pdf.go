package honeytoken

import (
	"bytes"
	"fmt"
	"strings"
)

// Manual plant IDs — linked from the public login page.
const (
	TokenManualSOC = "ht-man-soc81e4c2"
	TokenManualVPN = "ht-man-vpn93f1a0"
	TokenManualBG  = "ht-man-bg7c2e19"
	TokenManualIR  = "ht-man-ir4d90ab"
)

const (
	pdfLinesPerPage = 50
	pdfLineWidth    = 92
)

func init() {
	registry[TokenManualSOC] = Meta{
		ID: TokenManualSOC, Kind: "manual", Label: "SOC Console Operator Manual",
		Filename: "SOC_Console_Operator_Manual.pdf", ContentType: "application/pdf",
	}
	registry[TokenManualVPN] = Meta{
		ID: TokenManualVPN, Kind: "manual", Label: "VPN & MFA Sign-In Guide",
		Filename: "VPN_MFA_SignIn_Guide.pdf", ContentType: "application/pdf",
	}
	registry[TokenManualBG] = Meta{
		ID: TokenManualBG, Kind: "manual", Label: "Emergency Break-Glass Procedure",
		Filename: "Emergency_Break_Glass_Procedure.pdf", ContentType: "application/pdf",
	}
	registry[TokenManualIR] = Meta{
		ID: TokenManualIR, Kind: "manual", Label: "Incident Response Quick Reference",
		Filename: "Incident_Response_Quick_Reference.pdf", ContentType: "application/pdf",
	}
}

// ManualPDF returns a decoy multi-page PDF for the given manual token.
func ManualPDF(token string) ([]byte, Meta, bool) {
	m, ok := Lookup(token)
	if !ok || m.Kind != "manual" {
		return nil, Meta{}, false
	}
	title, subtitle, sections, ok := manualBody(token)
	if !ok {
		return nil, Meta{}, false
	}
	body := strings.Join(sections, "\n")
	pdf := buildManualPDF(title, subtitle, body, token, BeaconURL(token))
	return pdf, m, true
}

func manualBody(token string) (title, subtitle string, sections []string, ok bool) {
	switch token {
	case TokenManualSOC:
		return "Aetheris Security Operations Console",
			"Operator Manual v2026.07 - CORP-PROD-TENANT-01",
			manualSOCSections(), true
	case TokenManualVPN:
		return "Aetheris VPN Access & MFA Sign-In Guide",
			"Corporate Remote Access - RESTRICTED - CORP-PROD-VPN01",
			manualVPNSections(), true
	case TokenManualBG:
		return "Aetheris Emergency Break-Glass Procedure",
			"Sev-1 IdP Outage - Audit Logged - Doc CTRL-BG-2026-07",
			manualBGSections(), true
	case TokenManualIR:
		return "Aetheris Incident Response Quick Reference",
			"Production Playbook Extract - CORP-PROD-TENANT-01",
			manualIRSections(), true
	default:
		return "", "", nil, false
	}
}

func manualSOCSections() []string {
	lines := []string{
		"DOCUMENT CONTROL",
		"Owner: Aetheris SOC Platform Engineering",
		"Approver: Head of Detection & Response",
		"Classification: INTERNAL - Controlled Distribution",
		"Plant-ID embedded: " + TokenManualSOC,
		"Related: VPN_MFA_SignIn_Guide.pdf | Emergency_Break_Glass_Procedure.pdf",
		"Related: Incident_Response_Quick_Reference.pdf | CORP_Incident_Response_Runbook.txt",
		"Host mirror: CORP-PROD-SRV05.internal /docs/",
		"",
		"1. PURPOSE AND SCOPE",
		"This manual describes authenticated use of the Aetheris Security Operations",
		"Console for production tenant CORP-PROD-TENANT-01. It covers sign-in,",
		"workspace navigation, alert triage, case lifecycle, evidence export, and",
		"integration touchpoints with EDR, SIEM, identity, and network sensors.",
		"Out of scope: customer-facing Trust Center, marketing site, and unmanaged",
		"lab tenants (CORP-LAB-*).",
		"",
		"2. SYSTEM TOPOLOGY (LOGICAL)",
		"Edge: CORP-PROD-VPN01.internal  ->  CORP-PROD-WAF02.internal",
		"Console: CORP-PROD-SRV05.internal (this host - operations UI)",
		"IdP: CORP-PROD-IDP01.internal (primary) / CORP-PROD-IDP02.internal (DR)",
		"Jump: CORP-PROD-JMP02.internal (analyst shell / break-glass vault mirror)",
		"SIEM: CORP-PROD-SIEM01.internal (ingest) / CORP-PROD-SIEM02.internal (search)",
		"EDR console link-out: managed via integration id aeth-edr-prod-07",
		"DNS: CORP-PROD-DNS01.internal (*.internal authoritative)",
		"",
		"3. SIGN-IN PROCEDURE",
		"3.1 Preferred path",
		"1) Connect Corp VPN (see VPN_MFA_SignIn_Guide.pdf).",
		"2) Browse to the console URL from the Corp bookmarks pack.",
		"3) Sign in with work email + password.",
		"4) Complete MFA when prompted by Aetheris Identity.",
		"5) Land on Overview; confirm tenant badge CORP-PROD-TENANT-01.",
		"",
		"3.2 Degraded path (IdP slow / partial outage)",
		"1) Wait 30s; retry once.",
		"2) If still failing, page #soc-access and switch to password-only mode.",
		"3) Do NOT share passwords in chat. File ticket AETH-IAM-ACCESS.",
		"4) If IdP is fully down during Sev-1, follow Emergency_Break_Glass_Procedure.pdf.",
		"",
		"3.3 Session policy",
		"Idle timeout: 60 minutes. Absolute timeout: 8 hours.",
		"Concurrent sessions: 2 per analyst identity.",
		"Privileged Admin sessions: 30 minutes idle; require re-auth for exports.",
		"",
		"4. ROLE MATRIX",
		"Role            Capabilities",
		"--------------  --------------------------------------------------",
		"SOC Analyst     Read alerts/cases, acknowledge, add notes, limited export",
		"SOC Lead        Assign cases, escalate Sev, approve containment actions",
		"IR Specialist   Full evidence pack, isolate host, identity freeze requests",
		"Admin           Tenants, integrations, break-glass vault metadata, RBAC",
		"Auditor         Read-only cases + audit trail; no live response actions",
		"",
		"5. WORKSPACE MAP",
		"Overview     KPI strip, open Sev-1/2, sensor health, identity anomalies",
		"Incidents    Case queue with severity, assignee, MITRE tags",
		"Endpoints    Host inventory, isolation state, last check-in",
		"Network      Flow anomalies, DNS sinks, C2 watchlist hits",
		"Intel        IOC feed subscriptions, internal hunt cards",
		"Reports      Executive packs, weekly TTX summaries (/reports/)",
		"Exports      Authenticated dumps (/exports/) - rate limited + audited",
		"",
		"6. ALERT TRIAGE RUNBOOK (SUMMARY)",
		"6.1 Intake",
		"Open alert -> confirm sensor health != red -> check duplicate case 24h.",
		"If duplicate: merge notes and bump severity if new IoCs appear.",
		"",
		"6.2 Enrichment checklist",
		"[ ] User identity risk score from IdP",
		"[ ] Host EDR verdict + process tree top-10",
		"[ ] Source IP reputation (internal TI + sinkhole)",
		"[ ] Related mail gateway messages (phish bucket)",
		"[ ] VPN session correlation for remote users",
		"",
		"6.3 Decision",
		"False positive: close with reason code FP-* and feed tuning ticket.",
		"True positive: create/attach case, set severity, announce in #soc-warroom",
		"if Sev-1/2. Escalate per Incident_Response_Quick_Reference.pdf.",
		"",
		"7. CASE LIFECYCLE",
		"New -> Triaging -> Contained -> Eradicated -> Recovered -> Closed",
		"Mandatory artifacts before Closed: timeline, IoC list, lessons learned,",
		"and link to post-incident ticket AETH-PIR-YYYY-NNN.",
		"",
		"8. EVIDENCE AND EXPORTS",
		"Authenticated paths (JWT required):",
		"  /downloads/runbook.txt",
		"  /downloads/breakglass.txt (Admin + approved Sev-1 only)",
		"  /downloads/aws-keys.csv (legacy SIEM export - rotate after use)",
		"Directory traps used by automated collectors:",
		"  /reports/  /backup/  /archive/  /exports/  /logs/",
		"Do not pipe /logs/ into local tools without size limits (compressed packs).",
		"",
		"9. INTEGRATIONS REGISTER (PROD)",
		"ID                    System                 Status",
		"aeth-siem-prod-01     Splunk Enterprise      healthy",
		"aeth-edr-prod-07      Crowdstrike-class EDR  healthy",
		"aeth-idp-prod-02      Corp IdP OIDC          healthy",
		"aeth-mail-prod-03     Secure email gateway   degraded (see TTX notes)",
		"aeth-dns-prod-01      Internal DNS           healthy",
		"aeth-tick-prod-04     ITSM                   healthy",
		"",
		"10. NETWORK RANGES (ANALYST REFERENCE)",
		"10.50.0.0/16    Corp prod user + server VLAN aggregate",
		"10.50.20.0/24   SOC sensor / console VLAN",
		"10.50.30.0/24   Jump / PAM brokers",
		"10.60.0.0/16    Partner DMZ (no direct console route)",
		"192.168.88.0/24 Lab only - never route from prod VPN profile",
		"",
		"11. TROUBLESHOOTING MATRIX",
		"Symptom                      Action",
		"---------------------------  -------------------------------------------",
		"Login 401 loop               Reset via IdP; check MFA device clock",
		"Login 429                    Rate limit - wait Retry-After; page SOC eng",
		"Blank Overview               Hard refresh; clear site data; check VPN DNS",
		"Missing Incidents tab        RBAC drift - Admin reassigns role",
		"Export stuck                 Check /exports/ quota; open AETH-PLAT-EXPORT",
		"SSO button gone              Expected - password path only on this build",
		"",
		"12. CHANGE LOG (RECENT)",
		"2026-07-08  Build 2026.07.08-rc3 - MFA copy update, docs portal public",
		"2026-07-01  Break-glass vault rotation; plant tokens refreshed",
		"2026-06-15  Added WebRTC identity probe on login (privacy notice TBD)",
		"2026-05-20  Tenant CORP-PROD-TENANT-01 cutover from legacy brand",
		"",
		"13. APPENDIX A - CONTACT TREE",
		"SOC on-call:      pagerduty schedule soc-prod-primary",
		"Platform eng:     #soc-platform",
		"IAM:              #corp-iam",
		"Comms:            #corp-comms (external statements only)",
		"Email:            soc-ops@aetheris.security",
		"",
		"14. APPENDIX B - GLOSSARY",
		"Aetheris Identity  Corp identity broker fronting IdP",
		"Plant-ID           Tracking marker in controlled documents",
		"Sev-1              Business-critical active compromise / IdP outage",
		"TTX                Tabletop exercise",
		"Break-glass        Emergency credential set, time-boxed, audited",
		"",
		"15. APPENDIX C - SAMPLE ALERT NOTES TEMPLATE",
		"Title:",
		"Severity:",
		"Host / User:",
		"First seen / Last seen:",
		"IoCs:",
		"Actions taken:",
		"Next steps:",
		"References: case ID, SIEM deep link, EDR detection ID",
		"",
		"16. APPENDIX D - FAKE INTERNAL URLS (BOOKMARK THESE)",
		"https://console.aetheris.internal/dashboard",
		"https://siem.aetheris.internal/en-US/app/search",
		"https://idp.aetheris.internal/app/UserHome",
		"https://vault.aetheris.internal/ui/vault/secrets",
		"https://jmp02.aetheris.internal/guacamole/",
		"(Resolve only while on CORP-PROD VPN profile.)",
		"",
		"17. DOCUMENT AUTHENTICITY",
		"This PDF embeds a telemetry check URI. Opening or clicking the verify",
		"control records document custody in Aetheris SOC telemetry. Removing",
		"the control fails audit AETH-CTRL-DOC-07.",
	}
	return appendRabbitHole(lines, "SOC", TokenManualSOC, 8)
}

func manualVPNSections() []string {
	lines := []string{
		"DOCUMENT CONTROL",
		"Owner: Aetheris Network Access Engineering",
		"Classification: RESTRICTED",
		"Plant-ID: " + TokenManualVPN,
		"Companion docs: SOC_Console_Operator_Manual.pdf",
		"",
		"1. PURPOSE",
		"Establish encrypted remote access to Corp production networks before using",
		"the Aetheris Security Operations Console, jump hosts, and SIEM search heads.",
		"",
		"2. APPROVED CLIENTS",
		"- GlobalProtect (Windows / macOS) profile name: CORP-PROD",
		"- Always-On posture on managed Corp laptops",
		"- Contractor devices: approved browser isolation broker only (no native VPN)",
		"",
		"3. PREREQUISITES",
		"[ ] Managed endpoint agent healthy (EDR check-in < 24h)",
		"[ ] Disk encryption on",
		"[ ] MFA enrolled (Okta Verify or Corp authenticator)",
		"[ ] Directory account not disabled / password not expired",
		"[ ] Completed annual remote-access training module AETH-TRN-VPN-04",
		"",
		"4. CONNECTION STEPS (STANDARD)",
		"1) Join trusted network or cellular tether as needed.",
		"2) Launch VPN client; select CORP-PROD.",
		"3) Authenticate with work email.",
		"4) Approve MFA push within 60 seconds.",
		"5) Wait for 'Connected' and DNS suffix .internal.",
		"6) Verify routes: 10.50.0.0/16 present (see route table appendix).",
		"7) Open Operations Console bookmark.",
		"",
		"5. CONNECTION STEPS (CONTRACTOR)",
		"1) Open isolation broker URL from onboarding mail.",
		"2) Authenticate with contractor IdP federation.",
		"3) Launch published 'Aetheris Console' app shortcut only.",
		"4) Do not copy files to unmanaged endpoints.",
		"",
		"6. DNS AND SPLIT TUNNEL",
		"All *.internal queries must use CORP-PROD-DNS01.internal.",
		"Do not override DNS to 8.8.8.8 / 1.1.1.1 while on CORP-PROD.",
		"WebRTC / WebSocket to public STUN may leak path metadata; browser policies",
		"managed by Corp should remain enabled.",
		"",
		"7. PORTAL AND HOST ALIASES",
		"console.aetheris.internal     -> CORP-PROD-SRV05",
		"vpn01.aetheris.internal      -> CORP-PROD-VPN01",
		"jmp02.aetheris.internal      -> CORP-PROD-JMP02",
		"idp.aetheris.internal        -> CORP-PROD-IDP01",
		"siem.aetheris.internal       -> CORP-PROD-SIEM01",
		"",
		"8. FAILURE MODES",
		"Auth rejected: reset password at IdP; check MFA device time sync.",
		"Connected but no DNS: flush cache; reconnect; open AETH-NET-DNS.",
		"Connected but console timeout: confirm 10.50.20.0/24 route; try jmp shell.",
		"Certificate warning: STOP - escalate #corp-pki; do not bypass.",
		"",
		"9. POSTURE CHECKS (GATEWAY)",
		"The VPN portal evaluates:",
		"- Disk encryption state",
		"- EDR service running",
		"- OS patch level gate (N-1)",
		"- Forbidden: jailbroken / rooted profiles",
		"Failures redirect to remediation portal; do not use personal VPN bypass.",
		"",
		"10. APPENDIX - SAMPLE ROUTE TABLE (EXPECTED)",
		"10.50.0.0/16     via utunX   CORP-PROD",
		"10.50.20.0/24   via utunX   SOC VLAN",
		"10.50.30.0/24   via utunX   Jump VLAN",
		"Default remains local ISP except forced Corp domains.",
		"",
		"11. APPENDIX - CHANGE FREEZE WINDOWS",
		"VPN cert rotation: first Sunday monthly 02:00-04:00 UTC",
		"IdP maintenance: announced in #corp-status 72h ahead",
		"During freeze, Sev-1 break-glass follows Emergency_Break_Glass_Procedure.pdf",
		"",
		"12. AUTHENTICITY",
		"Telemetry verify URI embedded at end. Custody logged to Aetheris SOC.",
	}
	return appendRabbitHole(lines, "VPN", TokenManualVPN, 10)
}

func manualBGSections() []string {
	lines := []string{
		"DOCUMENT CONTROL",
		"Owner: Aetheris Incident Command",
		"Classification: RESTRICTED - Break-Glass",
		"Plant-ID: " + TokenManualBG,
		"Control: AETH-CTRL-BG-01",
		"",
		"1. WHEN TO USE",
		"Only during a declared Sev-1 where Corp IdP SSO/password paths are confirmed",
		"unavailable by Incident Commander (IC) AND platform engineering.",
		"Examples: IdP total outage, ransomware on identity tier, MFA provider dark.",
		"Non-examples: forgotten password, single-user lockout, routine maintenance.",
		"",
		"2. AUTHORIZATION",
		"1) IC declares Sev-1 in #soc-warroom with tag BG-AUTHORIZED.",
		"2) Two-person rule: IC + SOC Lead acknowledgment.",
		"3) Ticket AETH-BG-YYYY-NNN opened before credential retrieval.",
		"4) Post-use PIR mandatory within 24h.",
		"",
		"3. RETRIEVAL LOCATIONS",
		"Primary vault mirror (analyst shell):",
		"  CORP-PROD-SRV05.internal Documents/VPN_Breakglass_Credentials.txt",
		"Authenticated console mirror (Admin role):",
		"  /downloads/breakglass.txt",
		"Secondary envelope (sealed):",
		"  CORP-PROD-JMP02.internal /opt/aetheris/bg/CURRENT",
		"Paper safe: SOC cage - combination with Facilities on-call only",
		"",
		"4. LIVE PLACEHOLDERS (ROTATE MONTHLY - VERIFY PLANT)",
		"username: " + CanaryVPNUser,
		"password: [live vault only - printed copies redacted]",
		"otp_seed: [vault]",
		"vpn_gateway: CORP-PROD-VPN01.internal",
		"jump_host: CORP-PROD-JMP02.internal",
		"console: CORP-PROD-SRV05.internal",
		"",
		"5. EXECUTION STEPS",
		"1) Confirm BG-AUTHORIZED tag present.",
		"2) Retrieve CURRENT pack; note plant-id and rotation stamp.",
		"3) Connect emergency VPN profile CORP-PROD-BG.",
		"4) SSH/jump to JMP02; establish console session.",
		"5) Perform minimum actions to restore detection visibility.",
		"6) Do not browse personal mail or non-incident systems.",
		"7) Within 1 hour: file usage note in AETH-BG ticket.",
		"8) Within 24 hours: rotate BG secrets (platform eng).",
		"",
		"6. FORBIDDEN ACTIONS",
		"- Copying BG material to Slack, email, or USB",
		"- Reusing BG after rotation window without new authorization",
		"- Disabling audit pipelines to 'go faster'",
		"- Granting standing Admin to non-IR identities",
		"",
		"7. DETECTION COVERAGE DURING BG",
		"Expect elevated alerts: anomalous VPN geo, new PAM sessions, console Admin.",
		"Tune temporarily under change AETH-CHG-BG-*; revert after close.",
		"",
		"8. ROLLBACK",
		"After IdP recovery: force logout all BG sessions, rotate secrets, invalidate",
		"VPN profiles issued under CORP-PROD-BG, close AETH-BG ticket.",
		"",
		"9. APPENDIX - HISTORICAL DRILLS",
		"2026-06-12 TTX-BG-17: seal retrieval 4m; VPN up 6m; console 9m.",
		"2026-03-03 TTX-BG-16: paper safe delay 11m - Facilities paging improved.",
		"2025-11-20 TTX-BG-15: DNS split-brain - added checklist item 6.4.",
		"",
		"10. AUTHENTICITY",
		"Verify control URI at end of document. SOC telemetry records custody.",
	}
	return appendRabbitHole(lines, "BG", TokenManualBG, 10)
}

func manualIRSections() []string {
	lines := []string{
		"DOCUMENT CONTROL",
		"Owner: Aetheris Detection & Response",
		"Classification: INTERNAL",
		"Plant-ID: " + TokenManualIR,
		"Full runbook: CORP_Incident_Response_Runbook.txt",
		"",
		"1. SEVERITY RUBRIC",
		"Sev-1  Active ransomware, mass auth failure, IdP/VPN dark, data theft in progress",
		"Sev-2  Targeted intrusion, malware on VIP, confirmed C2, privileged abuse",
		"Sev-3  Phishing with credential use, single-host malware, low-impact abuse",
		"Sev-4  Suspicious only / needs more data",
		"",
		"2. FIRST 15 MINUTES",
		"1) Acknowledge alert in Aetheris Operations Console.",
		"2) Declare severity; if Sev-1/2 open #soc-warroom and page IC.",
		"3) Freeze risky identity sessions in IdP (or request IAM).",
		"4) Isolate host via JMP02 runbook / EDR contain.",
		"5) Preserve volatile evidence before reimage.",
		"6) Start timeline doc (Appendix C template in operator manual).",
		"",
		"3. CONTAINMENT OPTIONS",
		"Network: ACL drop on CORP-PROD-FW01 for host/subnet",
		"Host: EDR isolate / local firewall lockdown",
		"Identity: disable account, revoke refresh tokens, reset MFA",
		"Mail: purge known-bad messages at gateway",
		"DNS: sinkhole domains on CORP-PROD-DNS01",
		"",
		"4. EVIDENCE PACK",
		"Collect: IdP auth logs, EDR process tree, netflow, VPN session, mail headers,",
		"SIEM notable events, console case export.",
		"Staging paths: /exports/ and /reports/ on CORP-PROD-SRV05 (authenticated).",
		"Do not exfil packs to personal cloud.",
		"",
		"5. COMMS",
		"Internal: #soc-warroom facts only; no speculation.",
		"External: Corp Comms only. Legal + Privacy on personal data exposure.",
		"Customers: per Trust process - never ad-hoc from SOC chat.",
		"",
		"6. HANDOFF TO ERADICATION",
		"Confirm C2 dead, persistence removed, credentials rotated, detections tuned.",
		"Move case Contained -> Eradicated when IC agrees.",
		"",
		"7. RECOVERY",
		"Restore from known-good; monitor 72h heightened hunting.",
		"Close only with PIR link AETH-PIR-YYYY-NNN.",
		"",
		"8. QUICK LINKS",
		"Operator manual: SOC_Console_Operator_Manual.pdf",
		"VPN guide: VPN_MFA_SignIn_Guide.pdf",
		"Break-glass: Emergency_Break_Glass_Procedure.pdf",
		"Support: soc-ops@aetheris.security",
		"",
		"9. AUTHENTICITY",
		"Telemetry verify URI at end. Custody audited under AETH-CTRL-DOC-07.",
	}
	return appendRabbitHole(lines, "IR", TokenManualIR, 12)
}

// appendRabbitHole pads manuals with long appendix tables / fake runbooks so
// scanners and humans spend time scrolling. ASCII only.
func appendRabbitHole(base []string, kind, plant string, extraPages int) []string {
	out := append([]string{}, base...)
	out = append(out, "",
		"===========================================================================",
		"APPENDIX R - EXTENDED REFERENCE TABLES (Aetheris Security controlled)",
		"Kind="+kind+" Plant="+plant+" Generated for CORP-PROD documentation portal",
		"===========================================================================",
		"",
	)
	for page := 1; page <= extraPages; page++ {
		out = append(out,
			fmt.Sprintf("--- R.%02d CONTINUATION PAGE (%s) ---", page, kind),
			"Reviewers must initial each subsection during annual access recertification.",
			"",
		)
		for row := 1; row <= 28; row++ {
			out = append(out, fmt.Sprintf(
				"REF-%s-%02d-%02d  HOST=CORP-PROD-%s%02d.internal  VLAN=10.50.%d.0/24  OWNER=soc-tier-%d  CHECK=pending  PLANT=%s",
				kind, page, row, kind, (page*3+row)%90+10, (page+row)%40+10, (row%5)+1, plant,
			))
		}
		out = append(out, "",
			fmt.Sprintf("Notes R.%02d: Cross-check SIEM notable aeth-%s-%02d-* before marking complete.", page, strings.ToLower(kind), page),
			fmt.Sprintf("Mirror path: /archive/docs/%s/section-R%02d.md (authenticated collectors only)", kind, page),
			fmt.Sprintf("Related ticket stub: AETH-DOC-%s-%02d", kind, page),
			"",
		)
	}
	out = append(out,
		"END OF CONTROLLED DOCUMENT - Aetheris Security",
		"If you received this PDF without Plant-ID correlation, escalate #soc-platform.",
	)
	return out
}

// ManualFileName maps public /docs/ paths to plant tokens.
func ManualFileName(name string) (token string, ok bool) {
	switch name {
	case "SOC_Console_Operator_Manual.pdf", "operator-manual.pdf":
		return TokenManualSOC, true
	case "VPN_MFA_SignIn_Guide.pdf", "vpn-guide.pdf":
		return TokenManualVPN, true
	case "Emergency_Break_Glass_Procedure.pdf", "break-glass.pdf":
		return TokenManualBG, true
	case "Incident_Response_Quick_Reference.pdf", "ir-quickref.pdf":
		return TokenManualIR, true
	default:
		return "", false
	}
}

func pdfEscape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '(':
			b.WriteString(`\(`)
		case ')':
			b.WriteString(`\)`)
		case '\r', '\n':
		case '—', '–', '−':
			b.WriteByte('-')
		case '‘', '’', '‛', '`':
			b.WriteByte('\'')
		case '“', '”':
			b.WriteByte('"')
		case '…':
			b.WriteString("...")
		case ' ':
			b.WriteByte(' ')
		default:
			if r < 32 || r > 126 {
				b.WriteByte('?')
				continue
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

// buildManualPDF builds a multi-page PDF rabbit hole with per-page telemetry links.
func buildManualPDF(title, subtitle, body, plantID, beaconURL string) []byte {
	all := wrapLines(body, pdfLineWidth)
	var pages [][]string
	for i := 0; i < len(all); i += pdfLinesPerPage {
		end := i + pdfLinesPerPage
		if end > len(all) {
			end = len(all)
		}
		pages = append(pages, all[i:end])
	}
	if len(pages) == 0 {
		pages = [][]string{{"(empty)"}}
	}

	nPages := len(pages)
	// Object IDs:
	// 1 Catalog, 2 Pages, 3 Font, 4 Info
	// then for each page i: pageObj=5+i*3, content=6+i*3, annot=7+i*3
	type obj struct {
		id   int
		body []byte
	}
	var objs []obj
	add := func(id int, s string) { objs = append(objs, obj{id: id, body: []byte(s)}) }
	addBytes := func(id int, b []byte) { objs = append(objs, obj{id: id, body: b}) }

	kids := make([]string, 0, nPages)
	for i := 0; i < nPages; i++ {
		pageID := 5 + i*3
		kids = append(kids, fmt.Sprintf("%d 0 R", pageID))
	}
	add(1, "<< /Type /Catalog /Pages 2 0 R >>")
	add(2, fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), nPages))
	add(3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	add(4, fmt.Sprintf(`<< /Title (%s) /Author (Aetheris Security - Corp Docs)
/Subject (%s) /Keywords (plant-id:%s; CORP-PROD-SRV05; Aetheris)
/Creator (Aetheris Docs Portal) /Producer (Aetheris Internal)
>>`, pdfEscape(title), pdfEscape(subtitle), pdfEscape(plantID)))

	for i, pageLines := range pages {
		pageID := 5 + i*3
		contentID := 6 + i*3
		annotID := 7 + i*3

		var content bytes.Buffer
		content.WriteString("BT\n")
		if i == 0 {
			content.WriteString("/F1 14 Tf\n50 760 Td\n(" + pdfEscape(title) + ") Tj\n")
			content.WriteString("0 -16 Td\n/F1 10 Tf\n(" + pdfEscape(subtitle) + ") Tj\n")
			content.WriteString("0 -14 Td\n/F1 9 Tf\n(Classification: INTERNAL - Aetheris Security | Plant-ID: " + pdfEscape(plantID) + ") Tj\n")
			content.WriteString("0 -18 Td\n")
		} else {
			content.WriteString("/F1 9 Tf\n50 760 Td\n(" + pdfEscape(fmt.Sprintf("%s - page %d/%d - Aetheris Security", title, i+1, nPages)) + ") Tj\n")
			content.WriteString("0 -16 Td\n")
		}
		content.WriteString("/F1 8 Tf\n")
		for j, line := range pageLines {
			if j > 0 {
				content.WriteString("0 -11 Td\n")
			}
			content.WriteString("(" + pdfEscape(line) + ") Tj\n")
		}
		content.WriteString("0 -16 Td\n/F1 8 Tf\n(Verify authenticity / custody: " + pdfEscape(beaconURL) + ") Tj\n")
		content.WriteString("ET\n")
		stream := content.Bytes()

		var streamObj bytes.Buffer
		fmt.Fprintf(&streamObj, "<< /Length %d >>\nstream\n", len(stream))
		streamObj.Write(stream)
		streamObj.WriteString("endstream")
		addBytes(contentID, streamObj.Bytes())

		add(annotID, fmt.Sprintf(`<< /Type /Annot /Subtype /Link /Rect [50 28 560 55]
/Border [0 0 0]
/A << /S /URI /URI (%s) >>
>>`, pdfEscape(beaconURL)))

		add(pageID, fmt.Sprintf(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]
/Resources << /Font << /F1 3 0 R >> >>
/Contents %d 0 R
/Annots [%d 0 R]
>>`, contentID, annotID))
	}

	// Write PDF with correct xref offsets (objects may be out of numeric order).
	maxID := 4 + nPages*3
	byID := make(map[int][]byte, len(objs))
	for _, o := range objs {
		byID[o.id] = o.body
	}

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	offsets := make([]int, maxID+1)
	for id := 1; id <= maxID; id++ {
		body, exists := byID[id]
		if !exists {
			continue
		}
		offsets[id] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n", id)
		buf.Write(body)
		buf.WriteString("\nendobj\n")
	}

	xrefPos := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", maxID+1)
	buf.WriteString("0000000000 65535 f \n")
	for id := 1; id <= maxID; id++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[id])
	}
	buf.WriteString("trailer\n")
	fmt.Fprintf(&buf, "<< /Size %d /Root 1 0 R /Info 4 0 R >>\n", maxID+1)
	buf.WriteString("startxref\n")
	fmt.Fprintf(&buf, "%d\n", xrefPos)
	buf.WriteString("%%EOF\n")
	return buf.Bytes()
}

func wrapLines(text string, width int) []string {
	var out []string
	for _, para := range strings.Split(text, "\n") {
		if para == "" {
			out = append(out, "")
			continue
		}
		words := strings.Fields(para)
		var line string
		for _, w := range words {
			if line == "" {
				line = w
				continue
			}
			if len(line)+1+len(w) > width {
				out = append(out, line)
				line = w
			} else {
				line += " " + w
			}
		}
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
