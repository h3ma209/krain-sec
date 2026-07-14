package honeytoken

import (
	"bytes"
	"fmt"
	"strings"
)

// Manual plant IDs — linked from the public login page.
const (
	TokenManualSOC  = "ht-man-soc81e4c2"
	TokenManualVPN  = "ht-man-vpn93f1a0"
	TokenManualBG   = "ht-man-bg7c2e19"
	TokenManualIR   = "ht-man-ir4d90ab"
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

// ManualPDF returns a decoy PDF for the given manual token.
func ManualPDF(token string) ([]byte, Meta, bool) {
	m, ok := Lookup(token)
	if !ok || m.Kind != "manual" {
		return nil, Meta{}, false
	}
	var title, subtitle string
	var sections []string
	switch token {
	case TokenManualSOC:
		title = "Krain Security Operations Console"
		subtitle = "Operator Manual — CORP-PROD-TENANT-01"
		sections = []string{
			"1. Overview",
			"The Operations Console provides authenticated access to detection",
			"workspaces, case management, and endpoint telemetry for production",
			"tenants. Access requires corporate SSO or local console credentials.",
			"",
			"2. Sign-in procedure",
			"1) Browse to the console URL published by Corp Identity.",
			"2) Prefer Continue with Okta or Microsoft when available.",
			"3) If SSO is degraded, use work email + password (MFA enforced).",
			"4) Sessions expire after 1 hour of inactivity.",
			"",
			"3. Role matrix",
			"SOC Analyst  — read cases, acknowledge alerts",
			"SOC Lead     — escalate, assign, export packs",
			"Admin        — tenants, integrations, break-glass vault",
			"",
			"4. Troubleshooting",
			"Invalid credentials: reset via Corp IdP self-service, not this portal.",
			"SSO timeout: use password path; page #soc-access if IdP is down.",
			"Locked account: contact IAM after three failures.",
			"",
			"5. Related documents",
			"See VPN_MFA_SignIn_Guide.pdf and Emergency_Break_Glass_Procedure.pdf",
			"stored in the same documentation bundle.",
		}
	case TokenManualVPN:
		title = "VPN Access & MFA Sign-In Guide"
		subtitle = "Corporate Remote Access — Restricted"
		sections = []string{
			"1. Purpose",
			"This guide covers connecting to CORP-PROD-VPN01.internal before",
			"reaching the Security Operations Console and jump hosts.",
			"",
			"2. Prerequisites",
			"- Corp laptop with managed endpoint agent",
			"- Okta Verify or authenticator enrolled",
			"- Active Corp directory account",
			"",
			"3. Connection steps",
			"1) Launch Corp VPN client (GlobalProtect profile: CORP-PROD).",
			"2) Authenticate with work email; approve MFA push.",
			"3) Confirm route to 10.50.0.0/16 is installed.",
			"4) Open the Operations Console bookmark.",
			"",
			"4. Split tunnel notes",
			"DNS for *.internal must resolve via Corp DNS (CORP-PROD-DNS01).",
			"Do not disable WebRTC / browser isolation policies.",
			"",
			"5. Break-glass",
			"If IdP is unavailable during Sev-1, follow Emergency_Break_Glass_Procedure.pdf.",
			"Do not share credentials over chat or email.",
		}
	case TokenManualBG:
		title = "Emergency Break-Glass Procedure"
		subtitle = "Sev-1 IdP Outage — Audit Logged"
		sections = []string{
			"1. When to use",
			"Only during a declared Sev-1 when Corp IdP SSO is confirmed unavailable",
			"by the on-call Incident Commander.",
			"",
			"2. Retrieval",
			"Break-glass material is vaulted on CORP-PROD-SRV05.internal under",
			"Documents/VPN_Breakglass_Credentials.txt (analyst shell) and mirrored",
			"in the restricted downloads area after authentication.",
			"",
			"3. Steps",
			"1) Obtain Incident Commander approval in #soc-warroom.",
			"2) Retrieve current break-glass pack (rotated monthly).",
			"3) Connect VPN using the emergency profile.",
			"4) Access console with emergency operator account.",
			"5) File post-use ticket within 1 hour.",
			"",
			"4. Account placeholders (rotated — verify plant before use)",
			"username: " + CanaryVPNUser,
			"password: [redacted in printed copies — see live vault]",
			"jump: CORP-PROD-JMP02.internal",
			"",
			"5. Verification",
			"Open the authenticity check link below after retrieval so SOC telemetry",
			"records document use. Removing the check fails the audit control.",
		}
	case TokenManualIR:
		title = "Incident Response Quick Reference"
		subtitle = "Production — CORP-PROD-TENANT-01"
		sections = []string{
			"1. Severity",
			"Sev-1 — active ransomware / mass auth failure / IdP down",
			"Sev-2 — targeted intrusion / malware on VIP endpoint",
			"Sev-3 — phishing / single-host malware",
			"",
			"2. First 15 minutes",
			"1) Acknowledge alert in Operations Console.",
			"2) Freeze affected identity sessions in IdP.",
			"3) Isolate host via CORP-PROD-JMP02 runbook.",
			"4) Page on-call; open war-room channel.",
			"",
			"3. Evidence pack",
			"Collect: auth logs, EDR timeline, network flows, mail gateway hits.",
			"Export path (authenticated): /exports/ and /reports/ on the console host.",
			"",
			"4. Comms",
			"External statements only via Corp Comms. Never paste secrets in Slack.",
			"",
			"5. Full runbook",
			"See CORP_Incident_Response_Runbook.txt on analyst workstations and",
			"the authenticated downloads section of the console.",
		}
	default:
		return nil, Meta{}, false
	}

	body := strings.Join(sections, "\n")
	pdf := buildManualPDF(title, subtitle, body, token, BeaconURL(token))
	return pdf, m, true
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
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "(", "\\(")
	s = strings.ReplaceAll(s, ")", "\\)")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

// buildManualPDF creates a small but valid PDF with decoy procedure text,
// plant-id metadata, and a URI annotation pointing at the canary beacon.
func buildManualPDF(title, subtitle, body, plantID, beaconURL string) []byte {
	// Page content: Helvetica text lines
	var content bytes.Buffer
	content.WriteString("BT\n/F1 16 Tf\n50 750 Td\n(" + pdfEscape(title) + ") Tj\n")
	content.WriteString("0 -22 Td\n/F1 11 Tf\n(" + pdfEscape(subtitle) + ") Tj\n")
	content.WriteString("0 -28 Td\n/F1 9 Tf\n(Classification: INTERNAL — Krain Security) Tj\n")
	content.WriteString("0 -14 Td\n(Plant-ID: " + pdfEscape(plantID) + ") Tj\n")
	content.WriteString("0 -24 Td\n")

	lines := wrapLines(body, 88)
	if len(lines) > 48 {
		lines = lines[:48]
	}
	for i, line := range lines {
		if i > 0 {
			content.WriteString("0 -12 Td\n")
		}
		content.WriteString("(" + pdfEscape(line) + ") Tj\n")
	}
	content.WriteString("0 -28 Td\n/F1 9 Tf\n(Document authenticity check — click to verify with SOC telemetry:) Tj\n")
	content.WriteString("0 -14 Td\n(" + pdfEscape(beaconURL) + ") Tj\n")
	content.WriteString("ET\n")

	stream := content.Bytes()

	// Objects:
	// 1 Catalog, 2 Pages, 3 Page, 4 Font, 5 Content, 6 Annot (URI), 7 Info
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

	offsets := make([]int, 8) // 1..7

	writeObj := func(n int, body string) {
		offsets[n] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", n, body)
	}

	writeObj(1, "<< /Type /Catalog /Pages 2 0 R >>")
	writeObj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	writeObj(3, `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]
/Resources << /Font << /F1 4 0 R >> >>
/Contents 5 0 R
/Annots [6 0 R]
>>`)
	writeObj(4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

	offsets[5] = buf.Len()
	fmt.Fprintf(&buf, "5 0 obj\n<< /Length %d >>\nstream\n", len(stream))
	buf.Write(stream)
	buf.WriteString("\nendstream\nendobj\n")

	// Clickable link over lower text area → beacon (when user opens / clicks in a PDF reader)
	annot := fmt.Sprintf(`<< /Type /Annot /Subtype /Link /Rect [50 40 560 90]
/Border [0 0 0]
/A << /S /URI /URI (%s) >>
>>`, pdfEscape(beaconURL))
	writeObj(6, annot)

	info := fmt.Sprintf(`<< /Title (%s) /Author (Krain Security — Corp Docs)
/Subject (%s) /Keywords (plant-id:%s; CORP-PROD-SRV05)
/Creator (Krain Docs Portal) /Producer (Krain Internal)
>>`, pdfEscape(title), pdfEscape(subtitle), pdfEscape(plantID))
	writeObj(7, info)

	xrefPos := buf.Len()
	buf.WriteString("xref\n")
	fmt.Fprintf(&buf, "0 8\n")
	buf.WriteString("0000000000 65535 f \n")
	for i := 1; i <= 7; i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
	}
	buf.WriteString("trailer\n")
	fmt.Fprintf(&buf, "<< /Size 8 /Root 1 0 R /Info 7 0 R >>\n")
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
