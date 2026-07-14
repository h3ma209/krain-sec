package honeytoken

import (
	"bytes"
	"strings"
	"testing"
)

func TestManualPDFValid(t *testing.T) {
	pdf, meta, ok := ManualPDF(TokenManualSOC)
	if !ok {
		t.Fatal("expected manual")
	}
	if meta.Filename != "SOC_Console_Operator_Manual.pdf" {
		t.Fatalf("filename: %s", meta.Filename)
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF-1.4")) {
		t.Fatal("missing PDF header")
	}
	if !bytes.Contains(pdf, []byte("%%EOF")) {
		t.Fatal("missing EOF")
	}
	if !bytes.Contains(pdf, []byte(TokenManualSOC)) {
		t.Fatal("missing plant id")
	}
	if !bytes.Contains(pdf, []byte("/URI")) {
		t.Fatal("missing beacon URI annot")
	}
}

func TestManualFileName(t *testing.T) {
	tok, ok := ManualFileName("VPN_MFA_SignIn_Guide.pdf")
	if !ok || tok != TokenManualVPN {
		t.Fatalf("got %q %v", tok, ok)
	}
	if _, ok := ManualFileName("nope.pdf"); ok {
		t.Fatal("expected miss")
	}
}

func TestAllManualsBuild(t *testing.T) {
	for _, tok := range []string{TokenManualSOC, TokenManualVPN, TokenManualBG, TokenManualIR} {
		pdf, _, ok := ManualPDF(tok)
		if !ok || len(pdf) < 200 {
			t.Fatalf("%s failed", tok)
		}
		if !strings.Contains(string(pdf), "Plant-ID") && !bytes.Contains(pdf, []byte(tok)) {
			t.Fatalf("%s missing plant markers", tok)
		}
	}
}
