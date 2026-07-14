package honeytoken

import (
	"bytes"
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
		if !ok || len(pdf) < 8000 {
			t.Fatalf("%s failed size=%d", tok, len(pdf))
		}
		if !bytes.Contains(pdf, []byte(tok)) {
			t.Fatalf("%s missing plant markers", tok)
		}
		if !bytes.Contains(pdf, []byte("Aetheris")) {
			t.Fatalf("%s missing Aetheris brand", tok)
		}
		if bytes.Contains(pdf, []byte("Krain")) {
			t.Fatalf("%s still contains Krain", tok)
		}
		// multi-page: /Count N with N > 1
		if !bytes.Contains(pdf, []byte("/Count ")) {
			t.Fatalf("%s missing page count", tok)
		}
	}
}
