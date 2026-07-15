package honeytoken_test

import (
	"bytes"
	"testing"

	"krain-sec/internal/honeytoken"
)

func TestAllManualsBuild(t *testing.T) {
	tokens := []string{
		honeytoken.TokenManualSOC,
		honeytoken.TokenManualVPN,
		honeytoken.TokenManualBG,
		honeytoken.TokenManualIR,
	}
	for _, tok := range tokens {
		pdf, _, ok := honeytoken.ManualPDF(tok)
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
		if !bytes.Contains(pdf, []byte("/Count ")) {
			t.Fatalf("%s missing page count", tok)
		}
	}
}
