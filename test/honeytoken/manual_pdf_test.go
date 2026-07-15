package honeytoken_test

import (
	"bytes"
	"testing"

	"krain-sec/internal/honeytoken"
)

func TestManualPDFValid(t *testing.T) {
	pdf, meta, ok := honeytoken.ManualPDF(honeytoken.TokenManualSOC)
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
	if !bytes.Contains(pdf, []byte(honeytoken.TokenManualSOC)) {
		t.Fatal("missing plant id")
	}
	if !bytes.Contains(pdf, []byte("/URI")) {
		t.Fatal("missing beacon URI annot")
	}
}
