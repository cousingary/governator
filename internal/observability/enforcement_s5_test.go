package observability

import (
	"database/sql"
	_ "modernc.org/sqlite"
	"path/filepath"
	"reflect"
	"testing"
)

func TestS5EnforcementEvidenceRoundTrip(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	want := EnforcementRecord{
		RunID:                     "s5",
		Method:                    "landlock",
		NetworkNamespaced:         true,
		ProcessesObservedPeak:     2,
		LandlockABI:               3,
		KernelReadEnvelope:        []string{"/exact/tool", "/exact/lib"},
		DeclaredNetworkPolicy:     "deny",
		EnforcedNetworkPolicy:     "deny",
		NetworkAttemptObservation: "unavailable",
		NetworkDenialMechanism:    "isolated_namespace",
		DeclaredWriteRoots:        []string{"/workspace/output", "/workspace/RESULT.json"},
		ActualWriteSet:            []string{"output/result.txt"},
		DeclaredCredentialPolicy:  "none",
		ObservedCredentialAccess:  "unavailable",
		OutputConsequence:         "complete",
		Created:                   "now",
	}
	if err := RecordEnforcement(db, want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := EnforcementForRun(db, want.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("missing enforcement evidence")
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("evidence round trip got=%+v want=%+v", got, want)
	}
}
