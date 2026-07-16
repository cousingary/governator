// Package stage is Governator's common subprocess launch envelope. External
// helper stages use this executor so they share the same lifecycle: resolve an
// executable, freeze an environment, launch inside a descendant-owning scope,
// wait, prove descendant extinction, and return auditable execution evidence.
package stage

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cousingary/governator/internal/containment"
	"github.com/cousingary/governator/internal/controllerenv"
	"github.com/cousingary/governator/internal/enforce"
	"github.com/cousingary/governator/internal/toolregistry"
)

type ExecutableIdentity struct {
	CanonicalPath string `json:"canonical_path"`
	SHA256        string `json:"sha256,omitempty"`
}

type FrozenEnvironment struct {
	Values []string `json:"values"`
	Hash   string   `json:"hash"`
}

type NetworkPolicy string

const (
	NetworkPolicyUnspecified NetworkPolicy = "unspecified"
	NetworkPolicyDenied      NetworkPolicy = "deny"
	NetworkPolicyAllowed     NetworkPolicy = "allow"
)

type CredentialPolicy string

const (
	CredentialPolicyNone     CredentialPolicy = "none"
	CredentialPolicyDeclared CredentialPolicy = "declared"
)

type DescendantPolicy struct {
	RequireStrong bool `json:"require_strong"`
}

type EffectLedger struct {
	ScopeMethod          string   `json:"scope_method,omitempty"`
	WorkspaceFDScanClean bool     `json:"workspace_fd_scan_clean"`
	LandlockABI          int      `json:"landlock_abi,omitempty"`
	KernelReadEnvelope   []string `json:"kernel_read_envelope,omitempty"`
}

// CommandFactory lets callers with already-sealed launch logic build the exact
// *exec.Cmd while still receiving the scope the stage executor owns, plus the
// stage's EnforcementPlan so a handle-aware caller can compose the wrap
// AROUND its resolved (sealed/fd) launch target rather than having Run
// pre-wrap a bin/args pair that the caller is about to replace anyway (Sol
// redteam v7 HS2: the sealed-executable handle discarding the enforce wrap).
type CommandFactory func(ctx context.Context, scope *containment.Scope, plan enforce.Plan, bin string, args []string, dir string) (*exec.Cmd, error)

type StageSpec struct {
	RunID, StageID   string
	Executable       ExecutableIdentity
	Arguments        []string
	WorkingDirectory string
	Environment      FrozenEnvironment
	ReadRoots        []string
	WriteRoots       []string
	NetworkPolicy    NetworkPolicy
	CredentialPolicy CredentialPolicy
	Timeout          time.Duration
	OutputLimit      int64
	DescendantPolicy DescendantPolicy
	EnforcementPlan  enforce.Plan
	Stdin            io.Reader
	Stdout           io.Writer
	Stderr           io.Writer
	CommandFactory   CommandFactory
	ExecutableHandle *toolregistry.Handle
}

type StageResult struct {
	ExitStatus         int                `json:"exit_status"`
	ExecutableIdentity ExecutableIdentity `json:"executable_identity"`
	EnvironmentHash    string             `json:"environment_hash"`
	ObservedEffects    EffectLedger       `json:"observed_effects"`
	OutputTruncated    bool               `json:"output_truncated"`
	DescendantsGone    bool               `json:"descendants_gone"`
	Output             string             `json:"output,omitempty"`
}

type Executor struct{}

func NewExecutor() Executor { return Executor{} }

func (Executor) Run(ctx context.Context, spec StageSpec) (StageResult, error) {
	if strings.TrimSpace(spec.RunID) == "" {
		return StageResult{}, fmt.Errorf("stage: missing run id")
	}
	if strings.TrimSpace(spec.StageID) == "" {
		return StageResult{}, fmt.Errorf("stage: missing stage id")
	}
	if strings.TrimSpace(spec.Executable.CanonicalPath) == "" {
		return StageResult{}, fmt.Errorf("stage: missing executable path")
	}
	if spec.Environment.Values == nil {
		return StageResult{}, fmt.Errorf("stage: missing frozen environment")
	}
	if spec.Environment.Hash == "" || spec.Environment.Hash != controllerenv.Hash(spec.Environment.Values) {
		return StageResult{}, fmt.Errorf("stage: frozen environment hash mismatch")
	}
	effectivePlan, err := spec.EnforcementPlan.WithExecutableAndReadRoots(spec.Executable.CanonicalPath, spec.ReadRoots...)
	if err != nil {
		return StageResult{}, fmt.Errorf("stage: resolve read policy: %w", err)
	}
	if spec.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, spec.Timeout)
		defer cancel()
	}
	scope, err := containment.NewScope(spec.RunID+"-"+spec.StageID+"-"+nonce(), spec.DescendantPolicy.RequireStrong)
	if err != nil {
		return StageResult{}, err
	}
	bin := spec.Executable.CanonicalPath
	args := append([]string(nil), spec.Arguments...)
	factory := spec.CommandFactory
	if factory == nil && spec.ExecutableHandle != nil {
		factory = func(c context.Context, s *containment.Scope, p enforce.Plan, b string, a []string, d string) (*exec.Cmd, error) {
			return spec.ExecutableHandle.CommandWith(c, a, func(cc context.Context, sealed string, sealedArgs []string) *exec.Cmd {
				if p.Active {
					sealed, sealedArgs = p.Wrap(sealed, sealedArgs)
				}
				return s.Command(cc, sealed, sealedArgs, d)
			})
		}
	}
	if factory == nil {
		// No handle-aware caller -- this stage's Executable is a plain
		// resolved path (validators, graph provider, Assayer's own
		// non-backend stages), so the wrap is applied directly to it here.
		factory = func(c context.Context, s *containment.Scope, p enforce.Plan, b string, a []string, d string) (*exec.Cmd, error) {
			if p.Active {
				b, a = p.Wrap(b, a)
			}
			return s.Command(c, b, a, d), nil
		}
	}
	cmd, err := factory(ctx, scope, effectivePlan, bin, args, spec.WorkingDirectory)
	if err != nil {
		return StageResult{}, err
	}
	cmd.Env = append([]string(nil), spec.Environment.Values...)
	if spec.Stdin != nil {
		cmd.Stdin = spec.Stdin
	}
	var capture bytes.Buffer
	stdout := io.Writer(&capture)
	stderr := io.Writer(&capture)
	if spec.Stdout != nil {
		stdout = io.MultiWriter(spec.Stdout, &capture)
	}
	if spec.Stderr != nil {
		stderr = io.MultiWriter(spec.Stderr, &capture)
	}
	lwOut := &limitWriter{w: stdout, remaining: spec.OutputLimit}
	lwErr := &limitWriter{w: stderr, remaining: spec.OutputLimit}
	if spec.OutputLimit > 0 {
		stdout = lwOut
		stderr = lwErr
	}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	exit := 0
	var runErr error
	if err := cmd.Start(); err != nil {
		exit = -1
		runErr = err
	} else {
		if cmd.Process != nil {
			scope.Started(cmd.Process.Pid)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					exit = ee.ExitCode()
				} else {
					exit = -1
					runErr = err
				}
			}
		case <-ctx.Done():
			exit = -1
			runErr = ctx.Err()
			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
			<-done
		}
	}
	proof, extinctionErr := scope.Extinguish(context.Background(), containment.DefaultExtinctionDeadline, spec.WorkingDirectory)
	res := StageResult{
		ExitStatus:         exit,
		ExecutableIdentity: spec.Executable,
		EnvironmentHash:    spec.Environment.Hash,
		ObservedEffects: EffectLedger{
			ScopeMethod:          string(proof.Method),
			WorkspaceFDScanClean: proof.WorkspaceFDScanClean,
			LandlockABI:          effectivePlan.LandlockABI, KernelReadEnvelope: append([]string(nil), effectivePlan.ReadRoots...),
		},
		OutputTruncated: spec.OutputLimit > 0 && (lwOut.truncated || lwErr.truncated),
		DescendantsGone: extinctionErr == nil,
		Output:          capture.String(),
	}
	if extinctionErr != nil {
		return res, extinctionErr
	}
	return res, runErr
}

type limitWriter struct {
	w         io.Writer
	remaining int64
	truncated bool
}

func (l *limitWriter) Write(p []byte) (int, error) {
	orig := len(p)
	if l.remaining <= 0 {
		l.truncated = true
		return orig, nil
	}
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
		l.truncated = true
	}
	n, err := l.w.Write(p)
	l.remaining -= int64(n)
	if err != nil {
		return n, err
	}
	return orig, nil
}

func HashExecutable(path string) (ExecutableIdentity, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return ExecutableIdentity{}, err
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return ExecutableIdentity{}, err
	}
	sum := sha256.Sum256(b)
	return ExecutableIdentity{CanonicalPath: abs, SHA256: hex.EncodeToString(sum[:])}, nil
}

func nonce() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
