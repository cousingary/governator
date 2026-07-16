package runtime

import (
	"fmt"
	"github.com/cousingary/governator/internal/contextgraph"
	"github.com/cousingary/governator/internal/toolregistry"
	"os"
	goruntime "runtime"
	"sort"
	"strings"
)

// ExecutionIdentityV2 names the strict replay identity introduced by S6.
type ExecutionIdentityV2 = ExecutionIdentity

type ExecutableIdentity struct {
	Role, CanonicalPath, SHA256               string
	Device, Inode                             uint64
	OwnerUID, OwnerGID, Mode                  uint32
	Version, PackageIdentity, EnvironmentHash string
	Known, NotApplicable                      bool
}
type TransactionSnapshot struct {
	ContractHash, ConfigHash                                                string
	ProtectedPatterns                                                       []string
	GraphSnapshotHash, ExactPrompt, EnvironmentHash, CredentialIdentityHash string
	Participants                                                            map[string]ExecutableIdentity
	Artifacts                                                               []stagedArtifact
}

func newTransactionSnapshot(contractHash, configHash string, patterns []string, graphHash, prompt, envHash, credentialHash string, participants map[string]ExecutableIdentity, artifacts []stagedArtifact) TransactionSnapshot {
	p := make(map[string]ExecutableIdentity, len(participants))
	for role, identity := range participants {
		p[role] = identity
	}
	a := make([]stagedArtifact, len(artifacts))
	for i, artifact := range artifacts {
		a[i] = artifact
		a[i].data = append([]byte(nil), artifact.data...)
	}
	return TransactionSnapshot{ContractHash: contractHash, ConfigHash: configHash, ProtectedPatterns: append([]string(nil), patterns...), GraphSnapshotHash: graphHash, ExactPrompt: prompt, EnvironmentHash: envHash, CredentialIdentityHash: credentialHash, Participants: p, Artifacts: a}
}

var participantRoles = []string{"governator_self", "git", "shell", "python", "docker_cli", "docker_daemon", "unshare", "systemd_run", "backend", "validator_tools", "validator_scripts", "assayer", "assayer_profile", "assayer_checks", "graph_provider", "formatter", "linter"}

func notApplicable(role string) ExecutableIdentity {
	return ExecutableIdentity{Role: role, Known: true, NotApplicable: true}
}
func participantFromRegistry(role string, id toolregistry.Identity, env string) ExecutableIdentity {
	return ExecutableIdentity{Role: role, CanonicalPath: id.CanonicalPath, SHA256: id.SHA256, Device: id.Device, Inode: id.Inode, OwnerUID: id.OwnerUID, OwnerGID: id.OwnerGID, Mode: uint32(id.Mode.Perm()), EnvironmentHash: env, Known: id.SHA256 != "" && id.CanonicalPath != ""}
}
func resolvedParticipants(reg *toolregistry.Registry, backend toolregistry.Identity, graph contextgraph.Status, env, validator, assayer string) map[string]ExecutableIdentity {
	out := make(map[string]ExecutableIdentity, len(participantRoles))
	for _, role := range participantRoles {
		out[role] = notApplicable(role)
	}
	if goruntime.GOOS == "linux" {
		if info, err := os.Stat("/proc/self/exe"); err == nil {
			out["governator_self"] = ExecutableIdentity{Role: "governator_self", CanonicalPath: "/proc/self/exe", SHA256: governatorSelfSHA256(), Mode: uint32(info.Mode().Perm()), Known: true}
		}
	}
	names := map[string]string{"git": "git", "bash": "shell", "python3": "python", "docker": "docker_cli", "unshare": "unshare", "systemd-run": "systemd_run"}
	for name, role := range names {
		entry, ok := reg.Entry(name)
		if !ok || strings.TrimSpace(entry.Path) == "" {
			if role == "git" || role == "shell" {
				out[role] = ExecutableIdentity{Role: role, Known: false}
			}
			continue
		}
		if id, err := reg.Resolve(name, name); err == nil {
			out[role] = participantFromRegistry(role, id, env)
		} else {
			out[role] = ExecutableIdentity{Role: role}
		}
	}
	out["backend"] = participantFromRegistry("backend", backend, env)
	if graph.Enabled {
		out["graph_provider"] = ExecutableIdentity{Role: "graph_provider", CanonicalPath: graph.Path, SHA256: graph.SHA256, EnvironmentHash: env, Known: graph.Path != "" && graph.SHA256 != ""}
	}
	if validator != "" && validator != "unknown" {
		out["validator_tools"] = ExecutableIdentity{Role: "validator_tools", SHA256: validator, EnvironmentHash: env, Known: true}
		out["validator_scripts"] = ExecutableIdentity{Role: "validator_scripts", SHA256: validator, Known: true}
	}
	if assayer != "" && assayer != "unknown" {
		for _, role := range []string{"assayer", "assayer_profile", "assayer_checks"} {
			out[role] = ExecutableIdentity{Role: role, SHA256: assayer, EnvironmentHash: env, Known: true}
		}
	}
	return out
}
func validateParticipants(items map[string]ExecutableIdentity) error {
	var missing []string
	for _, role := range participantRoles {
		x, ok := items[role]
		if !ok || (!x.Known && !x.NotApplicable) {
			missing = append(missing, role)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		return fmt.Errorf("unknown required execution identities: %s", strings.Join(missing, ", "))
	}
	return nil
}
