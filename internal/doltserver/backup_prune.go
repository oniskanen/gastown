package doltserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// BackupTarget describes a single configured backup destination.
type BackupTarget struct {
	// Name is the backup remote name (e.g., "backup_export").
	Name string

	// URL is the remote URL as recorded in repo_state.json
	// (e.g., "file:///home/.../backup").
	URL string

	// Path is the resolved local filesystem path. Empty for non-file backups.
	Path string
}

// PruneResult records what a single PruneBackupTarget run did or would do.
type PruneResult struct {
	// Path is the backup target directory that was pruned.
	Path string

	// DryRun is true if no files were actually deleted.
	DryRun bool

	// Deleted holds the relative paths (under Path) of orphan files
	// removed (or, for DryRun, identified as orphans).
	Deleted []string

	// BytesFreed is the total size in bytes of the orphan files.
	BytesFreed int64

	// ReferencedChunks is the count of chunk hashes referenced from
	// the manifest(s) at the moment of the scan.
	ReferencedChunks int
}

// chunkHashPattern matches NBS chunk hashes: 32 lowercase base32-ish chars.
// Dolt's hash alphabet is "0123456789abcdefghijklmnopqrstuv" (32 chars, no
// w/x/y/z), but for matching purposes accepting all of [a-z0-9] is safe —
// any false-positive hash will simply never appear as a real chunk file.
var chunkHashPattern = regexp.MustCompile(`^[a-z0-9]{32}$`)

// nbsStagingPattern matches Dolt NBS staging temp files left behind by
// interrupted writes (`nbs_table_<digits>` and `nbs_manifest_<digits>`).
// These are never referenced by a successfully-flushed manifest.
var nbsStagingPattern = regexp.MustCompile(`^nbs_(table|manifest)_[0-9]+$`)

// preservedFilenames are control files at the root of a backup target that
// must never be deleted by the prune.
var preservedFilenames = map[string]struct{}{
	"manifest":          {},
	"manifest.appendix": {}, // future-proof; not currently used by file backups
	"LOCK":              {},
	"backup_state.json": {},
	"repo_state.json":   {},
}

// ListFileBackupTargets reads <dbDir>/.dolt/repo_state.json and returns the
// configured backup remotes whose URLs point at the local filesystem
// (file:// scheme). Non-file backups (s3://, etc.) are skipped — pruning
// remote storage is out of scope for this tool.
func ListFileBackupTargets(dbDir string) ([]BackupTarget, error) {
	repoStatePath := filepath.Join(dbDir, ".dolt", "repo_state.json")
	data, err := os.ReadFile(repoStatePath)
	if err != nil {
		return nil, fmt.Errorf("read repo_state.json: %w", err)
	}

	var state struct {
		Backups map[string]struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"backups"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse repo_state.json: %w", err)
	}

	names := make([]string, 0, len(state.Backups))
	for name := range state.Backups {
		names = append(names, name)
	}
	sort.Strings(names)

	var targets []BackupTarget
	for _, name := range names {
		b := state.Backups[name]
		if !strings.HasPrefix(b.URL, "file://") {
			continue
		}
		targets = append(targets, BackupTarget{
			Name: b.Name,
			URL:  b.URL,
			Path: strings.TrimPrefix(b.URL, "file://"),
		})
	}
	return targets, nil
}

// PruneBackupTarget removes orphan chunk and staging files from a Dolt
// backup target directory. An "orphan" is a file in the directory whose
// chunk hash is not referenced from the target's manifest, or which is a
// known transient staging file from an interrupted NBS write.
//
// The function is conservative: any unrecognized file (anything that is not
// a referenced or unreferenced chunk file, and not an NBS staging temp) is
// left in place. Subdirectories are recursed into so that the `oldgen/`
// sub-store is also pruned.
//
// Set dryRun=true to identify orphans without deleting them.
//
// The caller must ensure no `dolt backup sync` is running against the
// target while this is invoked. The expected callsites are (a) the
// mol-dog-backup daemon path, immediately after `dolt backup sync` returns,
// and (b) the `gt dolt backup-prune` CLI, which is human-driven.
func PruneBackupTarget(targetPath string, dryRun bool) (PruneResult, error) {
	result := PruneResult{Path: targetPath, DryRun: dryRun}

	info, err := os.Stat(targetPath)
	if err != nil {
		return result, fmt.Errorf("stat target: %w", err)
	}
	if !info.IsDir() {
		return result, fmt.Errorf("not a directory: %s", targetPath)
	}

	referenced, err := collectReferencedChunks(targetPath)
	if err != nil {
		return result, err
	}
	result.ReferencedChunks = len(referenced)

	if err := pruneDir(targetPath, "", referenced, dryRun, &result); err != nil {
		return result, err
	}
	return result, nil
}

// collectReferencedChunks parses the manifest at the root of a backup target
// (and any sub-store manifests, e.g., oldgen/) and returns the set of all
// 32-char chunk hashes referenced.
//
// The Dolt manifest format is colon-delimited:
//
//	<ver>:<store>:<root>:<lock>:<base>:<chunk1>:<size1>:<chunk2>:<size2>:...
//
// Rather than positionally parsing and risk getting the chunk-pair offset
// wrong across format versions, we extract every 32-char hash-shaped token
// and union them. This is safely over-inclusive: an extra "referenced" hash
// merely preserves a file that may not strictly be needed.
func collectReferencedChunks(targetPath string) (map[string]struct{}, error) {
	referenced := make(map[string]struct{})

	// Root manifest is required.
	if err := mergeManifestChunks(filepath.Join(targetPath, "manifest"), referenced); err != nil {
		return nil, err
	}

	// Sub-store manifests (currently only oldgen/) are optional.
	subManifests, _ := filepath.Glob(filepath.Join(targetPath, "*", "manifest"))
	for _, m := range subManifests {
		if err := mergeManifestChunks(m, referenced); err != nil {
			return nil, fmt.Errorf("sub-store manifest %s: %w", m, err)
		}
	}
	return referenced, nil
}

func mergeManifestChunks(path string, into map[string]struct{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read manifest %s: %w", path, err)
	}
	for _, tok := range strings.Split(string(data), ":") {
		tok = strings.TrimSpace(tok)
		if chunkHashPattern.MatchString(tok) {
			into[tok] = struct{}{}
		}
	}
	return nil
}

// pruneDir walks one directory level (root or oldgen/) and deletes orphan
// chunk + staging files. It recurses into subdirectories that look like NBS
// sub-stores (i.e., contain their own manifest).
func pruneDir(targetPath, rel string, referenced map[string]struct{}, dryRun bool, result *PruneResult) error {
	dir := filepath.Join(targetPath, rel)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read dir %s: %w", dir, err)
	}

	for _, e := range entries {
		name := e.Name()
		entryRel := filepath.Join(rel, name)

		if e.IsDir() {
			// Recurse into NBS sub-stores (have their own manifest).
			if _, err := os.Stat(filepath.Join(dir, name, "manifest")); err == nil {
				if err := pruneDir(targetPath, entryRel, referenced, dryRun, result); err != nil {
					return err
				}
			}
			continue
		}

		if _, ok := preservedFilenames[name]; ok {
			continue
		}

		if !classifyOrphan(name, referenced) {
			continue
		}

		fullPath := filepath.Join(dir, name)
		size, err := fileSize(fullPath)
		if err != nil {
			return fmt.Errorf("stat %s: %w", fullPath, err)
		}
		if !dryRun {
			if err := os.Remove(fullPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("remove %s: %w", fullPath, err)
			}
		}
		result.Deleted = append(result.Deleted, entryRel)
		result.BytesFreed += size
	}
	return nil
}

// classifyOrphan returns true iff the regular file `name` is a chunk-style
// or staging-style file that is NOT referenced by the manifest.
func classifyOrphan(name string, referenced map[string]struct{}) bool {
	if nbsStagingPattern.MatchString(name) {
		return true
	}
	if strings.HasSuffix(name, ".darc") {
		hash := strings.TrimSuffix(name, ".darc")
		if !chunkHashPattern.MatchString(hash) {
			return false
		}
		_, ok := referenced[hash]
		return !ok
	}
	if chunkHashPattern.MatchString(name) {
		// Bare hash file (raw NBS table named after content hash).
		_, ok := referenced[name]
		return !ok
	}
	return false
}

func fileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}
