package doltserver

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hashes is a small pool of valid 32-char chunk hashes used in tests.
var hashes = []string{
	"01b66vvjtvnruto35oo6pof46db2o1ki",
	"02sigbvvcmvc5e6528qr96pf9fdr5d33",
	"084gdbtf0dvsaq2vc46fth1oanhnutlr",
	"0b6rsjm862o41aoaia9mlji2312v799v",
	"0dlv2oegcpjhq447p5pqlt9nv4elnp5a",
	"0ja1iaetrhbrnrgv1n1r0horaalk65u1",
	"0s4v4at900qg1p67hkdsafatp64br0tk",
}

// makeManifest writes a Dolt-shaped manifest referencing the given chunk
// hashes. Format is the same colon-delimited shape that real Dolt produces:
// <ver>:<store>:<root>:<lock>:<base>:<chunk>:<size>:...
func makeManifest(t *testing.T, dir string, refs []string) {
	t.Helper()
	parts := []string{
		"5",
		"__DOLT__",
		"012obcil40rhdu4ormkb851hd30iudkt", // root
		"oa20eagmkhhnleqp7i3gj3vc51hqunfl", // lock
		"00000000000000000000000000000000", // base (no appendix)
	}
	for _, h := range refs {
		parts = append(parts, h, "1024")
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest"), []byte(strings.Join(parts, ":")), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

// writeFile creates a file with the given size (bytes of zero-padding).
func writeFile(t *testing.T, path string, size int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func setOf(items []string) map[string]struct{} {
	s := make(map[string]struct{}, len(items))
	for _, x := range items {
		s[x] = struct{}{}
	}
	return s
}

// TestPruneBackupTarget_DeletesOrphans is the core happy-path test:
// referenced .darc kept, unreferenced .darc deleted, nbs_table_/nbs_manifest_
// staging files deleted.
func TestPruneBackupTarget_DeletesOrphans(t *testing.T) {
	dir := t.TempDir()
	makeManifest(t, dir, hashes[:3])

	// Referenced chunks (kept).
	for _, h := range hashes[:3] {
		writeFile(t, filepath.Join(dir, h+".darc"), 100)
	}
	// Orphan .darc files (deleted).
	for _, h := range hashes[3:6] {
		writeFile(t, filepath.Join(dir, h+".darc"), 200)
	}
	// Orphan nbs staging files (deleted).
	writeFile(t, filepath.Join(dir, "nbs_table_1234567890"), 300)
	writeFile(t, filepath.Join(dir, "nbs_manifest_42"), 0)
	// Control files (kept).
	writeFile(t, filepath.Join(dir, "LOCK"), 0)
	writeFile(t, filepath.Join(dir, "backup_state.json"), 50)

	res, err := PruneBackupTarget(dir, false)
	if err != nil {
		t.Fatalf("PruneBackupTarget: %v", err)
	}

	wantDeleted := setOf([]string{
		hashes[3] + ".darc",
		hashes[4] + ".darc",
		hashes[5] + ".darc",
		"nbs_table_1234567890",
		"nbs_manifest_42",
	})
	got := setOf(res.Deleted)
	if len(got) != len(wantDeleted) {
		t.Errorf("deleted count = %d (%v); want %d (%v)", len(got), res.Deleted, len(wantDeleted), wantDeleted)
	}
	for k := range wantDeleted {
		if _, ok := got[k]; !ok {
			t.Errorf("missing from deleted: %s", k)
		}
	}

	// 3 × 200 + 300 + 0 = 900 bytes
	if res.BytesFreed != 900 {
		t.Errorf("BytesFreed = %d; want 900", res.BytesFreed)
	}
	// 3 chunks + root + lock + base — collectReferencedChunks is deliberately
	// over-inclusive (matches every 32-char hash-shaped token), so root/lock/
	// base hashes count too.
	if res.ReferencedChunks != 6 {
		t.Errorf("ReferencedChunks = %d; want 6", res.ReferencedChunks)
	}

	// Referenced .darcs should still be on disk.
	for _, h := range hashes[:3] {
		if _, err := os.Stat(filepath.Join(dir, h+".darc")); err != nil {
			t.Errorf("referenced %s.darc was deleted: %v", h, err)
		}
	}
	// Control files preserved.
	for _, name := range []string{"manifest", "LOCK", "backup_state.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("control file %s was deleted: %v", name, err)
		}
	}
}

// TestPruneBackupTarget_DryRun verifies that dry-run identifies orphans
// without touching the filesystem.
func TestPruneBackupTarget_DryRun(t *testing.T) {
	dir := t.TempDir()
	makeManifest(t, dir, hashes[:2])
	writeFile(t, filepath.Join(dir, hashes[0]+".darc"), 50)
	writeFile(t, filepath.Join(dir, hashes[1]+".darc"), 50)
	writeFile(t, filepath.Join(dir, hashes[2]+".darc"), 100)
	writeFile(t, filepath.Join(dir, "nbs_table_99"), 200)

	res, err := PruneBackupTarget(dir, true)
	if err != nil {
		t.Fatalf("PruneBackupTarget: %v", err)
	}
	if !res.DryRun {
		t.Error("DryRun = false; want true")
	}
	if len(res.Deleted) != 2 {
		t.Errorf("Deleted = %v; want 2 entries", res.Deleted)
	}
	if res.BytesFreed != 300 {
		t.Errorf("BytesFreed = %d; want 300", res.BytesFreed)
	}
	// Verify nothing was actually deleted.
	for _, name := range []string{
		hashes[0] + ".darc", hashes[1] + ".darc", hashes[2] + ".darc",
		"nbs_table_99", "manifest",
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("dry-run deleted %s: %v", name, err)
		}
	}
}

// TestPruneBackupTarget_OldgenSubstore verifies that the oldgen sub-store
// is recursed into and its orphans are cleaned independently of the root.
func TestPruneBackupTarget_OldgenSubstore(t *testing.T) {
	dir := t.TempDir()
	makeManifest(t, dir, hashes[:1])
	writeFile(t, filepath.Join(dir, hashes[0]+".darc"), 100)

	oldgen := filepath.Join(dir, "oldgen")
	if err := os.Mkdir(oldgen, 0o700); err != nil {
		t.Fatalf("mkdir oldgen: %v", err)
	}
	makeManifest(t, oldgen, []string{hashes[1]})
	writeFile(t, filepath.Join(oldgen, hashes[1]+".darc"), 100) // referenced
	writeFile(t, filepath.Join(oldgen, hashes[2]+".darc"), 200) // orphan
	writeFile(t, filepath.Join(oldgen, "nbs_table_7"), 50)      // orphan staging

	res, err := PruneBackupTarget(dir, false)
	if err != nil {
		t.Fatalf("PruneBackupTarget: %v", err)
	}

	want := setOf([]string{
		filepath.Join("oldgen", hashes[2]+".darc"),
		filepath.Join("oldgen", "nbs_table_7"),
	})
	got := setOf(res.Deleted)
	if len(got) != len(want) {
		t.Errorf("Deleted = %v; want %v", res.Deleted, want)
	}
	for k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("missing from deleted: %s", k)
		}
	}
	if _, err := os.Stat(filepath.Join(oldgen, hashes[1]+".darc")); err != nil {
		t.Errorf("referenced oldgen chunk deleted: %v", err)
	}
}

// TestPruneBackupTarget_PreservesUnknownFiles verifies the prune is
// conservative: anything not matching a known orphan pattern (random files,
// hidden files, future Dolt formats) is left in place.
func TestPruneBackupTarget_PreservesUnknownFiles(t *testing.T) {
	dir := t.TempDir()
	makeManifest(t, dir, hashes[:1])
	writeFile(t, filepath.Join(dir, hashes[0]+".darc"), 50)

	preserved := []string{
		"README.md",                              // human note
		"snapshot.tar",                           // unrelated archive
		".hidden",                                // hidden file
		"chunkidx.idx",                           // future Dolt format
		"abc.darc",                               // .darc but not 32-char hash
		"01b66vvjtvnruto35oo6pof46db2o1ki.other", // hash-ish but unknown ext
	}
	for _, name := range preserved {
		writeFile(t, filepath.Join(dir, name), 10)
	}

	res, err := PruneBackupTarget(dir, false)
	if err != nil {
		t.Fatalf("PruneBackupTarget: %v", err)
	}
	if len(res.Deleted) != 0 {
		t.Errorf("Deleted = %v; want []", res.Deleted)
	}
	for _, name := range preserved {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("unknown file %s was deleted: %v", name, err)
		}
	}
}

// TestPruneBackupTarget_MissingManifest returns an error rather than
// nuking everything — defensive guard against running against a non-NBS
// directory.
func TestPruneBackupTarget_MissingManifest(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, hashes[0]+".darc"), 100)

	_, err := PruneBackupTarget(dir, false)
	if err == nil {
		t.Fatal("expected error for missing manifest, got nil")
	}
	if !strings.Contains(err.Error(), "manifest") {
		t.Errorf("error should mention manifest: %v", err)
	}
	// File should still exist after the error.
	if _, err := os.Stat(filepath.Join(dir, hashes[0]+".darc")); err != nil {
		t.Errorf("file deleted despite manifest read error: %v", err)
	}
}

// TestPruneBackupTarget_BoundedAcrossInterruptedSyncs is the regression
// test for the orphan-accumulation bug: simulate the failure mode that
// fills disks (interrupted `dolt backup sync` leaves nbs_table_* + old
// .darcs behind) and verify that running the prune after each cycle
// keeps the target directory size bounded.
//
// Without prune, each cycle adds ~2× orphan_size of garbage; with prune,
// the target size never exceeds the current manifest's chunk total.
func TestPruneBackupTarget_BoundedAcrossInterruptedSyncs(t *testing.T) {
	dir := t.TempDir()

	// Simulate 5 sync cycles. Each cycle:
	//   1. Writes some nbs_table_* staging files (interrupted write).
	//   2. Renames/replaces the manifest to point at a new set of .darcs.
	//   3. Old .darcs from the previous cycle become unreferenced orphans.
	//   4. Prune runs, garbage gets cleaned up.
	const cycles = 5
	const cycleChunkSize = 4096
	const cycleStagingSize = 8192

	// Per-cycle: pick 3 fresh hash slots; previous 3 become orphans next cycle.
	pickHashes := func(n int, offset int) []string {
		out := make([]string, n)
		for i := 0; i < n; i++ {
			// Generate distinct fake-but-valid hashes by mod-cycling the pool.
			idx := (offset + i) % len(hashes)
			out[i] = hashes[idx]
		}
		return out
	}

	maxSize := int64(0)
	for cycle := 0; cycle < cycles; cycle++ {
		// Step 1: simulate interrupted write — stage files left behind.
		for i := 0; i < 3; i++ {
			writeFile(t,
				filepath.Join(dir, fmt.Sprintf("nbs_table_%d%d", cycle, i)),
				cycleStagingSize)
		}
		// Step 2: write fresh chunks.
		fresh := pickHashes(3, cycle*3)
		for _, h := range fresh {
			writeFile(t, filepath.Join(dir, h+".darc"), cycleChunkSize)
		}
		// Step 3: update manifest to reference only the fresh chunks.
		makeManifest(t, dir, fresh)

		// Step 4: prune.
		res, err := PruneBackupTarget(dir, false)
		if err != nil {
			t.Fatalf("cycle %d: prune: %v", cycle, err)
		}

		// Verify size after prune: should equal manifest + LOCK
		// (none here) + 3 × .darc + zero staging.
		size := dirSizeRecursive(t, dir)
		if size > maxSize {
			maxSize = size
		}

		// Allow up to 3 fresh chunks worth of data + manifest overhead.
		// Manifest is ~200 bytes; 3 chunks at 4096 = 12288. Cap generously.
		const upperBound = 3*cycleChunkSize + 4096
		if size > upperBound {
			t.Errorf("cycle %d: dir size %d exceeds bound %d; pruner is leaking: %+v",
				cycle, size, upperBound, res)
		}
	}

	// Final assertion: after all cycles, the directory has not grown
	// unboundedly. Without the prune, total size would be roughly
	// cycles × (3 × 8192 staging + 3 × 4096 darcs) ≈ 184 KB;
	// with prune it stays at ~12 KB.
	if maxSize >= int64(cycles*(3*cycleStagingSize+3*cycleChunkSize)) {
		t.Errorf("max dir size %d suggests no pruning happened", maxSize)
	}
}

// TestListFileBackupTargets verifies repo_state.json parsing and filtering
// of non-file:// remotes.
func TestListFileBackupTargets(t *testing.T) {
	dbDir := t.TempDir()
	doltDir := filepath.Join(dbDir, ".dolt")
	if err := os.MkdirAll(doltDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	state := map[string]any{
		"backups": map[string]any{
			"backup_export": map[string]any{
				"name": "backup_export",
				"url":  "file:///tmp/x/backup",
			},
			"s3-mirror": map[string]any{
				"name": "s3-mirror",
				"url":  "s3://bucket/path",
			},
		},
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(doltDir, "repo_state.json"), data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	targets, err := ListFileBackupTargets(dbDir)
	if err != nil {
		t.Fatalf("ListFileBackupTargets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("got %d targets; want 1 (s3:// should be filtered)", len(targets))
	}
	if targets[0].Name != "backup_export" {
		t.Errorf("Name = %q; want backup_export", targets[0].Name)
	}
	if targets[0].Path != "/tmp/x/backup" {
		t.Errorf("Path = %q; want /tmp/x/backup", targets[0].Path)
	}
}

// dirSizeRecursive sums the byte size of every regular file under dir.
func dirSizeRecursive(t *testing.T, dir string) int64 {
	t.Helper()
	var total int64
	err := filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return total
}
