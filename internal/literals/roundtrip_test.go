package literals

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// buildAndRunProbe compiles a probe program and runs it, failing on a build
// error or on output other than want. A non-empty goVersion builds it as a
// module declaring that language version.
func buildAndRunProbe(t *testing.T, source []byte, goVersion, want string) {
	t.Helper()
	dir := t.TempDir()
	srcPath, binPath := filepath.Join(dir, "main.go"), filepath.Join(dir, "probe.exe")
	if err := os.WriteFile(srcPath, source, 0o600); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-p=1", "-o", binPath, srcPath)
	if goVersion != "" {
		goMod := "module probe\n\ngo " + goVersion + "\n"
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o600); err != nil {
			t.Fatal(err)
		}
		build = exec.Command("go", "build", "-p=1", "-o", binPath, ".")
		build.Dir = dir
	}
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	if out, err := exec.Command(binPath).CombinedOutput(); err != nil || string(out) != want {
		t.Fatalf("run: %v\n%s", err, out)
	}
}
