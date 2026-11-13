// Copyright (c) 2020, The Garble Authors.
// See LICENSE for licensing information.

//go:build ignore

// bench_literals benchmarks the build time, run time and binary size of
// "garble -literals build" against a plain "go build", for one garble checkout.
//
// It generates these programs:
//   - sizes: one module per string size, each with many global strings of that size
//   - hot: a function returning a 32-byte literal, called a million times
//   - embed: a 1 MiB file embedded as a []byte
//
// Each build iteration writes a unique dummy var to bust the build cache
// without rebuilding the entire runtime. A timeout kills any build or run
// that takes too long, reporting "timeout" on stderr and skipping.
//
// Output is in Go benchmark format, compatible with benchstat. To compare two
// checkouts of garble, such as master and a branch, run once per checkout:
//
//	go run ./scripts/bench_literals.go -garble ../garble-master -label master >master.txt
//	go run ./scripts/bench_literals.go -label branch >branch.txt
//	cat master.txt branch.txt | benchstat -col /garble -
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	mathrand "math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var rng *mathrand.ChaCha8

func init() {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		panic(err)
	}
	rng = mathrand.NewChaCha8(seed)
}

var (
	count     = flag.Int("count", 1, "number of iterations for each benchmark")
	timeout   = flag.Duration("timeout", 30*time.Second, "timeout per build or run invocation")
	garbleDir = flag.String("garble", ".", "garble checkout to build and benchmark")
	label     = flag.String("label", "new", "value of the /garble benchmark key for this checkout")
)

// stringSizes to benchmark, from just above MinSize (8) to the old 2 KiB limit
// of the per-literal obfuscators.
var stringSizes = []int{
	16, 64, 256, 1024, 2048,
}

// program is a generated module to benchmark.
type program struct {
	name string
	dir  string
}

func main() {
	flag.Parse()

	tmpDir, err := os.MkdirTemp("", "garble-bench-literals-*")
	if err != nil {
		fatal("mkdtemp: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	garbleBin := filepath.Join(tmpDir, "garble")
	fmt.Fprintf(os.Stderr, "building garble from %s...\n", *garbleDir)
	runCmdNoTimeout(*garbleDir, "go", "build", "-o", garbleBin, ".")

	var programs []program
	for _, size := range stringSizes {
		dir := filepath.Join(tmpDir, fmt.Sprintf("size%dB", size))
		writeModule(dir, sizesMain(size), nil)
		programs = append(programs, program{fmt.Sprintf("size%dB", size), dir})
	}
	hotDir := filepath.Join(tmpDir, "hot")
	writeModule(hotDir, hotMain(), nil)
	embedDir := filepath.Join(tmpDir, "embed")
	writeModule(embedDir, embedMain, map[string]string{"data.txt": randomHex(1 << 20)})
	programs = append(programs, program{"hot", hotDir}, program{"embed", embedDir})

	// Garble caches the transformed standard library, so the first build is
	// much slower than the ones we want to measure.
	fmt.Fprintf(os.Stderr, "warming garble cache...\n")
	runCmdNoTimeout(programs[0].dir, garbleBin, "-literals", "build", "-o", filepath.Join(tmpDir, "warmup"), ".")

	for _, prog := range programs {
		bench("go", prog, filepath.Join(tmpDir, prog.name+"_go"), "go", "build")
		bench(*label, prog, filepath.Join(tmpDir, prog.name+"_garble"), garbleBin, "-literals", "build")
	}
}

// bench builds prog *count times with the given command, printing the build
// time and binary size of each build, then runs the binary *count times.
func bench(variant string, prog program, bin string, buildArgs ...string) {
	suffix := fmt.Sprintf("/garble=%s/%s", variant, prog.name)
	built := false
	for range *count {
		// Write a unique file each iteration to bust the build cache
		// without rebuilding the entire runtime.
		entry := fmt.Sprintf("package main\n\nvar _benchIter uint64 = %d\n", rng.Uint64())
		must(os.WriteFile(filepath.Join(prog.dir, "bench_iter.go"), []byte(entry), 0o644))

		args := append(buildArgs[1:len(buildArgs):len(buildArgs)], "-o", bin, ".")
		d, ok := runCmdWithTimeout(prog.dir, buildArgs[0], args...)
		if !ok {
			fmt.Printf("BenchmarkBuild%s 1 %d ns/op\n", suffix, timeout.Nanoseconds())
			fmt.Fprintf(os.Stderr, "    ^ timed out: %s\n", strings.Join(buildArgs, " "))
			break
		}
		built = true
		fmt.Printf("BenchmarkBuild%s 1 %d ns/op\n", suffix, d.Nanoseconds())
		info, err := os.Stat(bin)
		must(err)
		fmt.Printf("BenchmarkSize%s 1 %d bin-bytes\n", suffix, info.Size())
	}
	if !built {
		return
	}
	// Some systems check a new executable on its first run, such as macOS,
	// which takes far longer than running it.
	runCmdWithTimeout("", bin)
	for range *count {
		d, ok := runCmdWithTimeout("", bin)
		if !ok {
			fmt.Printf("BenchmarkRun%s 1 %d ns/op\n", suffix, timeout.Nanoseconds())
			fmt.Fprintf(os.Stderr, "    ^ timed out: %s\n", bin)
			return
		}
		fmt.Printf("BenchmarkRun%s 1 %d ns/op\n", suffix, d.Nanoseconds())
	}
}

// runCmdWithTimeout runs the command with the configured timeout.
// It returns the elapsed time and true on success, or zero and false on timeout.
// The command is started in its own process group so that on timeout,
// the entire tree (including child processes like subcompilers) is killed.
func runCmdWithTimeout(dir string, name string, args ...string) (time.Duration, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)

	// Kill the entire process group, not just the leader.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}

	cmd.Dir = dir
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	start := time.Now()
	err := cmd.Run()
	elapsed := time.Since(start)

	if ctx.Err() != nil {
		return 0, false
	}
	if err != nil {
		fatal("command %s %v failed: %v", name, args, err)
	}
	return elapsed, true
}

// runCmdNoTimeout runs a command without any timeout (used for setup steps).
func runCmdNoTimeout(dir string, name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fatal("command %s %v failed: %v", name, args, err)
	}
}

// numStrings is the number of strings per size in each test program.
// High enough to amortize per-build overhead and produce stable timings,
// low enough to keep individual builds fast.
const numStrings = 20

func writeModule(dir, mainSource string, files map[string]string) {
	must(os.MkdirAll(dir, 0o755))
	must(os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test/bench\n\ngo 1.27\n"), 0o644))
	must(os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainSource), 0o644))
	for name, content := range files {
		must(os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
	}
}

func sizesMain(stringSize int) string {
	var b strings.Builder
	b.WriteString("package main\n\nimport \"os\"\n\n")
	for i := range numStrings {
		fmt.Fprintf(&b, "var s%d = %q\n", i, randomHex(stringSize))
	}
	b.WriteString("\nfunc main() {\n")
	b.WriteString("\tf, _ := os.Create(os.DevNull)\n")
	for i := range numStrings {
		fmt.Fprintf(&b, "\tf.WriteString(s%d)\n", i)
	}
	b.WriteString("\tf.Close()\n")
	b.WriteString("}\n")
	return b.String()
}

// hotMain decodes one literal on every call, as in a hot loop.
func hotMain() string {
	return fmt.Sprintf(`package main

var sink int

//go:noinline
func hot() string { return %q }

func main() {
	for i := 0; i < 1000000; i++ {
		sink += len(hot())
	}
}
`, randomHex(32))
}

const embedMain = `package main

import _ "embed"

//go:embed data.txt
var data []byte

func main() { println(len(data)) }
`

func randomHex(n int) string {
	raw := make([]byte, (n+1)/2)
	rng.Read(raw)
	return hex.EncodeToString(raw)[:n]
}

func must(err error) {
	if err != nil {
		fatal("%v", err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
