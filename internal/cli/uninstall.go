package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"windroute/internal/state"
)

// cmdUninstall removes everything windroute created: the nftables rules, the
// redirect proxy, the runtime state directory and the executable itself.
//
// It intentionally does not touch anything it does not own, so it is safe to
// run and safe to re-run.
func cmdUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	keepState := fs.Bool("keep-state", false, "keep the runtime state directory")
	keepBinary := fs.Bool("keep-binary", false, "keep the windroute executable")
	binaryPath := fs.String("binary", "", "executable to remove (default: this executable)")
	dryRun := fs.Bool("dry-run", false, "show what would be removed without changing anything")
	force := fs.Bool("force", false, "remove the executable even if it is not named 'windroute'")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireRoot(); err != nil {
		return err
	}

	exe := resolveExecutable(*binaryPath)

	fmt.Println("windroute uninstall")

	if *dryRun {
		fmt.Println("  would remove nftables table 'inet windroute' (if present)")
		fmt.Println("  would stop the redirect proxy (if running)")
		if !*keepState {
			fmt.Printf("  would remove state directory %s\n", state.Dir())
		}
		if !*keepBinary && exe != "" {
			fmt.Printf("  would remove executable %s\n", exe)
		}
		fmt.Println("\ndry run: nothing was changed")
		return nil
	}

	var problems []string

	// 1. Undo all networking changes and stop the proxy (shared with "stop").
	actions, probs := teardown()
	for _, a := range actions {
		fmt.Printf("  %s\n", a)
	}
	problems = append(problems, probs...)

	// 2. Remove the runtime state directory (teardown only clears state.json).
	if !*keepState {
		if err := os.RemoveAll(state.Dir()); err != nil {
			problems = append(problems, fmt.Sprintf("remove %s: %v", state.Dir(), err))
		} else {
			fmt.Printf("  removed state directory %s\n", state.Dir())
		}
	}

	// 3. Remove the executable.
	if !*keepBinary && exe != "" {
		if filepath.Base(exe) != "windroute" && !*force {
			fmt.Printf("  skipped %s: not named 'windroute' (use --force to remove)\n", exe)
		} else if err := os.Remove(exe); err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("  executable already gone: %s\n", exe)
			} else {
				problems = append(problems, fmt.Sprintf("remove %s: %v", exe, err))
			}
		} else {
			fmt.Printf("  removed executable %s\n", exe)
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("uninstall completed with issues: %s", strings.Join(problems, "; "))
	}
	fmt.Println("windroute uninstalled")
	return nil
}

// resolveExecutable returns the real path of the binary to remove, following
// symlinks so that removing it removes the actual file.
func resolveExecutable(override string) string {
	p := override
	if p == "" {
		var err error
		p, err = os.Executable()
		if err != nil {
			return ""
		}
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return p
}
