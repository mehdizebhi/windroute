package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"windroute/internal/state"
)

// cmdLogs prints (and optionally follows) the redirect proxy log.
func cmdLogs(args []string) error {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	n := fs.Int("n", 50, "number of recent lines to show (0 = all)")
	follow := fs.Bool("f", false, "follow the log")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := state.LogFile()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("no log yet at " + path)
			return nil
		}
		return err
	}
	defer f.Close()

	printTail(path, *n)
	if !*follow {
		return nil
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	return followLog(f)
}

func printTail(path string, n int) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if n > 0 && len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	if len(lines) > 0 && lines[0] != "" {
		fmt.Println(strings.Join(lines, "\n"))
	}
}

func followLog(f *os.File) error {
	buf := make([]byte, 8192)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			os.Stdout.Write(buf[:n])
		}
		if err == io.EOF {
			time.Sleep(300 * time.Millisecond)
			continue
		}
		if err != nil {
			return err
		}
	}
}
