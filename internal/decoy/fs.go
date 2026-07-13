package decoy

import (
	"bufio"
	_ "embed"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/golang/glog"
)

//go:embed bash_history
var BashHistory string

//go:embed powershell_history
var PowerShellHistory string

// Virtual home paths an admin would poke after landing.
var homeFiles = map[string]string{
	".bash_history": BashHistory,
	".bashrc": `# ~/.bashrc — CORP-PROD-SRV05.internal
HISTSIZE=5000
HISTFILESIZE=10000
HISTCONTROL=ignoredups:erasedups
export HISTTIMEFORMAT="%F %T "
export PS1='\[\e[0;32m\]\u@\h:\w\$\[\e[0m\] '
alias ll='ls -la'
alias grep='grep --color=auto'
`,
	".profile": `# ~/.profile
if [ -n "$BASH_VERSION" ]; then
  [ -f "$HOME/.bashrc" ] && . "$HOME/.bashrc"
fi
`,
	".local/share/powershell/PSReadLine/ConsoleHost_history.txt": PowerShellHistory,
}

func fileContent(name string) (string, bool) {
	name = strings.TrimSpace(name)
	name = strings.TrimPrefix(name, "./")
	name = strings.TrimPrefix(name, "~/")
	name = strings.TrimPrefix(name, "/home/admin/")
	name = path.Clean(name)
	if name == "." || name == "" {
		return "", false
	}
	content, ok := homeFiles[name]
	return content, ok
}

// RunShell presents a minimal interactive login shell with decoy artifacts.
func RunShell(in io.Reader, out io.Writer, user, hostShort, hostFQDN, remote string) {
	prompt := fmt.Sprintf("%s@%s:~$ ", user, hostShort)
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for {
		if _, err := io.WriteString(out, prompt); err != nil {
			return
		}
		if !scanner.Scan() {
			return
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		glog.Infof("ssh cmd host=%s ip=%s user=%s cmd=%q", hostFQDN, remote, user, line)

		if !dispatch(out, user, hostShort, hostFQDN, line) {
			return
		}
	}
}

func dispatch(out io.Writer, user, hostShort, hostFQDN, line string) bool {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return true
	}
	cmd := fields[0]

	switch cmd {
	case "exit", "logout", "quit":
		io.WriteString(out, "logout\n")
		return false
	case "clear":
		io.WriteString(out, "\033[2J\033[H")
		return true
	case "whoami":
		fmt.Fprintln(out, user)
	case "hostname":
		if len(fields) > 1 && fields[1] == "-f" {
			fmt.Fprintln(out, hostFQDN)
		} else {
			fmt.Fprintln(out, hostShort)
		}
	case "pwd":
		fmt.Fprintf(out, "/home/%s\n", user)
	case "uname":
		fmt.Fprintln(out, "Linux "+hostShort+" 5.15.0-113-generic #123-Ubuntu SMP x86_64 GNU/Linux")
	case "id":
		fmt.Fprintf(out, "uid=1000(%s) gid=1000(%s) groups=1000(%s),27(sudo),100(users)\n", user, user, user)
	case "history":
		writeNumberedHistory(out)
	case "ls":
		writeLS(out, fields[1:])
	case "cat", "head", "tail", "less", "more":
		writeCat(out, fields[1:])
	case "help":
		io.WriteString(out, "Builtins: cat ls history pwd whoami hostname id uname clear exit\n")
	default:
		fmt.Fprintf(out, "bash: %s: command not found\n", cmd)
	}
	return true
}

func writeNumberedHistory(out io.Writer) {
	lines := strings.Split(strings.TrimSuffix(BashHistory, "\n"), "\n")
	n := 1
	for _, line := range lines {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fmt.Fprintf(out, "%5d  %s\n", n, line)
		n++
	}
}

func writeLS(out io.Writer, args []string) {
	long, all := false, false
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			continue
		}
		if strings.Contains(a, "l") {
			long = true
		}
		if strings.Contains(a, "a") {
			all = true
		}
	}

	entries := []struct {
		mode, name string
		hidden     bool
	}{
		{"drwxr-xr-x", ".", true},
		{"drwxr-xr-x", "..", true},
		{"-rw-------", ".bash_history", true},
		{"-rw-r--r--", ".bashrc", true},
		{"-rw-r--r--", ".profile", true},
		{"drwx------", ".local", true},
		{"drwxr-xr-x", "bin", false},
		{"drwxr-xr-x", "logs", false},
	}

	if long {
		for _, e := range entries {
			if e.hidden && !all {
				continue
			}
			fmt.Fprintf(out, "%s 1 admin admin  4096 Jul  8 09:14 %s\n", e.mode, e.name)
		}
		return
	}

	for _, e := range entries {
		if e.hidden && !all {
			continue
		}
		if e.name == "." || e.name == ".." {
			if all {
				fmt.Fprintf(out, "%s  ", e.name)
			}
			continue
		}
		fmt.Fprintf(out, "%s  ", e.name)
	}
	io.WriteString(out, "\n")
}

func writeCat(out io.Writer, args []string) {
	seenFile := false
	for _, raw := range args {
		if strings.HasPrefix(raw, "-") {
			continue
		}
		seenFile = true
		content, ok := fileContent(raw)
		if !ok {
			fmt.Fprintf(out, "cat: %s: No such file or directory\n", raw)
			continue
		}
		io.WriteString(out, content)
		if !strings.HasSuffix(content, "\n") {
			io.WriteString(out, "\n")
		}
	}
	if !seenFile {
		io.WriteString(out, "cat: missing file operand\n")
	}
}
