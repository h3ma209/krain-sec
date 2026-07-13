package decoy

import (
	"bufio"
	_ "embed"
	"fmt"
	"io"
	"path"
	"strings"

	"krain-sec/internal/honeytoken"
	"krain-sec/internal/store"

	"github.com/golang/glog"
)

//go:embed bash_history
var BashHistory string

//go:embed powershell_history
var PowerShellHistory string

func homeFiles() map[string]string {
	bg, _, _ := honeytoken.Content(honeytoken.TokenBreakglass)
	aws, _, _ := honeytoken.Content(honeytoken.TokenAWSKeys)
	key, _, _ := honeytoken.Content(honeytoken.TokenSSHKey)
	rb, _, _ := honeytoken.Content(honeytoken.TokenRunbook)

	return map[string]string{
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
		"Documents/VPN_Breakglass_Credentials.txt":                   bg,
		"Documents/CORP_Incident_Response_Runbook.txt":               rb,
		"aws_keys/corp-prod-readonly.csv":                           aws,
		".config/corp/id_rsa":                                       key,
		".ssh/id_rsa_deploy":                                        key,
		".ssh/config": `Host CORP-PROD-BLD09
  HostName CORP-PROD-BLD09.internal
  User deploy
  IdentityFile ~/.ssh/id_rsa_deploy
`,
	}
}

func normalizePath(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimPrefix(name, "./")
	name = strings.TrimPrefix(name, "~/")
	name = strings.TrimPrefix(name, "/home/admin/")
	name = path.Clean(name)
	if name == "." {
		return ""
	}
	return name
}

func fileContent(name string) (string, bool) {
	name = normalizePath(name)
	if name == "" {
		return "", false
	}
	content, ok := homeFiles()[name]
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
		store.RecordSSHCommand(remote, user, line)

		if !dispatch(out, user, hostShort, hostFQDN, remote, line) {
			return
		}
	}
}

func dispatch(out io.Writer, user, hostShort, hostFQDN, remote, line string) bool {
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
		writeLs(out, fields[1:])
	case "cat", "head", "tail", "less", "more":
		writeCat(out, fields[1:], remote, user)
	case "find":
		writeFind(out)
	case "help":
		io.WriteString(out, "Builtins: cat ls find history pwd whoami hostname id uname clear exit\n")
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

type dirEntry struct {
	mode, name string
	hidden     bool
	dir        bool
}

func listingFor(target string) []dirEntry {
	target = normalizePath(target)
	switch target {
	case "", ".":
		return []dirEntry{
			{"drwxr-xr-x", ".", true, true},
			{"drwxr-xr-x", "..", true, true},
			{"-rw-------", ".bash_history", true, false},
			{"-rw-r--r--", ".bashrc", true, false},
			{"-rw-r--r--", ".profile", true, false},
			{"drwx------", ".local", true, true},
			{"drwx------", ".config", true, true},
			{"drwx------", ".ssh", true, true},
			{"drwxr-xr-x", "Documents", false, true},
			{"drwxr-xr-x", "aws_keys", false, true},
			{"drwxr-xr-x", "bin", false, true},
			{"drwxr-xr-x", "logs", false, true},
		}
	case "Documents":
		return []dirEntry{
			{"-rw-------", "VPN_Breakglass_Credentials.txt", false, false},
			{"-rw-r--r--", "CORP_Incident_Response_Runbook.txt", false, false},
		}
	case "aws_keys":
		return []dirEntry{
			{"-rw-------", "corp-prod-readonly.csv", false, false},
		}
	case ".config":
		return []dirEntry{{"drwx------", "corp", false, true}}
	case ".config/corp":
		return []dirEntry{{"-rw-------", "id_rsa", false, false}}
	case ".ssh":
		return []dirEntry{
			{"-rw-------", "id_rsa_deploy", false, false},
			{"-rw-r--r--", "config", false, false},
		}
	case ".local":
		return []dirEntry{{"drwx------", "share", false, true}}
	default:
		return nil
	}
}

func writeLs(out io.Writer, args []string) {
	long, all := false, false
	target := ""
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			if strings.Contains(a, "l") {
				long = true
			}
			if strings.Contains(a, "a") {
				all = true
			}
			continue
		}
		target = a
	}

	entries := listingFor(target)
	if entries == nil {
		// maybe it's a file
		if _, ok := fileContent(target); ok {
			fmt.Fprintln(out, path.Base(normalizePath(target)))
			return
		}
		fmt.Fprintf(out, "ls: cannot access '%s': No such file or directory\n", target)
		return
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
		if (e.name == "." || e.name == "..") && !all {
			continue
		}
		fmt.Fprintf(out, "%s  ", e.name)
	}
	io.WriteString(out, "\n")
}

func writeFind(out io.Writer) {
	for name := range homeFiles() {
		fmt.Fprintf(out, "/home/admin/%s\n", name)
	}
}

func writeCat(out io.Writer, args []string, remote, user string) {
	seenFile := false
	for _, raw := range args {
		if strings.HasPrefix(raw, "-") {
			continue
		}
		seenFile = true
		rel := normalizePath(raw)
		content, ok := fileContent(raw)
		if !ok {
			fmt.Fprintf(out, "cat: %s: No such file or directory\n", raw)
			continue
		}
		if token, isHoney := honeytoken.PathToToken(rel); isHoney {
			honeytoken.LogHit("ssh_read", token, remote, fmt.Sprintf("user=%s path=%s", user, rel))
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
