package util

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"syscall"
	"text/template"

	"github.com/MakeNowJust/heredoc"
	"github.com/Masterminds/sprig/v3"
	iam "github.com/netsoc/iam/client"
	"golang.org/x/sys/unix"
)

// JailConfig represents jail configuration
type JailConfig struct {
	TmpDir string `mapstructure:"tmp_dir"`

	LogLevel string `mapstructure:"log_level"`
	UIDStart uint32 `mapstructure:"uid_start"`
	GIDStart uint32 `mapstructure:"gid_start"`

	Cgroups struct {
		Name string

		Memory  uint64
		PIDs    uint64
		CPUTime uint32 `mapstructure:"cpu_time"`
	} `mapstructure:"cgroups"`

	HomeSize uint64 `mapstructure:"home_size"`
}

type jailInfo struct {
	Config  *JailConfig
	User    *iam.User
	Path    string
	Command string
}

var configTemplate = template.Must(template.New("nsjail.cfg").Funcs(sprig.GenericFuncMap()).Parse(heredoc.Doc(`
	name: "shhd-fish"
	description: "nsjail config to run restricted fish"

	mode: ONCE
	hostname: "{{ .User.Username }}-netsoc"
	cwd: "/home/{{ .User.Username }}"

	time_limit: 0
	daemon: false
	max_cpus: 1

	log_fd: 3
	log_level: {{ .Config.LogLevel }}

	keep_env: true

	cap: "CAP_SETUID"
	cap: "CAP_SETGID"
	skip_setsid: true

	cgroup_mem_parent: "{{ .Config.Cgroups.Name }}"
	cgroup_pids_parent: "{{ .Config.Cgroups.Name }}"
	cgroup_cpu_parent: "{{ .Config.Cgroups.Name }}"
	cgroup_mem_max: {{ .Config.Cgroups.Memory }}
	cgroup_pids_max: {{ .Config.Cgroups.PIDs }}
	cgroup_cpu_ms_per_sec: {{ .Config.Cgroups.CPUTime }}

	uidmap {
		inside_id: "0"
		outside_id: "{{ .Config.UIDStart }}"
		count: 65537
	}
	gidmap {
		inside_id: "0"
		outside_id: "{{ .Config.GIDStart }}"
		count: 65537
	}

	mount {
		dst: "/dev"
		fstype: "tmpfs"
		options: "size=8388608"
		rw: true
		is_bind: false
	}
	mount {
		src: "{{ .Config.TmpDir }}/null"
		dst: "/dev/null"
		rw: true
		is_bind: true
	}
	mount {
		src: "{{ .Config.TmpDir }}/zero"
		dst: "/dev/zero"
		rw: true
		is_bind: true
	}
	mount {
		src: "{{ .Config.TmpDir }}/random"
		dst: "/dev/random"
		is_bind: true
	}
	mount {
		src: "{{ .Config.TmpDir }}/urandom"
		dst: "/dev/urandom"
		is_bind: true
	}

	mount {
		dst: "/proc"
		fstype: "proc"
		rw: false
	}
	mount {
		src: "/proc/self/fd"
		dst: "/dev/fd"
		is_symlink: true
	}

	mount {
		src: "/lib"
		dst: "/lib"
		is_bind: true
		rw: false
	}
	mount {
		src: "/bin"
		dst: "/bin"
		is_bind: true
		rw: false
	}
	mount {
		src: "/sbin"
		dst: "/sbin"
		is_bind: true
	}
	mount {
		src: "/usr"
		dst: "/usr"
		is_bind: true
	}

	mount {
		src: "/etc/shells"
		dst: "/etc/shells"
		is_bind: true
	}
	mount {
		src: "/etc/terminfo"
		dst: "/etc/terminfo"
		is_bind: true
	}
	mount {
		src: "/etc/fish"
		dst: "/etc/fish"
		is_bind: true
	}

	mount {
		dst: "/tmp"
		fstype: "tmpfs"
		options: "size=8388608"
		rw: true
		is_bind: false
	}

	mount {
		dst: "/etc/passwd"
		src_content: "root:x:0:0::/:/sbin/nologin\n{{ .User.Username }}:x:1000:1000::/home/{{ .User.Username }}:/usr/bin/fish\n"
	}
	mount {
		dst: "/etc/group"
		src_content: "root:x:0:root\n{{ .User.Username }}:x:1000:\n"
	}
	mount {
		dst: "/etc/fish/config.fish"
		src_content: "set -gx PATH {{ .Path }}"
	}

	mount {
		dst: "/home/{{ .User.Username }}"
		fstype: "tmpfs"
		options: "size={{ .Config.HomeSize }}"
		rw: true
		is_bind: false
	}
	mount {
		dst: "/home/{{ .User.Username }}/.netsoc.yaml"
		src_content: "test"
		rw: true
	}

	seccomp_string: "KILL { syslog }"
	seccomp_string: "DEFAULT ALLOW"

	exec_bin {
		path: "/bin/su"
		arg0: "su"
		arg: "-"
		#arg: "root"
		#arg: "-s"
		#arg: "/usr/bin/fish"
		arg: "{{ .User.Username }}"
	{{- if .Command }}
		arg: "-c"
		arg: "{{ .Command }}"
	{{- end }}
	}
`)))

// InitJail initializes the jail environment
func InitJail(c *JailConfig) error {
	if err := os.MkdirAll(c.TmpDir, 0775); err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}

	oldMask := syscall.Umask(0o000)
	if err := EnsureNod(path.Join(c.TmpDir, "null"), syscall.S_IFCHR|0o666, unix.Mkdev(1, 3)); err != nil {
		return fmt.Errorf("failed to create /dev/null: %w", err)
	}
	if err := EnsureNod(path.Join(c.TmpDir, "zero"), syscall.S_IFCHR|0o666, unix.Mkdev(1, 5)); err != nil {
		return fmt.Errorf("failed to create /dev/zero: %w", err)
	}
	if err := EnsureNod(path.Join(c.TmpDir, "random"), syscall.S_IFCHR|0o666, unix.Mkdev(1, 8)); err != nil {
		return fmt.Errorf("failed to create /dev/random: %w", err)
	}
	if err := EnsureNod(path.Join(c.TmpDir, "urandom"), syscall.S_IFCHR|0o666, unix.Mkdev(1, 9)); err != nil {
		return fmt.Errorf("failed to create /dev/urandom: %w", err)
	}
	syscall.Umask(oldMask)

	for _, f := range []string{"null", "zero", "random", "urandom"} {
		if err := os.Chown(path.Join(c.TmpDir, f), int(c.UIDStart), int(c.GIDStart)); err != nil {
			return fmt.Errorf("failed to set ownership of device file %v: %w", f, err)
		}
	}

	for _, cg := range []string{"memory", "pids", "cpu"} {
		if err := os.MkdirAll(path.Join("/sys/fs/cgroup", cg, c.Cgroups.Name), 775); err != nil {
			return fmt.Errorf("failed to create cgroup %v parent %v: %w", cg, c.Cgroups.Name, err)
		}
	}

	return nil
}

// NewShellJail creates a new exec.Cmd for running fish in an nsjail
func NewShellJail(c *JailConfig, u *iam.User, pathVar, command string) (*exec.Cmd, error) {
	filename := path.Join(c.TmpDir, fmt.Sprintf("u%v.cfg", u.Id))

	f, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to create tempfile: %w", err)
	}

	if err := configTemplate.Execute(f, jailInfo{
		Config:  c,
		User:    u,
		Path:    pathVar,
		Command: command,
	}); err != nil {
		return nil, fmt.Errorf("failed to render config template: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("failed to close tempfile: %w", err)
	}

	return exec.Command("nsjail", "--config", f.Name()), nil
}
