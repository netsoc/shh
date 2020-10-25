package util

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"syscall"
	"text/template"

	"github.com/MakeNowJust/heredoc"
	"github.com/Masterminds/sprig/v3"
	iam "github.com/netsoc/iam/client"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var allAddr = net.IPv4(0xff, 0xff, 0xff, 0xff)

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

	Network struct {
		Interface string
		Address   net.IPNet
	}
}

type jailNetInfo struct {
	IP   net.IP
	Mask string
}
type jailInfo struct {
	Config  *JailConfig
	User    *iam.User
	Token   string
	Path    string
	Command string

	Net jailNetInfo
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
	cap: "CAP_NET_RAW"
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
	}
	gidmap {
		inside_id: "0"
		outside_id: "{{ .Config.GIDStart }}"
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
		src: "/lib64"
		dst: "/lib64"
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
		src: "/etc/ssl"
		dst: "/etc/ssl"
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
		src_content: "{{ .User.Username }}:x:0:0::/home/{{ .User.Username }}:/usr/bin/fish\n"
	}
	mount {
		dst: "/etc/group"
		src_content: "{{ .User.Username }}:x:0:\n"
	}
	mount {
		dst: "/etc/resolv.conf"
		src_content: "nameserver 1.1.1.1\nnameserver 1.0.0.1\n"
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
		src_content: "last_update_check: 9999-12-31T23:59:59Z\ntoken: {{ .Token }}\n"
		rw: true
	}

	seccomp_string: "KILL { syslog }"
	seccomp_string: "DEFAULT ALLOW"

	macvlan_iface: "{{ .Config.Network.Interface }}-jail"
	macvlan_vs_ip: "{{ .Net.IP }}"
	macvlan_vs_nm: "{{ .Net.Mask }}"
	macvlan_vs_gw: "{{ .Config.Network.Address.IP }}"

	exec_bin {
		path: "/bin/su"
		arg0: "su"
		arg: "-"
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

	la := netlink.NewLinkAttrs()
	la.Name = c.Network.Interface + "-host"
	existingVeth, err := netlink.LinkByName(la.Name)
	if err == nil {
		if err := netlink.LinkDel(existingVeth); err != nil {
			return fmt.Errorf("failed to delete existing veth pair: %w", err)
		}
	} else if !errors.As(err, &netlink.LinkNotFoundError{}) {
		return fmt.Errorf("failed to check for existing veth pair: %w", err)
	}

	jailVethName := c.Network.Interface + "-jail"
	veth := &netlink.Veth{
		LinkAttrs: la,
		PeerName:  jailVethName,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("failed to create veth pair: %w", err)
	}
	if err := netlink.LinkSetUp(veth); err != nil {
		return fmt.Errorf("failed to set host veth up: %w", err)
	}
	if err := netlink.AddrAdd(veth, &netlink.Addr{IPNet: &c.Network.Address}); err != nil {
		return fmt.Errorf("failed to add IP to host veth: %w", err)
	}

	jailVeth, err := netlink.LinkByName(jailVethName)
	if err != nil {
		return fmt.Errorf("failed to get jail veth: %w", err)
	}
	if err := netlink.LinkSetUp(jailVeth); err != nil {
		return fmt.Errorf("failed to set jail veth up: %w", err)
	}

	if err := exec.Command("firewall.sh", c.Network.Address.String()).Run(); err != nil {
		return fmt.Errorf("failed to set up firewall: %w", err)
	}

	return nil
}

// NewShellJail creates a new exec.Cmd for running fish in an nsjail
func NewShellJail(c *JailConfig, u *iam.User, token, pathVar, command string) (*exec.Cmd, error) {
	filename := path.Join(c.TmpDir, fmt.Sprintf("u%v.cfg", u.Id))

	f, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to create tempfile: %w", err)
	}

	info := jailInfo{
		Config:  c,
		User:    u,
		Token:   token,
		Path:    pathVar,
		Command: command,
	}

	if c.Network.Interface != "" {
		var ipNum uint32
		netIPBuf := bytes.NewBuffer(c.Network.Address.IP.To4())
		if err := binary.Read(netIPBuf, binary.BigEndian, &ipNum); err != nil {
			return nil, fmt.Errorf("failed to convert IP address to uint32: %w", err)
		}
		ipNum += uint32(u.Id)

		var ipBuf bytes.Buffer
		binary.Write(&ipBuf, binary.BigEndian, ipNum)
		info.Net = jailNetInfo{
			IP:   net.IP(ipBuf.Bytes()),
			Mask: allAddr.Mask(c.Network.Address.Mask).String(),
		}
	}

	if err := configTemplate.Execute(f, info); err != nil {
		return nil, fmt.Errorf("failed to render config template: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("failed to close tempfile: %w", err)
	}

	return exec.Command("nsjail", "--config", f.Name()), nil
}
