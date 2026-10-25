//go:build linux

package reqtap

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Run captures until ctx ends. It needs CAP_NET_RAW in the network namespace
// whose services it records (kodeblue's own). onPorts, when set, is told the
// recorded ports whenever they change.
func Run(ctx context.Context, rec *Recorder, onPorts func([]uint16)) error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("raw socket (needs CAP_NET_RAW): %w", err)
	}
	defer unix.Close(fd)
	if err := attachTCPFilter(fd); err != nil {
		return fmt.Errorf("packet filter: %w", err)
	}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
	lo := -1
	if ifi, err := net.InterfaceByName("lo"); err == nil {
		lo = ifi.Index
	}
	refresh := func() {
		ports := listeningPorts()
		old := rec.Ports()
		rec.SetPorts(ports)
		if onPorts != nil && !samePorts(old, ports) {
			onPorts(rec.Ports())
		}
	}
	refresh()
	defer rec.Close()
	buf := make([]byte, 65536)
	lastRefresh, lastFlush := time.Now(), time.Now()
	for ctx.Err() == nil {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err == nil {
			if ll, ok := from.(*unix.SockaddrLinklayer); ok && !(ll.Ifindex == lo && ll.Pkttype == unix.PACKET_OUTGOING) {
				// Loopback traffic is seen twice, as sent and as received.
				rec.Packet(buf[:n])
			}
		} else if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			return fmt.Errorf("capture: %w", err)
		}
		if time.Since(lastFlush) >= time.Second {
			rec.Flush()
			lastFlush = time.Now()
		}
		if time.Since(lastRefresh) >= 10*time.Second {
			refresh()
			lastRefresh = time.Now()
		}
	}
	return nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// attachTCPFilter keeps only TCP packets (IPv4 or IPv6) in the kernel, cut
// to 4 KB: enough for a request line and its headers.
func attachTCPFilter(fd int) error {
	const (
		ldH   = 0x28       // BPF_LD|BPF_H|BPF_ABS
		ldB   = 0x30       // BPF_LD|BPF_B|BPF_ABS
		jeqK  = 0x15       // BPF_JMP|BPF_JEQ|BPF_K
		retK  = 0x06       // BPF_RET|BPF_K
		proto = 0xfffff000 // SKF_AD_OFF + SKF_AD_PROTOCOL
	)
	prog := []unix.SockFilter{
		{Code: ldH, K: proto},
		{Code: jeqK, Jt: 0, Jf: 2, K: 0x0800},
		{Code: ldB, K: 9},
		{Code: jeqK, Jt: 3, Jf: 4, K: 6},
		{Code: jeqK, Jt: 0, Jf: 3, K: 0x86dd},
		{Code: ldB, K: 6},
		{Code: jeqK, Jt: 0, Jf: 1, K: 6},
		{Code: retK, K: 4096},
		{Code: retK, K: 0},
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: (*unix.SockFilter)(unsafe.Pointer(&prog[0]))}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog)
}

func samePorts(a []uint16, b map[uint16]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for _, p := range a {
		if !b[p] {
			return false
		}
	}
	return true
}

// listeningPorts are the TCP ports listening in this network namespace,
// except kodeblue's own (its engine's API is HTTP too).
func listeningPorts() map[uint16]bool {
	own := ownSocketInodes()
	ports := map[uint16]bool{}
	for _, f := range []string{"/proc/self/net/tcp", "/proc/self/net/tcp6"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			fl := strings.Fields(line)
			if len(fl) < 10 || fl[3] != "0A" || own[fl[9]] {
				continue
			}
			parts := strings.Split(fl[1], ":")
			if len(parts) != 2 {
				continue
			}
			if raw, err := hex.DecodeString(parts[1]); err == nil && len(raw) == 2 {
				ports[uint16(raw[0])<<8|uint16(raw[1])] = true
			}
		}
	}
	return ports
}

// ownSocketInodes are the sockets of kodeblue and the processes it started.
func ownSocketInodes() map[string]bool {
	self := os.Getpid()
	parent := map[int]int{}
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		s := string(b)
		if i := strings.LastIndexByte(s, ')'); i >= 0 {
			if fl := strings.Fields(s[i+1:]); len(fl) > 1 {
				parent[pid], _ = strconv.Atoi(fl[1])
			}
		}
	}
	mine := func(pid int) bool {
		for i := 0; i < 64 && pid > 1; i++ {
			if pid == self {
				return true
			}
			pid = parent[pid]
		}
		return false
	}
	out := map[string]bool{}
	for pid := range parent {
		if !mine(pid) {
			continue
		}
		fds, _ := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		for _, fd := range fds {
			l, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
			if err == nil && strings.HasPrefix(l, "socket:[") {
				out[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = true
			}
		}
	}
	return out
}
