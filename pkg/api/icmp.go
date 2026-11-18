package api

import (
	"encoding/binary"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var icmpSeq uint32

// PingICMP sends one ICMP echo using an unprivileged datagram ping socket
// (works as root, or for users within net.ipv4.ping_group_range) and returns
// the round-trip time. The kernel assigns the echo identifier and checksum.
func PingICMP(ip string, timeout time.Duration) (time.Duration, error) {
	addr := net.ParseIP(ip).To4()
	if addr == nil {
		return 0, &net.AddrError{Err: "not an IPv4 address", Addr: ip}
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, syscall.IPPROTO_ICMP)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)

	tv := syscall.NsecToTimeval(int64(timeout))
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return 0, err
	}

	seq := uint16(atomic.AddUint32(&icmpSeq, 1))
	pkt := make([]byte, 16)
	pkt[0] = 8 // echo request
	binary.BigEndian.PutUint16(pkt[6:], seq)

	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], addr)
	deadline := time.Now().Add(timeout)
	start := time.Now()
	if err := syscall.Sendto(fd, pkt, 0, &sa); err != nil {
		return 0, err
	}
	buf := make([]byte, 128)
	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return 0, err
		}
		if n >= 8 && buf[0] == 0 && binary.BigEndian.Uint16(buf[6:]) == seq {
			return time.Since(start), nil
		}
	}
	return 0, syscall.ETIMEDOUT
}

// MeasureHopDelays pings every candidate `count` times with bounded
// concurrency and returns the median delay (ms) of each reachable one, as the
// SDK's ping tool does (ping_result_type "median"). Unreachable candidates
// are omitted.
func MeasureHopDelays(cands []HopCandidate, count int, timeout time.Duration, concurrency int) []HopDelay {
	if count < 1 {
		count = 1
	}
	if concurrency < 1 {
		concurrency = 1
	}
	var (
		mu  sync.Mutex
		out []HopDelay
		wg  sync.WaitGroup
	)
	sem := make(chan struct{}, concurrency)
	seen := map[string]bool{}
	for _, c := range cands {
		if c.IP == "" || seen[c.IP] {
			continue
		}
		seen[c.IP] = true
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var samples []float64
			for i := 0; i < count; i++ {
				if rtt, err := PingICMP(ip, timeout); err == nil {
					samples = append(samples, durationMs(rtt))
				}
			}
			if len(samples) == 0 {
				return
			}
			sort.Float64s(samples)
			mu.Lock()
			out = append(out, HopDelay{IP: ip, Delay: roundTenth(samples[len(samples)/2])})
			mu.Unlock()
		}(c.IP)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Delay < out[j].Delay })
	return out
}

func roundTenth(v float64) float64 {
	return float64(int64(v*10+0.5)) / 10
}
