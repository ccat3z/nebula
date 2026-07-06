package udp

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
)

// PacketConnConn wraps an arbitrary net.PacketConn so it satisfies nebula's
// udp.Conn interface.
//
// It is intended for embedding scenarios (e.g. sing-box) where the outer UDP
// socket is created and owned by the host application rather than by nebula
// itself. The behavior mirrors udp.GenericConn (udp_generic.go): packets are
// read one at a time and handed to the registered EncReader callback.
//
// Unlike GenericConn, which embeds *net.UDPConn, this wraps net.PacketConn so it
// works with any wrapper (sing-box's dialer returns a tracked/routed
// PacketConn, not a bare *net.UDPConn).
type PacketConnConn struct {
	pc net.PacketConn
	l  *logrus.Logger
}

var _ Conn = &PacketConnConn{}

// NewPacketConnConn wraps an existing net.PacketConn as a nebula udp.Conn.
// Ownership of conn is transferred: Close() will close it.
func NewPacketConnConn(l *logrus.Logger, conn net.PacketConn) *PacketConnConn {
	return &PacketConnConn{pc: conn, l: l}
}

func (u *PacketConnConn) WriteTo(b []byte, addr netip.AddrPort) error {
	udpAddr := net.UDPAddrFromAddrPort(addr)
	if udpAddr == nil {
		return fmt.Errorf("invalid addrport: %s", addr)
	}
	_, err := u.pc.WriteTo(b, udpAddr)
	return err
}

func (u *PacketConnConn) LocalAddr() (netip.AddrPort, error) {
	switch v := u.pc.LocalAddr().(type) {
	case *net.UDPAddr:
		addr, ok := netip.AddrFromSlice(v.IP)
		if !ok {
			return netip.AddrPort{}, fmt.Errorf("LocalAddr returned invalid IP address: %s", v.IP)
		}
		return netip.AddrPortFrom(addr.Unmap(), uint16(v.Port)), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("LocalAddr returned: %#v", u.pc.LocalAddr())
	}
}

func (u *PacketConnConn) ListenOut(r EncReader, lhf LightHouseHandlerFunc, cache *firewall.ConntrackCacheTicker, q int) {
	plaintext := make([]byte, MTU)
	buffer := make([]byte, MTU)
	h := &header.H{}
	fwPacket := &firewall.Packet{}
	nb := make([]byte, 12, 12)

	for {
		// Just read one packet at a time
		n, rua, err := u.pc.ReadFrom(buffer)
		if err != nil {
			if u.l != nil {
				u.l.WithError(err).Debug("udp socket is closed, exiting read loop")
			}
			return
		}

		var addrPort netip.AddrPort
		switch v := rua.(type) {
		case *net.UDPAddr:
			if ap, ok := netip.AddrFromSlice(v.IP); ok {
				addrPort = netip.AddrPortFrom(ap.Unmap(), uint16(v.Port))
			} else {
				continue
			}
		default:
			continue
		}

		r(
			addrPort,
			plaintext[:0],
			buffer[:n],
			h,
			fwPacket,
			lhf,
			nb,
			q,
			cache.Get(u.l),
		)
	}
}

func (u *PacketConnConn) Rebind() error {
	return nil
}

func (u *PacketConnConn) ReloadConfig(c *config.C) {
	// TODO
}

func (u *PacketConnConn) Close() error {
	return u.pc.Close()
}
