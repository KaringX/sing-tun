//go:build with_gvisor && darwin

package tun

import (
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/qdisc/fifo"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	fdbased "github.com/sagernet/sing-tun/internal/fdbased_darwin"
	rawfile "github.com/sagernet/sing-tun/internal/rawfile_darwin"

	"golang.org/x/sys/unix"
)

var _ GVisorTun = (*NativeTun)(nil)

func (t *NativeTun) WritePacket(pkt *stack.PacketBuffer) (int, error) {
	t.writePacketAccess.Lock()         //karing
	defer t.writePacketAccess.Unlock() //karing

	iovecs := t.iovecsOutputDefault[:0] //karing
	if pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber {
		iovecs = append(iovecs, packetHeaderVec4)
	} else {
		iovecs = append(iovecs, packetHeaderVec6)
	}
	var dataLen int
	for _, packetSlice := range pkt.AsSlices() {
		if len(packetSlice) == 0 { //karing
			continue
		}
		dataLen += len(packetSlice)
		iovec := unix.Iovec{
			Base: &packetSlice[0],
		}
		iovec.SetLen(len(packetSlice))
		iovecs = append(iovecs, iovec)
	}
	if dataLen == 0 { //karing
		return 0, nil
	}
	//if cap(iovecs) > cap(t.iovecsOutputDefault) { //karing
	t.iovecsOutputDefault = iovecs[:0]
	//} //karing
	errno := rawfile.NonBlockingWriteIovec(t.tunFd, iovecs)
	if errno == 0 {
		return dataLen, nil
	} else {
		return 0, errno
	}
}

func (t *NativeTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	ep, err := fdbased.New(&fdbased.Options{
		FDs:                  []int{t.tunFd},
		MTU:                  t.options.MTU,
		ProcessorsPerChannel: 1,
		RXChecksumOffload:    true,
		PacketDispatchMode:   fdbased.RecvMMsg,
		MultiPendingPackets:  t.options.EXP_MultiPendingPackets,
		SendMsgX:             t.options.EXP_SendMsgX,
	})
	if err != nil {
		return nil, stack.NICOptions{}, err
	}
	return ep, stack.NICOptions{
		QDisc: fifo.New(ep, 1, 1000),
	}, nil
}
