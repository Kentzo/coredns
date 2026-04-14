package testutil

import (
	"testing"

	"github.com/miekg/dns"
)

func EnableDSO(tb testing.TB) {
	tb.Helper()

	origAccept := dns.DefaultMsgAcceptFunc
	dns.DefaultMsgAcceptFunc = func(dh dns.Header) dns.MsgAcceptAction {
		return dns.MsgAccept
	}
	tb.Cleanup(func() {
		dns.DefaultMsgAcceptFunc = origAccept
	})

	origInvalid := dns.DefaultMsgInvalidFunc
	dns.DefaultMsgInvalidFunc = func(m []byte, err error) {
		tb.Errorf("Server received invalid message")
	}
	tb.Cleanup(func() {
		dns.DefaultMsgInvalidFunc = origInvalid
	})
}
