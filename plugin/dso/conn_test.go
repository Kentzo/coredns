package dso

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

type stubResponse struct {
	tcp net.Conn
}

var _ dns.ResponseWriter = &stubResponse{}

func (w *stubResponse) LocalAddr() net.Addr       { return nil }
func (w *stubResponse) RemoteAddr() net.Addr      { return nil }
func (w *stubResponse) WriteMsg(*dns.Msg) error   { return nil }
func (w *stubResponse) Write([]byte) (int, error) { return 0, nil }
func (w *stubResponse) Close() error              { return nil }
func (w *stubResponse) TsigStatus() error         { return nil }
func (w *stubResponse) TsigTimersOnly(bool)       {}
func (w *stubResponse) Hijack()                   {}

type wrapA struct {
	dns.ResponseWriter
}

type wrapB struct {
	dns.ResponseWriter
	tcp int
}

type wrapC struct {
	dns.ResponseWriter
}

func TestGetConn(t *testing.T) {
	t.Parallel()

	r := &stubResponse{
		tcp: &net.TCPConn{},
	}

	ra := &wrapA{r}
	rb := &wrapB{ra, 42}
	rc := &wrapC{rb}

	if conn := GetConn(rc).(*net.TCPConn); conn != r.tcp {
		t.Errorf("Expected %v, got %v", r.tcp, conn)
	}
}
