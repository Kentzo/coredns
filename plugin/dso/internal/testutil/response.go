//go:build ignore
package testutil

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

type WriteHook struct {
	OnEnterC chan struct{} // Closed upon WriteMsg entry.
	WriteC   chan error    // Holds WriteMsg until closed or written to.
	OnExitC  chan struct{} // Closed upon WriteMsg exit.
}

type WriteHookID struct {
	id       uint16
	response bool
}

type HookableWriter struct {
	dns.ResponseWriter

	MsgsC  chan *dns.Msg
	mu     sync.RWMutex
	hooked map[WriteHookID]WriteHook
	closed bool
	tcp    net.Conn
}

// Hook installs a single shot hook for a given message ID request or response.
func (w *HookableWriter) Hook(id uint16, response bool) WriteHook {
	e := WriteHook{
		OnEnterC: make(chan struct{}),
		WriteC:   make(chan error, 1),
		OnExitC:  make(chan struct{}),
	}
	w.hooked[WriteHookID{id, response}] = e
	return e
}

func (w *HookableWriter) Conn() net.Conn {
	return w.tcp
}

func (w *HookableWriter) Close() (err error) {
	if err = w.tcp.Close(); err == nil {
		w.mu.Lock()
		defer w.mu.Unlock()

		w.closed = true
		close(w.MsgsC)
	}
	return err
}

func (w *HookableWriter) ReadMsg() (m *dns.Msg, ok bool) {
	m, ok = <-w.MsgsC
	return m, ok
}

func (w *HookableWriter) ReadMsgWithTimeout(timeout time.Duration) (m *dns.Msg, ok bool) {
	select {
	case m, ok = <-w.MsgsC:
		return m, ok
	case <-time.After(timeout):
		return nil, ok
	}
}

func (w *HookableWriter) WriteMsg(m *dns.Msg) (err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return fmt.Errorf("closed")
	}

	hookID := WriteHookID{m.Id, m.Response}
	if e, ok := w.hooked[hookID]; ok {
		delete(w.hooked, hookID)
		close(e.OnEnterC)
		defer close(e.OnExitC)
		err = <-e.WriteC
		if err != nil {
			return err
		}
	} else {
		data, err := m.Pack()
		if err != nil {
			return err
		}
		_, err = w.tcp.Write(data)
		if err != nil {
			return err
		}
	}
	w.MsgsC <- m.Copy()
	return nil
}

func NewHookableWriter() *HookableWriter {
	return &HookableWriter{
		ResponseWriter: &test.ResponseWriter{TCP: true},
		hooked:         make(map[WriteHookID]WriteHook),
		MsgsC:          make(chan *dns.Msg, 64),
	}
}
