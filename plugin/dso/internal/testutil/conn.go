package testutil

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"
)

type StubConn struct {
	local  net.Addr
	remote net.Addr
}

func (StubConn) Close() error                       { return nil }
func (conn StubConn) LocalAddr() net.Addr           { return conn.local }
func (StubConn) Read(b []byte) (n int, err error)   { return len(b), nil }
func (conn StubConn) RemoteAddr() net.Addr          { return conn.remote }
func (StubConn) SetDeadline(t time.Time) error      { return nil }
func (StubConn) SetReadDeadline(t time.Time) error  { return nil }
func (StubConn) SetWriteDeadline(t time.Time) error { return nil }
func (StubConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (StubConn) SetLinger(sec int) error            { return nil }

type WriteHook struct {
	OnEnterC chan struct{} // Closed upon WriteMsg entry.
	WriteC   chan error    // Holds WriteMsg until closed or written to.
	OnExitC  chan struct{} // Closed upon WriteMsg exit.
}

type WriteHookID struct {
	id       uint16
	response bool
}

type Conn struct {
	net.Conn

	TeeC   chan []byte
	mu     sync.RWMutex
	hooks  map[WriteHookID]WriteHook
	closed bool
}

var _ net.Conn = &Conn{}

func NewConn(conn net.Conn) *Conn {
	if conn == nil {
		conn = StubConn{}
	}
	return &Conn{
		Conn:  conn,
		hooks: make(map[WriteHookID]WriteHook),
		TeeC:  make(chan []byte, 64),
	}
}

// Hook installs a single shot hook for a given message ID request or response.
func (conn *Conn) Hook(id uint16, response bool) WriteHook {
	hookID := WriteHookID{id, response}
	if _, ok := conn.hooks[hookID]; ok {
		panic("duplicate hook")
	}
	hook := WriteHook{
		OnEnterC: make(chan struct{}),
		WriteC:   make(chan error, 1),
		OnExitC:  make(chan struct{}),
	}
	conn.hooks[hookID] = hook
	return hook
}

func (conn *Conn) Close() (err error) {
	if err = conn.Conn.Close(); err == nil {
		conn.mu.Lock()
		defer conn.mu.Unlock()

		conn.closed = true
		close(conn.TeeC)
	}
	return err
}

func (conn *Conn) Write(msg []byte) (n int, err error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.closed {
		return 0, fmt.Errorf("closed")
	}

	hookID := WriteHookID{binary.BigEndian.Uint16(msg), msg[2]&0x80 != 0}
	if hook, ok := conn.hooks[hookID]; ok {
		delete(conn.hooks, hookID)
		close(hook.OnEnterC)
		defer close(hook.OnExitC)
		err = <-hook.WriteC
		if err != nil {
			return 0, err
		}
	}
	n, err = conn.Conn.Write(msg)
	if err != nil {
		return n, err
	}
	conn.TeeC <- slices.Clone(msg)
	return len(msg), nil
}

func (conn *Conn) NetConn() net.Conn {
	return conn.Conn
}

func SetupConn(tb testing.TB) (list net.Listener, listconn, conn net.Conn) {
	tb.Helper()

	list, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		tb.Fatalf("Expected listener, got %v", err)
	}
	tb.Cleanup(func() {
		list.Close()
	})

	accepted := make(chan struct{})
	var lerr error
	go func() {
		defer close(accepted)
		defer list.Close()
		listconn, lerr = list.Accept()
		if lerr == nil {
			lerr = listconn.SetReadDeadline(time.Now().Add(10 * time.Second))
		}
		tb.Cleanup(func() {
			listconn.Close()
		})
	}()
	conn, err = net.Dial(list.Addr().Network(), list.Addr().String())
	if err != nil {
		tb.Fatalf("Expected to dial, got %v", err)
	}
	tb.Cleanup(func() {
		conn.Close()
	})
	<-accepted
	if lerr != nil {
		tb.Fatalf("Expected to accept, got %v", err)
	}
	return list, listconn, conn
}

func AssertRST(tb testing.TB, conn net.Conn) {
	tb.Helper()

	var gotErr error
	buf := make([]byte, 1024)
	for {
		_, gotErr = conn.Read(buf)
		if gotErr != nil {
			break
		}
	}
	if !errors.Is(gotErr, syscall.ECONNRESET) {
		tb.Errorf("Expected ECONNRESET, got %v", gotErr)
	}
}
