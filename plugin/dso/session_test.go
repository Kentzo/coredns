package dso_test

import (
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/dso"
	"github.com/coredns/coredns/plugin/dso/internal/testutil"
	"github.com/miekg/dns"
)

// func TestDefaultKeepAlive(t *testing.T) {
// 	t.Parallel()

// 	tcs := []struct {
// 		idleTimeout time.Duration
// 		want        dns.DSOKeepAlive
// 	}{
// 		{-1 * time.Second, dns.DSOKeepAlive{InactivityTimeout: 0, KeepAliveInterval: uint32(dns.DSOKeepAliveIntervalMin.Milliseconds())}},
// 		{0, dns.DSOKeepAlive{InactivityTimeout: 0, KeepAliveInterval: uint32(dns.DSOKeepAliveIntervalMin.Milliseconds())}},
// 		{1 * time.Second, dns.DSOKeepAlive{InactivityTimeout: 0, KeepAliveInterval: uint32(dns.DSOKeepAliveIntervalMin.Milliseconds())}},
// 		{9 * time.Second, dns.DSOKeepAlive{InactivityTimeout: 4000, KeepAliveInterval: uint32(dns.DSOKeepAliveIntervalMin.Milliseconds())}},
// 		{30 * time.Second, dns.DSOKeepAlive{InactivityTimeout: 15000, KeepAliveInterval: 15000}},
// 	}
// 	for _, tc := range tcs {
// 		t.Run(fmt.Sprintf("%v", tc.idleTimeout), func(t *testing.T) {
// 			t.Parallel()
// 			sesh := session.NewWithID(&test.ResponseWriter{TCP: true}, session.NewIDWithConn(&dnsserver.Server{IdleTimeout: tc.idleTimeout}, nil))
// 			if *sesh.DefaultKeepAlive != tc.want {
// 				t.Errorf("Expected (%v), got (%v)", tc.want, sesh.DefaultKeepAlive)
// 			}
// 		})
// 	}
// }

func TestSessionWaiting(t *testing.T) {
	t.Parallel()

	testutil.SetupWaitingSession(t, nil)
}

func TestSessionPending(t *testing.T) {
	t.Parallel()

	_, h, _ := testutil.SetupPendingSession(t, nil)
	t.Cleanup(func() { close(h.WriteC) })
}

func TestSessionEstablished(t *testing.T) {
	t.Parallel()

	testutil.SetupEstablishedSession(t, nil)
}

func TestSessionClosing(t *testing.T) {
	t.Parallel()

	testutil.SetupClosingSession(t, nil)
}

func TestSessionClosed(t *testing.T) {
	t.Parallel()

	testutil.SetupClosedSession(t, nil)
}

func TestWriteMsg(t *testing.T) {
	t.Parallel()

	t.Run(dso.SessionWaiting.String(), func(t *testing.T) {
		t.Parallel()

		tcs := []struct {
			name string
			msg  []byte
			want error
		}{
			{"Error REP", testutil.NewErrorRepMsg(1), nil},
			{"REP", testutil.NewRepMsg(1), nil},
			{"REQ", testutil.NewReqMsg(1), dso.ErrSessionState},
			{"UNI", testutil.NewUniMsg(), dso.ErrSessionState},
		}
		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				sesh := testutil.SetupWaitingSession(t, nil)

				gotErr := sesh.WriteMsg(tc.msg)
				if gotErr != tc.want {
					t.Errorf("Expected %v, got %v", tc.want, gotErr)
				}
			})
		}
	})

	t.Run(dso.SessionPending.String(), func(t *testing.T) {
		t.Parallel()

		tcs := []struct {
			name string
			msg  []byte
		}{
			{"Error REP", testutil.NewErrorRepMsg(2)},
			{"REP", testutil.NewRepMsg(2)},
			{"REQ", testutil.NewReqMsg(2)},
			{"UNI", testutil.NewUniMsg()},
		}
		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				sesh, hook, _ := testutil.SetupPendingSession(t, nil)

				done := sesh.AsyncWriteMsg(tc.msg)
				select {
				case <-done:
					t.Errorf("Expected session to block.")
				case <-time.After(testutil.NoMessageTimeout):
				}

				close(hook.WriteC)
				sesh.AssertWrittenAnyMsg(t)
				gotMsg := sesh.AssertWrittenAnyMsg(t)
				if !slices.Equal(gotMsg, tc.msg) {
					t.Errorf("Expected %v, got %v", tc.msg, gotMsg)
				}
			})
		}
	})

	t.Run(dso.SessionEstablished.String(), func(t *testing.T) {
		t.Parallel()

		tcs := []struct {
			name string
			msg  []byte
		}{
			{"Error REP", testutil.NewErrorRepMsg(2)},
			{"REP", testutil.NewRepMsg(2)},
			{"REQ", testutil.NewReqMsg(2)},
			{"UNI", testutil.NewUniMsg()},
		}
		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				sesh := testutil.SetupEstablishedSession(t, nil)

				sesh.WriteMsg(tc.msg)
				gotMsg := sesh.AssertWrittenAnyMsg(t)
				if !slices.Equal(gotMsg, tc.msg) {
					t.Errorf("Expected %v, got %v", tc.msg, gotMsg)
				}
			})
		}
	})

	t.Run(dso.SessionClosing.String(), func(t *testing.T) {
		t.Parallel()

		tcs := []struct {
			name    string
			msg     []byte
			wantErr error
			wantMsg bool
		}{
			{"Error REP", testutil.NewErrorRepMsg(2), nil, true},
			{"REP", testutil.NewRepMsg(2), dso.ErrSessionClosed, false},
			{"REQ", testutil.NewReqMsg(2), dso.ErrSessionClosed, false},
			{"UNI", testutil.NewUniMsg(), dso.ErrSessionClosed, false},
		}
		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				sesh := testutil.SetupClosingSession(t, nil)

				gotErr := sesh.WriteMsg(tc.msg)
				if gotErr != tc.wantErr {
					t.Errorf("Expected %v, got %v", tc.wantErr, gotErr)
				}

				if tc.wantMsg {
					gotMsg := sesh.AssertWrittenAnyMsg(t)
					if !slices.Equal(gotMsg, tc.msg) {
						t.Errorf("Expected %v, got %v", tc.msg, gotMsg)
					}
				} else {
					sesh.AssertWrittenNoMsg(t)
				}
			})
		}
	})

	t.Run(dso.SessionClosed.String(), func(t *testing.T) {
		t.Parallel()

		tcs := []struct {
			name    string
			msg     []byte
			wantErr error
			wantMsg bool
		}{
			{"Error REP", testutil.NewErrorRepMsg(2), nil, true},
			{"REP", testutil.NewRepMsg(2), dso.ErrSessionClosed, false},
			{"REQ", testutil.NewReqMsg(2), dso.ErrSessionClosed, false},
			{"UNI", testutil.NewUniMsg(), dso.ErrSessionClosed, false},
		}
		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				sesh := testutil.SetupClosedSession(t, nil)

				gotErr := sesh.WriteMsg(tc.msg)
				if gotErr != tc.wantErr {
					t.Errorf("Expected %v, got %v", tc.wantErr, gotErr)
				}

				if tc.wantMsg {
					gotMsg := sesh.AssertWrittenAnyMsg(t)
					if !slices.Equal(gotMsg, tc.msg) {
						t.Errorf("Expected %v, got %v", tc.msg, gotMsg)
					}
				} else {
					sesh.AssertWrittenNoMsg(t)
				}
			})
		}
	})
}

func TestWriteCloseMsg(t *testing.T) {
	t.Parallel()

	t.Run(dso.SessionWaiting.String(), func(t *testing.T) {
		t.Parallel()

		sesh := testutil.SetupWaitingSession(t, nil)

		gotErr := sesh.WriteCloseMsg(dns.RcodeSuccess, 0)
		if gotErr != nil {
			t.Errorf("Expected no error, got %v", gotErr)
		}
		sesh.AssertState(t, dso.SessionClosed)
	})

	t.Run(dso.SessionPending.String(), func(t *testing.T) {
		t.Parallel()

		sesh, establishingH, _ := testutil.SetupPendingSession(t, nil)

		var (
			buf [dso.MsgHeaderLen + dso.TLVHeaderLen + dso.KeepAliveLen]byte
			b   = dso.NewMsgBuilder(buf[:])
		)
		b.SetMsgHeader(dso.MsgHeader{ID: 0, Response: false, Rcode: dns.RcodeSuccess})
		b.WriteRetryDelay(dso.RetryDelay{})
		closeDone := sesh.AsyncWriteMsg(b.Message())
		select {
		case <-closeDone:
			t.Error("Expected close to wait")
		case <-time.After(testutil.NoMessageTimeout):
		}

		close(establishingH.WriteC)
		sesh.AssertWrittenAnyMsg(t)

		gotErr := <-closeDone
		if gotErr != nil {
			t.Errorf("Expected no error, got %v", gotErr)
		}
		sesh.AssertWrittenCloseMsg(t)
		sesh.AssertState(t, dso.SessionClosing)
	})

	t.Run(dso.SessionEstablished.String(), func(t *testing.T) {
		t.Parallel()

		sesh := testutil.SetupEstablishedSession(t, nil)

		gotErr := sesh.WriteCloseMsg(dns.RcodeSuccess, 0)
		if gotErr != nil {
			t.Errorf("Expected no error, got %v", gotErr)
		}
		sesh.AssertWrittenCloseMsg(t)
		sesh.AssertState(t, dso.SessionClosing)
	})

	t.Run(dso.SessionClosing.String(), func(t *testing.T) {
		t.Parallel()

		sesh := testutil.SetupClosingSession(t, nil)

		gotErr := sesh.WriteCloseMsg(dns.RcodeSuccess, 0)
		if gotErr != dso.ErrSessionClosed {
			t.Errorf("Expected %v, got %v", dso.ErrSessionClosed, gotErr)
		}
		sesh.AssertWrittenNoMsg(t)
		sesh.AssertState(t, dso.SessionClosing)
	})

	t.Run(dso.SessionClosed.String(), func(t *testing.T) {
		t.Parallel()

		sesh := testutil.SetupClosedSession(t, nil)

		gotErr := sesh.WriteCloseMsg(dns.RcodeSuccess, 0)
		if gotErr != dso.ErrSessionClosed {
			t.Errorf("Expected %v, got %v", dso.ErrSessionClosed, gotErr)
		}
		sesh.AssertWrittenNoMsg(t)
		sesh.AssertState(t, dso.SessionClosed)
	})
}

func TestWriteEstablishingResponseSendsKeepAlive(t *testing.T) {
	t.Parallel()

	sesh := testutil.NewSession(t, nil)

	var (
		buf [dso.MsgHeaderLen]byte
		b   = dso.NewMsgBuilder(buf[:])
	)
	b.SetMsgHeader(dso.MsgHeader{ID: 1, Response: true, Rcode: dns.RcodeSuccess})
	sesh.WriteMsg(b.Message())
	sesh.AssertWrittenAnyMsg(t)
	sesh.AssertState(t, dso.SessionEstablished)

	gotMsg := sesh.AssertWrittenAnyMsg(t)
	m, err := UnpackMsg(gotMsg, dso.OriginServer)
	if err != nil {
		t.Fatalf("Expected to unpack message, got %v", err)
	}
	if m.TLV[0].Type() != dso.TypeKeepAlive {
		t.Errorf("Expected KeepAlive unidirectional, got %v", gotMsg)
	}
}

func TestWriteEstablishingResponseError(t *testing.T) {
	t.Parallel()

	sesh, hook, done := testutil.SetupPendingSession(t, nil)

	wantErr := fmt.Errorf("")
	hook.WriteC <- wantErr
	gotErr := <-done
	if gotErr != wantErr {
		t.Errorf("Expected %v, got %v", wantErr, gotErr)
	}
	sesh.AssertState(t, dso.SessionClosed)
}

func TestWriteMsgError(t *testing.T) {
	t.Parallel()

	t.Run(dso.SessionWaiting.String(), func(t *testing.T) {
		t.Parallel()

		sesh := testutil.SetupWaitingSession(t, nil)

		h, done := sesh.HookWriteMsg(testutil.NewErrorRepMsg(2))
		wantErr := fmt.Errorf("")
		h.WriteC <- wantErr
		gotErr := <-done
		if gotErr != wantErr {
			t.Errorf("Expected %v, got %v", wantErr, gotErr)
		}
		sesh.AssertState(t, dso.SessionClosed)
	})

	t.Run(dso.SessionPending.String(), func(t *testing.T) {
		t.Parallel()

		sesh, establishingHook, establishingDone := testutil.SetupPendingSession(t, nil)

		h, done := sesh.HookWriteMsg(testutil.NewErrorRepMsg(2))
		wantErr := fmt.Errorf("")
		h.WriteC <- wantErr

		close(establishingHook.WriteC)
		gotErr := <-establishingDone
		if gotErr != nil {
			t.Errorf("Expected no error, got %v", gotErr)
		}
		sesh.AssertState(t, dso.SessionEstablished)

		gotErr = <-done
		if gotErr != wantErr {
			t.Errorf("Expected %v, got %v", wantErr, gotErr)
		}
		sesh.AssertState(t, dso.SessionClosed)
	})

	t.Run(dso.SessionEstablished.String(), func(t *testing.T) {
		t.Parallel()

		sesh := testutil.SetupEstablishedSession(t, nil)

		h, done := sesh.HookWriteMsg(testutil.NewReqMsg(2))
		wantErr := fmt.Errorf("")
		h.WriteC <- wantErr
		gotErr := <-done
		if gotErr != wantErr {
			t.Errorf("Expected %v, got %v", wantErr, gotErr)
		}
		sesh.AssertState(t, dso.SessionClosed)
	})
}

func TestClose(t *testing.T) {
	t.Parallel()

	t.Run(dso.SessionWaiting.String(), func(t *testing.T) {
		t.Parallel()

		sesh := testutil.SetupWaitingSession(t, nil)

		sesh.ConnClosed()
		sesh.AssertState(t, dso.SessionClosed)
	})

	t.Run(dso.SessionPending.String(), func(t *testing.T) {
		t.Parallel()

		sesh, h, done := testutil.SetupPendingSession(t, nil)

		sesh.ConnClosed()
		sesh.AssertState(t, dso.SessionClosed)

		close(h.WriteC)
		gotErr := <-done
		if gotErr != dso.ErrSessionClosed {
			t.Errorf("Expected ErrSessionClosed, got %v", gotErr)
		}
		sesh.AssertState(t, dso.SessionClosed)
	})

	t.Run(dso.SessionEstablished.String(), func(t *testing.T) {
		t.Parallel()

		sesh := testutil.SetupEstablishedSession(t, nil)

		sesh.ConnClosed()
		sesh.AssertState(t, dso.SessionClosed)
	})

	t.Run(dso.SessionClosing.String(), func(t *testing.T) {
		t.Parallel()

		sesh := testutil.SetupClosingSession(t, nil)

		sesh.ConnClosed()
		sesh.AssertState(t, dso.SessionClosed)
	})

	t.Run(dso.SessionClosed.String(), func(t *testing.T) {
		t.Parallel()

		sesh := testutil.SetupClosedSession(t, nil)

		sesh.ConnClosed()
		sesh.AssertState(t, dso.SessionClosed)
	})
}

func TestForcedClose(t *testing.T) {
	t.Parallel()

	_, lconn, conn := testutil.SetupConn(t)
	sesh := testutil.SetupEstablishedSession(t, lconn.(*net.TCPConn))

	go func() { sesh.WriteCloseMsg(dns.RcodeSuccess, 0) }()
	testutil.AssertRST(t, conn)
}
