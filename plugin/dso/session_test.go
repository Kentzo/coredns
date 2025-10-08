package dso

import (
	"errors"
	"testing"

	"github.com/miekg/dns"
)

func TestIsValidState(t *testing.T) {
	t.Parallel()

	ka := &dns.DSOKeepAlive{}

	req := new(dns.Msg)
	dns.SetDSORequest(req, 1)
	req.Stateful = append(req.Stateful, ka)

	rep := new(dns.Msg)
	rep.Id = 1
	rep.Response = true
	rep.Opcode = dns.OpcodeStateful
	rep.Rcode = dns.RcodeSuccess

	uni := new(dns.Msg)
	dns.SetDSOUnidirectional(uni)
	uni.Stateful = append(uni.Stateful, ka)

	tcs := []struct {
		name string; state SessionState; m *dns.Msg; want error
	} {
		{"Waiting/REQ", SessionWaiting, req, nil},
		{"Waiting/REP", SessionWaiting, rep, ErrSessionState},
		{"Waiting/UNI", SessionWaiting, uni, ErrSessionState},
		{"Pending/REQ", SessionPending, req, ErrSessionState},
		{"Pending/REP", SessionPending, rep, ErrSessionState},
		{"Pending/UNI", SessionPending, uni, ErrSessionState},
		{"Established/REQ", SessionEstablished, req, nil},
		{"Established/REP", SessionEstablished, rep, nil},
		{"Established/UNI", SessionEstablished, uni, nil},
		{"Closed/REQ", SessionClosed, req, ErrSessionClosed},
		{"Closed/REP", SessionClosed, rep, ErrSessionClosed},
		{"Closed/UNI", SessionClosed, uni, ErrSessionClosed},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sesh := Session{}
			sesh.state.Store(uint32(tc.state))
			if got := sesh.IsValidState(tc.m); !errors.Is(got, tc.want) {
				t.Errorf("Expected %v, got %v", tc.want, got)
			}
		})
	}
}
