package dso

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestSplitPushMsg(t *testing.T) {
	t.Parallel()

	var template string = `%02d.test 10 IN TXT "` + strings.Repeat("T", 1145) + `"`

	tcs := []struct {
		name   string
		repeat int
		want   int
	}{
		{"below", 13, 1},
		{"at", 14, 1},
		{"above", 15, 2},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := new(dns.Msg)
			dns.SetDSOUnidirectional(m)
			tlv := &dns.DSOPush{}
			m.Stateful = append(m.Stateful, tlv)

			for i := 0; i < tc.repeat; i++ {
				rr, err := dns.NewRR(fmt.Sprintf(template, i))
				if err != nil {
					t.Fatalf("Expected new RR, go %v", err)
				}
				if l := dns.Len(rr); l != 1169 {
					t.Fatalf("Expected RR of size 1169, got %d", l)
				}
				tlv.Change = append(tlv.Change, rr)
			}

			got := slices.Collect(splitPushMsg(m))
			if len(got) != tc.want {
				t.Fatalf("Expected %d messages, got %d", tc.want, len(got))
			}

			if tc.want == 1 {
				if m != got[0] {
					t.Fatalf("Expected exactly the same message, got %v", got[0])
				}
			} else {
				got_rrs := make([]dns.RR, 0, tc.repeat)
				for _, m1 := range got {
					got_rrs = append(got_rrs, m1.Stateful[0].(*dns.DSOPush).Change...)
				}
				if !slices.Equal(got_rrs, tlv.Change) {
					t.Fatalf("Expected the same change, got a mismatch")
				}
			}
		})
	}
}
