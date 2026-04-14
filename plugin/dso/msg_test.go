package dso_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/coredns/coredns/plugin/dso"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

type Msg struct {
	Header dso.MsgHeader
	TLV    []dso.TLV
}

func (m Msg) Equal(m1 Msg) bool {
	return m.Header == m1.Header && slices.EqualFunc(m.TLV, m1.TLV, func(tlv, tlv1 dso.TLV) bool { return tlv.Equal(tlv1) })
}

func (m Msg) Pack(b *dso.MsgBuilder) (msg []byte, err error) {
	err = b.SetMsgHeader(m.Header)
	if err != nil {
		return nil, err
	}
	for _, tlv := range m.TLV {
		err = b.WriteTLV(tlv)
		if err != nil {
			return nil, err
		}
	}
	return b.Message(), nil
}

func UnpackMsg(msg []byte, o dso.Origin) (m Msg, err error) {
	var p dso.MsgParser
	if m.Header, err = p.Start(msg, o); err != nil {
		return Msg{}, err
	}
	var tlv dso.TLV
	for {
		_, err = p.TLVHeader()
		if err != nil {
			break
		}
		tlv, err = p.TLV()
		if err != nil {
			break
		}
		m.TLV = append(m.TLV, tlv)
	}
	if err != dso.ErrDone {
		return Msg{}, err
	}
	return m, nil
}

var (
	testMsg = Msg{
		Header: dso.MsgHeader{42, true, dns.RcodeStatefulTypeNotImplemented},
		TLV: []dso.TLV{
			dso.KeepAlive{dso.InactivityTimeoutDefault, dso.KeepAliveIntervalDefault},
			dso.RetryDelay{60 * 1000},
			dso.EncryptionPadding{8},
			dso.Subscribe{"test.", dns.TypeA, dns.ClassINET},
			dso.Push{[]dns.RR{test.A("test. IN A 192.0.2.1")}},
			dso.Unsubscribe{9000},
			dso.Reconfirm{test.A("test. IN A 192.0.2.1")},
		},
	}
	testMsgBytes = [...]byte{
		0x00, 0x2a, 0xb0, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MsgHeader
		0x00, 0x01, 0x00, 0x08, // KeepAlive Header
		0x00, 0x00, 0x3a, 0x98, 0x00, 0x00, 0x3a, 0x98, // KeepAlive
		0x00, 0x02, 0x00, 0x04, // RetryDelay Header
		0x00, 0x00, 0xea, 0x60, // RetryDelay
		0x00, 0x03, 0x00, 0x08, // EncryptionPadding Header
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EncryptionPadding
		0x00, 0x40, 0x00, 0x0a, // Subscribe Header
		0x04, 0x74, 0x65, 0x73, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, // Subscribe
		0x00, 0x41, 0x00, 0x14, // Push Header
		0x04, 0x74, 0x65, 0x73, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x01, // Push
		0x00, 0x42, 0x00, 0x02, // Unsubscribe Header
		0x23, 0x28, // Unsubscribe
		0x00, 0x43, 0x00, 0x0e, // Reconfirm Header
		0x04, 0x74, 0x65, 0x73, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x00, 0x02, 0x01, // Reconfirm
	}
	testMsgCompressedBytes = [...]byte{
		0x00, 0x2a, 0xb0, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MsgHeader
		0x00, 0x01, 0x00, 0x08, // KeepAlive Header
		0x00, 0x00, 0x3a, 0x98, 0x00, 0x00, 0x3a, 0x98, // KeepAlive
		0x00, 0x02, 0x00, 0x04, // RetryDelay Header
		0x00, 0x00, 0xea, 0x60, // RetryDelay
		0x00, 0x03, 0x00, 0x08, // EncryptionPadding Header
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EncryptionPadding
		0x00, 0x40, 0x00, 0x0a, // Subscribe Header
		0x04, 0x74, 0x65, 0x73, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, // Subscribe
		0x00, 0x41, 0x00, 0x10, // Push Header
		0xc0, 0x30, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x01, // Push
		0x00, 0x42, 0x00, 0x02, // Unsubscribe Header
		0x23, 0x28, // Unsubscribe
		0x00, 0x43, 0x00, 0x0e, // Reconfirm Header
		0x4, 0x74, 0x65, 0x73, 0x74, 0x0, 0x0, 0x1, 0x0, 0x1, 0xc0, 0x0, 0x2, 0x1, // Reconfirm
	}
)

func TestBuilderAllocs(t *testing.T) {
	var (
		buf [128]byte
		b   = dso.NewMsgBuilder(buf[:])
	)
	n := testing.AllocsPerRun(100, func() {
		msgBytes, err := testMsg.Pack(b)
		if err != nil {
			t.Errorf("Expected to pack message, got %v", err)
		}
		if len(msgBytes) == 0 {
			t.Errorf("Expected non-empty packed message")
		}
		b.Finish()
	})
	if n != 0 {
		t.Errorf("Expected no allocations, got %v", n)
	}
}

func TestParserAllocs(t *testing.T) {
	n := testing.AllocsPerRun(100, func() {
		p := dso.MsgParser{}
		p.Start(testMsgBytes[:], dso.OriginClient)
		_, err := p.TLVHeader()
		if err != nil {
			t.Fail()
		}
		_, err = p.KeepAlive()
		if err != nil {
			t.Fail()
		}

		_, err = p.TLVHeader()
		if err != nil {
			t.Fail()
		}
		_, err = p.RetryDelay()
		if err != nil {
			t.Fail()
		}

		_, err = p.TLVHeader()
		if err != nil {
			t.Fail()
		}
		_, err = p.EncryptionPadding()
		if err != nil {
			t.Fail()
		}

		_, err = p.TLVHeader()
		if err != nil {
			t.Fail()
		}
		err = p.SkipTLV()
		if err != nil {
			t.Fail()
		}

		_, err = p.TLVHeader()
		if err != nil {
			t.Fail()
		}
		err = p.SkipTLV()
		if err != nil {
			t.Fail()
		}

		_, err = p.TLVHeader()
		if err != nil {
			t.Fail()
		}
		_, err = p.Unsubscribe()
		if err != nil {
			t.Fail()
		}

		_, err = p.TLVHeader()
		if err != nil {
			t.Fail()
		}
		err = p.SkipTLV()
		if err != nil {
			t.Fail()
		}

		if _, err = p.TLVHeader(); err != dso.ErrDone {
			t.Errorf("Expected parser to be done")
		}
	})
	if n != 0 {
		t.Errorf("Expected no allocations, got %v", n)
	}
}

func TestBuildParseParity(t *testing.T) {
	t.Parallel()

	var (
		buf [128]byte
		b   = dso.NewMsgBuilder(buf[:])
	)
	t.Run("uncompressed", func(t *testing.T) {
		msgBytes, err := testMsg.Pack(b)
		if err != nil {
			t.Errorf("Expected to pack message, got %v", err)
		}
		if !slices.Equal(msgBytes, testMsgBytes[:]) {
			t.Errorf("Expected packed messages to be equal")
		}

		msg, err := UnpackMsg(msgBytes, dso.OriginClient)
		if err != nil {
			t.Errorf("Expected to unpack message, got %v", err)
		}
		if !msg.Equal(testMsg) {
			t.Errorf("Expected messages to be equal")
		}
		b.Finish()
	})

	t.Run(" compressed", func(t *testing.T) {
		b.EnableCompression()
		msgBytes, err := testMsg.Pack(b)
		if err != nil {
			t.Errorf("Expected to pack message, got %v", err)
		}
		if !slices.Equal(msgBytes, testMsgCompressedBytes[:]) {
			t.Errorf("Expected packed messages to be equal")
		}

		msg, err := UnpackMsg(msgBytes, dso.OriginClient)
		if err != nil {
			t.Errorf("Expected to unpack message, got %v", err)
		}
		if !msg.Equal(testMsg) {
			t.Errorf("Expected messages to be equal")
		}
		b.Finish()
	})
}

func TestParseMalformed(t *testing.T) {
	t.Parallel()

	msgBytes := slices.Clone(testMsgBytes[:])

	t.Run("Malformed MsgHeader", func(t *testing.T) {
		var p dso.MsgParser
		_, err := p.Start(msgBytes[:dso.MsgHeaderLen-1], dso.OriginClient)
		if err == nil {
			t.Errorf("Expected parser to fail")
		}
	})
}

func TestBuilderPadding(t *testing.T) {
	t.Parallel()

	var (
		buf      [128]byte
		b        = dso.NewMsgBuilder(buf[:])
		blockLen = dso.MsgHeaderLen + 1
	)
	b.EnablePadding(uint16(blockLen))
	b.SetMsgHeader(dso.MsgHeader{})
	if len(b.Message())%blockLen != 0 {
		t.Errorf("Expected padded message")
	}
	b.Finish()
}

func FuzzParser(f *testing.F) {
	f.Add(testMsgBytes[:])
	f.Add(testMsgCompressedBytes[:])
	f.Fuzz(func(t *testing.T, in []byte) {
		var (
			parser    dso.MsgParser
			msgHeader dso.MsgHeader
			tlv       dso.TLV
			err       error
		)
		msgHeader, err = parser.Start(in, dso.OriginServer)
		if err == nil {
			err = msgHeader.Verify()
		}
		if err != nil && !errors.Is(err, dso.ErrMsgHeader) {
			t.Fatalf("Unexpected error %v", err)
		}
		for {
			_, err = parser.TLVHeader()
			if err == nil {
				tlv, err = parser.TLV()
				if err == nil {
					err = tlv.Verify(parser.TLVUsage())
				} else if errors.Is(err, dso.ErrTLV) {
					err = parser.SkipTLV()
				}
			}
			if err == dso.ErrDone || errors.Is(err, dso.ErrTLV) {
				break
			} else if err != nil {
				t.Fatalf("Unexpected error %v", err)
			}
		}
	})
}
