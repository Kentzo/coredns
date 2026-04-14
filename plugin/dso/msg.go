package dso

import (
	"encoding/binary"
	"errors"
	"fmt"
	"iter"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	MsgHeaderLen = 12
	TLVHeaderLen = 4

	KeepAliveLen   = 8
	RetryDelayLen  = 4
	UnsubscribeLen = 2
)

// PackError wraps dns.PackRR error by adding index of RR that failed to pack.
type PackError struct {
	Index int // index of RR that failed to pack
	cause error
}

func (e *PackError) Error() string {
	return fmt.Sprintf("failed to pack %d: %s", e.Index, e.cause.Error())
}

func (e *PackError) Unwrap() error { return e.cause }

var (
	// ErrDone indicates that all TLVs have been parsed.
	ErrDone      = fmt.Errorf("parser is done")
	ErrMsgHeader = fmt.Errorf("bad DSO header")
	ErrTLV       = fmt.Errorf("bad TLV")
)

type Type uint16

const (
	TypeKeepAlive         = Type(dns.StatefulTypeKeepAlive)
	TypeRetryDelay        = Type(dns.StatefulTypeRetryDelay)
	TypeEncryptionPadding = Type(dns.StatefulTypeEncryptionPadding)

	TypeSubscribe   Type = 0x0040
	TypePush        Type = 0x0041
	TypeUnsubscribe Type = 0x0042
	TypeReconfirm   Type = 0x0043
)

func (t Type) String() string {
	switch t {
	case TypeKeepAlive:
		return "KeepAlive"
	case TypeRetryDelay:
		return "RetryDelay"
	case TypeEncryptionPadding:
		return "EncryptionPadding"
	case TypeSubscribe:
		return "Subscribe"
	case TypePush:
		return "Push"
	case TypeUnsubscribe:
		return "Unsubscribe"
	case TypeReconfirm:
		return "Reconfirm"
	default:
		return "Type{0x" + strconv.FormatInt(int64(t), 16) + "}"
	}
}

// MsgHeader represents DSO DNS message header fields.
type MsgHeader struct {
	ID       uint16
	Response bool
	Rcode    uint8
}

// IsRequest returns true if the message is a DSO request.
func (h MsgHeader) IsRequest() bool {
	return h.ID != 0 && !h.Response
}

// IsUnidirectional returns true if the message is a DSO unidirectional.
func (h MsgHeader) IsUnidirectional() bool {
	return h.ID == 0 && !h.Response
}

// IsResponse returns true if the message is a DSO response.
func (h MsgHeader) IsResponse() bool {
	return h.ID != 0 && h.Response
}

func (h MsgHeader) Verify() error {
	if h.ID == 0 && h.Response {
		return ErrMsgHeader
	}
	return nil
}

func (h MsgHeader) pack(buf []byte, off int) int {
	buf = buf[off : off+MsgHeaderLen]
	v := uint32(h.ID)<<16 | dns.OpcodeStateful<<11 | uint32(h.Rcode)
	if h.Response {
		v |= 1 << 15
	}
	binary.BigEndian.PutUint32(buf, v)
	binary.BigEndian.PutUint64(buf[4:], 0)
	return off + MsgHeaderLen
}

func unpackMsgHeader(msg []byte, off int) (MsgHeader, int) {
	bits := binary.BigEndian.Uint16(msg[off+2:])
	return MsgHeader{
		binary.BigEndian.Uint16(msg[off:]),
		bits&(1<<15) != 0,
		uint8(bits & 0xF),
	}, off + MsgHeaderLen
}

// TLVHeader is the header of a DSO TLV.
type TLVHeader struct {
	Type   Type
	Length uint16
}

func (h TLVHeader) pack(buf []byte, off int) int {
	binary.BigEndian.PutUint32(buf[off:off+TLVHeaderLen], uint32(h.Type)<<16|uint32(h.Length))
	return off + TLVHeaderLen
}

func unpackTLVHeader(msg []byte, off int) (TLVHeader, int) {
	return TLVHeader{
		Type(binary.BigEndian.Uint16(msg[off:])),
		binary.BigEndian.Uint16(msg[off+2:]),
	}, off + TLVHeaderLen
}

// MsgParser incrementally parses a DSO message.
//
// When parsing is started, the [MsgHeader] is parsed. Next, each TLV can be parsed
// incrementally via [MsgParser.TLVHeader] that parses [TLVHeader] only, followed by either
// [MsgParser.XxxTLV] that fully parses the TLV, or [MsgParser.SkipTLV] that skips the TLV.
// Usage context of the current TLV is available via [MsgParser.TLVUsage].
//
// When all TLVs have been parsed, attempt to continue will return [ErrDone].
//
// MsgParser is safe to copy to preserve the parsing state.
//
// Note that there is no requirement to fully skip or parse the message.
type MsgParser struct {
	msg []byte
	off int

	header    MsgHeader
	tlvUsage  Usage
	tlvHeader TLVHeader

	tlvSameResponseType bool
	isPadded            bool
}

// Start parses [MsgHeader] and enables the parsing of TLVs.
func (p *MsgParser) Start(msg []byte, origin Origin) (MsgHeader, error) {
	if len(msg) < MsgHeaderLen {
		return MsgHeader{}, ErrMsgHeader
	}
	p.header, p.off = unpackMsgHeader(msg, 0)
	p.msg = msg
	p.tlvUsage = Usage(origin)
	return p.header, nil
}

// SetResponseType sets primary response type of a message
// to distinguish response primary from response additional usage contexts.
func (p *MsgParser) SetResponseType(t Type) {
	if p.off <= MsgHeaderLen {
		p.tlvHeader.Type = t
		p.tlvSameResponseType = true
	}
}

// IsPadded returns true if message contains [EncryptionPadding].
// The result it cached.
func (p *MsgParser) IsPadded() bool {
	var (
		h   TLVHeader
		off = MsgHeaderLen
	)
	for !p.isPadded && len(p.msg)-off >= TLVHeaderLen {
		h, off = unpackTLVHeader(p.msg, off)
		p.isPadded = h.Type == TypeEncryptionPadding
		off += int(h.Length)
	}
	return p.isPadded
}

// TLVHeader parses a single TLVHeader.
func (p *MsgParser) TLVHeader() (h TLVHeader, err error) {
	if p.off == len(p.msg) {
		return TLVHeader{}, ErrDone
	}
	if len(p.msg)-p.off < TLVHeaderLen {
		return TLVHeader{}, errMalformed
	}
	h, p.off = unpackTLVHeader(p.msg, p.off)
	p.tlvSameResponseType = p.tlvSameResponseType && h.Type == p.tlvHeader.Type
	p.isPadded = p.isPadded || h.Type == TypeEncryptionPadding
	p.tlvHeader = h
	return h, nil
}

func (p *MsgParser) TLVUsage() (u Usage) {
	switch {
	case p.off == MsgHeaderLen+TLVHeaderLen && p.header.ID == 0:
		u = UsageSU
	case p.off == MsgHeaderLen+TLVHeaderLen && !p.header.Response:
		u = UsageSP
	case !p.header.Response:
		u = UsageSA
	case p.tlvSameResponseType:
		u = UsageCRP
	default:
		u = UsageCRA
	}
	if p.tlvUsage&UsageFromClient != 0 {
		u = u << usageClientOff
	}
	return u
}

// SkipTLV skips a single TLV.
func (p *MsgParser) SkipTLV() (err error) {
	if len(p.msg)-p.off < int(p.tlvHeader.Length) {
		return errMalformed
	}
	p.off += int(p.tlvHeader.Length)
	return nil
}

// KeepAlive parses a single KeepAlive TLV.
func (p *MsgParser) KeepAlive() (tlv KeepAlive, err error) {
	tlv, p.off, err = unpackKeepAlive(p.msg, p.off, p.tlvHeader.Length)
	return tlv, err
}

// RetryDelay parses a single RetryDelay TLV.
func (p *MsgParser) RetryDelay() (tlv RetryDelay, err error) {
	tlv, p.off, err = unpackRetryDelay(p.msg, p.off, p.tlvHeader.Length)
	return tlv, err
}

// EncryptionPadding parses a single EncryptionPadding TLV.
func (p *MsgParser) EncryptionPadding() (tlv EncryptionPadding, err error) {
	tlv, p.off, err = unpackEncryptionPadding(p.msg, p.off, p.tlvHeader.Length)
	return tlv, err
}

// Subscribe parses a single Subscribe TLV.
func (p *MsgParser) Subscribe() (tlv Subscribe, err error) {
	tlv, p.off, err = unpackSubscribe(p.msg, p.off, p.tlvHeader.Length)
	return tlv, err
}

// Push parses a single Push TLV.
func (p *MsgParser) Push() (tlv Push, err error) {
	tlv, p.off, err = unpackPush(p.msg, p.off, p.tlvHeader.Length)
	return tlv, err
}

// Unsubscribe parses a single Unsubscribe TLV.
func (p *MsgParser) Unsubscribe() (tlv Unsubscribe, err error) {
	tlv, p.off, err = unpackUnsubscribe(p.msg, p.off, p.tlvHeader.Length)
	return tlv, err
}

// Reconfirm parses a single Reconfirm TLV.
func (p *MsgParser) Reconfirm() (tlv Reconfirm, err error) {
	tlv, p.off, err = unpackReconfirm(p.msg, p.off, p.tlvHeader.Length)
	return tlv, err
}

func (p *MsgParser) TLV() (TLV, error) {
	switch p.tlvHeader.Type {
	case TypeKeepAlive:
		return p.KeepAlive()
	case TypeRetryDelay:
		return p.RetryDelay()
	case TypeEncryptionPadding:
		return p.EncryptionPadding()
	case TypeSubscribe:
		return p.Subscribe()
	case TypePush:
		return p.Push()
	case TypeUnsubscribe:
		return p.Unsubscribe()
	case TypeReconfirm:
		return p.Reconfirm()
	default:
		return nil, ErrTLV
	}
}

type MsgBuilder struct {
	Buf         []byte
	Off         int
	blockLen    uint16
	compression map[string]int
}

// NewMsgBuilder returns Builder of a DSO message that puts data to buf without resizing.
func NewMsgBuilder(buf []byte) *MsgBuilder {
	return &MsgBuilder{Buf: buf, blockLen: 1}
}

func (b *MsgBuilder) EnableCompression() {
	b.compression = make(map[string]int)
}

// EnablePadding ensures that [EncryptionPadding] TLV is added,
// if necessary, for [MsgBuilder.Message] to be multiple of blockLen.
func (b *MsgBuilder) EnablePadding(blockLen uint16) {
	_ = b.Buf[(len(b.Buf)/int(blockLen))*1-1] // blockLen is not 0 and at least 1 block can be written
	b.blockLen = blockLen
}

func (b *MsgBuilder) SetMsgHeader(h MsgHeader) error {
	b.Off = max(h.pack(b.Buf, 0), b.Off)
	return nil
}

func (b *MsgBuilder) WriteKeepAlive(tlv KeepAlive) error {
	b.Off = TLVHeader{TypeKeepAlive, KeepAliveLen}.pack(b.Buf, b.Off)
	b.Off, _ = tlv.pack(b.Buf, b.Off, b.compression)
	return nil
}

func (b *MsgBuilder) WriteRetryDelay(tlv RetryDelay) error {
	b.Off = TLVHeader{TypeRetryDelay, RetryDelayLen}.pack(b.Buf, b.Off)
	b.Off, _ = tlv.pack(b.Buf, b.Off, b.compression)
	return nil
}

func (b *MsgBuilder) WriteEncryptionPadding(tlv EncryptionPadding) error {
	b.Off = TLVHeader{TypeEncryptionPadding, tlv.Padding}.pack(b.Buf, b.Off)
	b.Off, _ = tlv.pack(b.Buf, b.Off, b.compression)
	return nil
}

func (b *MsgBuilder) WriteSubscribe(tlv Subscribe) (err error) {
	headerStart := b.Off
	headerEnd := headerStart + TLVHeaderLen
	b.Off, err = tlv.pack(b.Buf, headerEnd, b.compression)
	TLVHeader{TypeSubscribe, uint16(b.Off - headerEnd)}.pack(b.Buf, headerStart)
	return err
}

func (b *MsgBuilder) WritePush(tlv Push) (err error) {
	headerStart := b.Off
	headerEnd := headerStart + TLVHeaderLen
	b.Off, err = tlv.pack(b.Buf, headerEnd, b.compression)
	TLVHeader{TypePush, uint16(b.Off - headerEnd)}.pack(b.Buf, headerStart)
	return err
}

func (b *MsgBuilder) WriteUnsubscribe(tlv Unsubscribe) error {
	b.Off = TLVHeader{TypeUnsubscribe, UnsubscribeLen}.pack(b.Buf, b.Off)
	b.Off, _ = tlv.pack(b.Buf, b.Off, b.compression)
	return nil
}

func (b *MsgBuilder) WriteReconfirm(tlv Reconfirm) (err error) {
	headerStart := b.Off
	headerEnd := headerStart + TLVHeaderLen
	b.Off, err = tlv.pack(b.Buf, headerEnd, b.compression)
	TLVHeader{TypeReconfirm, uint16(b.Off - headerEnd)}.pack(b.Buf, headerStart)
	return err
}

func (b *MsgBuilder) WriteTLV(tlv TLV) error {
	switch tlv := tlv.(type) {
	case KeepAlive:
		return b.WriteKeepAlive(tlv)
	case RetryDelay:
		return b.WriteRetryDelay(tlv)
	case EncryptionPadding:
		return b.WriteEncryptionPadding(tlv)
	case Subscribe:
		return b.WriteSubscribe(tlv)
	case Push:
		return b.WritePush(tlv)
	case Unsubscribe:
		return b.WriteUnsubscribe(tlv)
	case Reconfirm:
		return b.WriteReconfirm(tlv)
	default:
		return ErrTLV
	}
}

func (b *MsgBuilder) Message() []byte {
	off := b.Off
	if off%int(b.blockLen) != 0 {
		padLen := b.blockLen - uint16((off+TLVHeaderLen)%int(b.blockLen))
		off = TLVHeader{TypeEncryptionPadding, padLen}.pack(b.Buf, off) + int(padLen)
	}
	return b.Buf[:off]
}

func (b *MsgBuilder) Finish() {
	b.Off = 0
	clear(b.compression)
}

type (
	Pooler interface {
		Get() *[]byte
		Put(*[]byte)
	}
	// MsgPool implements [Pooler] to return buffers of the specified length.
	// Attempts to put a larger buffers are rejected.
	MsgPool struct {
		l    int
		pool sync.Pool
	}
)

func NewMsgPool(l int) *MsgPool {
	return &MsgPool{
		l: l,
		pool: sync.Pool{
			New: func() any {
				b := make([]byte, l)
				return &b
			},
		},
	}
}

func (p *MsgPool) Get() *[]byte {
	b := p.pool.Get().(*[]byte)
	*b = (*b)[:cap(*b)]
	return b
}

func (p *MsgPool) Put(buf *[]byte) {
	if cap(*buf) == p.l {
		p.pool.Put(buf)
	}
}

// TLSBlockLen is recommened multiple for padding.
//
// RFC 8467, Section 4.1: If a server receives a query that includes the EDNS(0) "Padding"
// option, ... SHOULD pad the corresponding response to a multiple of 468 octets
const TLSBlockLen = 468

// TLV is a generic DSO TLV.
type TLV interface {
	// Type returns numerical TLV type.
	Type() Type
	// Verify checks that TLV satisfies specification in given usage context.
	Verify(usage Usage) error
	// Equal returns true if TLVs are equal.
	Equal(tlv TLV) bool
	// Copy creates deep-copy of TLV.
	Copy() TLV
	// String converts TLV to readable string.
	String() string

	len() int
}

const (
	// RFC 8490, Section 6.2: On a new DSO Session, if no explicit DSO Keepalive message exchange
	// has taken place, the default value for both timeouts is 15 seconds.
	InactivityTimeoutDefault = 15 * 1000
	KeepAliveIntervalDefault = 15 * 1000
	// RFC 8490, Section 6.5.2: By default, it is RECOMMENDED that clients request, and servers
	// grant, a keepalive interval of 60 minutes.
	KeepAliveIntervalRecommened = 60 * 60 * 1000
	// RFC 8490, Section 7.1: The keepalive interval MUST NOT be less than ten seconds.
	KeepAliveIntervalMin = 10 * 1000
	// RFC 8490, Section 6.5.2: A keepalive interval value of 0xFFFFFFFF represents "infinity"
	// and informs the client that it should generate no DSO keepalive traffic.
	KeepAliveIntervalNever = 0xFFFFFFFF
	// RFC 8490, Section 6.4.2: An inactivity timeout of 0xFFFFFFFF represents "infinity"
	// and informs the client that it may keep an idle connection open as long as it wishes.
	InactivityTimeoutNever = 0xFFFFFFFF
)

// KeepAlive is RFC 8490, Section 7.1 Keepalive TLV.
type KeepAlive struct {
	// This is the timeout at which the client MUST begin closing an inactive DSO Session.
	InactivityTimeout uint32
	// This is the interval at which a client MUST generate DSO keepalive traffic to maintain
	// connection state.
	KeepAliveInterval uint32
}

// Type implements [TLV.Type].
func (tlv KeepAlive) Type() Type {
	return TypeKeepAlive
}

// Verify implements [TLV.Verify].
func (tlv KeepAlive) Verify(usage Usage) error {
	switch {
	case usage&UsageKeepAlive == 0:
		return errUsage
	case usage&UsageFromServer != 0 && tlv.KeepAliveInterval < KeepAliveIntervalMin:
		return errBadKeepAlive
	default:
		return nil
	}
}

// Equal implements [TLV.Equal].
func (tlv KeepAlive) Equal(tlv1 TLV) bool {
	ka, ok := tlv1.(KeepAlive)
	return ok && tlv == ka
}

// Copy implements [TLV.Copy].
func (tlv KeepAlive) Copy() TLV {
	return KeepAlive{tlv.InactivityTimeout, tlv.KeepAliveInterval}
}

// String implements [TLV.String].
func (tlv KeepAlive) String() string {
	return fmt.Sprintf("timeout %dms, interval %dms", tlv.InactivityTimeout, tlv.KeepAliveInterval)
}

func (tlv KeepAlive) pack(buf []byte, off int, _ map[string]int) (int, error) {
	binary.BigEndian.PutUint64(buf[off:off+KeepAliveLen], uint64(tlv.InactivityTimeout)<<32|uint64(tlv.KeepAliveInterval))
	return off + KeepAliveLen, nil
}

func (tlv KeepAlive) len() int {
	return KeepAliveLen
}

func unpackKeepAlive(msg []byte, off int, tlvLen uint16) (KeepAlive, int, error) {
	if tlvLen != KeepAliveLen {
		return KeepAlive{}, off, errMalformed
	}
	if len(msg)-off < KeepAliveLen {
		return KeepAlive{}, off, errMalformed
	}
	msg = msg[off:]
	return KeepAlive{
		binary.BigEndian.Uint32(msg),
		binary.BigEndian.Uint32(msg[4:]),
	}, off + KeepAliveLen, nil
}

// RetryDelay is RFC 8490, Section 7.2 Retry Delay TLV.
type RetryDelay struct {
	// A time value within which the initiator MUST NOT retry this operation or retry connecting
	// to this server.
	RetryDelay uint32
}

// Type implements [TLV.Type].
func (tlv RetryDelay) Type() Type {
	return TypeRetryDelay
}

// Verify implements [TLV.Verify].
func (tlv RetryDelay) Verify(usage Usage) error {
	if usage&UsageRetryDelay == 0 {
		return errUsage
	}
	return nil
}

// Equal implements [TLV.Equal].
func (tlv RetryDelay) Equal(tlv1 TLV) bool {
	rd, ok := tlv1.(RetryDelay)
	return ok && tlv == rd
}

// Copy implements [TLV.Copy].
func (tlv RetryDelay) Copy() TLV {
	return &RetryDelay{tlv.RetryDelay}
}

// String implements [TLV.String].
func (tlv RetryDelay) String() string {
	return (time.Duration(tlv.RetryDelay) * time.Millisecond).String()
}

func (tlv RetryDelay) pack(buf []byte, off int, _ map[string]int) (int, error) {
	binary.BigEndian.PutUint32(buf[off:off+RetryDelayLen], tlv.RetryDelay)
	return off + RetryDelayLen, nil
}

func (tlv RetryDelay) len() int {
	return RetryDelayLen
}

func unpackRetryDelay(msg []byte, off int, tlvLen uint16) (RetryDelay, int, error) {
	if tlvLen != RetryDelayLen {
		return RetryDelay{}, off, errMalformed
	}
	if len(msg)-off < RetryDelayLen {
		return RetryDelay{}, off, errMalformed
	}
	return RetryDelay{binary.BigEndian.Uint32(msg[off:])}, off + RetryDelayLen, nil
}

// EncryptionPadding is RFC 8490, Section 7.3 Encryption Padding TLV.
//
// Even the empty TLV adds 4 bytes due to header.
// See also RFC 8467.
type EncryptionPadding struct {
	Padding uint16
}

// Type implements the [TLV.Type].
func (tlv EncryptionPadding) Type() Type {
	return TypeEncryptionPadding
}

// Verify implements [TLV.Verify].
func (tlv EncryptionPadding) Verify(usage Usage) error {
	if usage&UsageEncryptionPadding == 0 {
		return errUsage
	}
	return nil
}

// Equal implements [TLV.Equal].
func (tlv EncryptionPadding) Equal(tlv1 TLV) bool {
	ep, ok := tlv1.(EncryptionPadding)
	return ok && tlv == ep
}

// Copy implements [TLV.Copy]
func (tlv EncryptionPadding) Copy() TLV {
	return &EncryptionPadding{tlv.Padding}
}

// String implements [TLV.String].
func (tlv EncryptionPadding) String() string {
	return fmt.Sprintf("%dB", tlv.Padding)
}

func (tlv EncryptionPadding) pack(_ []byte, off int, _ map[string]int) (int, error) {
	return off + int(tlv.Padding), nil
}

func (tlv EncryptionPadding) len() int {
	return int(tlv.Padding)
}

func unpackEncryptionPadding(msg []byte, off int, tlvLen uint16) (EncryptionPadding, int, error) {
	if len(msg)-off < int(tlvLen) {
		return EncryptionPadding{}, off, errMalformed
	}
	return EncryptionPadding{tlvLen}, off + int(tlvLen), nil
}

// Subscribe is RFC 8765, Section 6.2 Subscribe TLV.
type Subscribe struct {
	// Domain name of RR that subscriber wants.
	//
	// DNS wildcarding is not supported, case insensitivity applies, CNAME matches
	// only a CNAME record.
	Name string
	// Type of RR that subscriber wants.
	//
	// TypeANY (255) is interepreted to mean "ALL".
	RRType uint16
	// Class of RR that subscriber wants.
	//
	// ClassANY (255) is interpreted to mean "ALL".
	Class uint16
}

// Type implements [TLV.Type].
func (tlv Subscribe) Type() Type {
	return TypeSubscribe
}

// Verify implements [TLV.Verify].
func (tlv Subscribe) Verify(usage Usage) error {
	if usage&UsageSubscribe == 0 {
		return errUsage
	}
	return nil
}

// Equal implements [TLV.Equal].
func (tlv Subscribe) Equal(tlv1 TLV) bool {
	sub, ok := tlv1.(Subscribe)
	return ok && tlv == sub
}

// Copy implements [TLV.Copy].
func (tlv Subscribe) Copy() TLV {
	return &Subscribe{tlv.Name, tlv.RRType, tlv.Class}
}

// String implements [TLV.String].
func (tlv Subscribe) String() string {
	s := ";" + dns.Name(tlv.Name).String() + "\t"
	s += dns.Class(tlv.Class).String() + "\t"
	s += " " + dns.Type(tlv.RRType).String()
	return s
}

func (tlv Subscribe) pack(buf []byte, off int, compression map[string]int) (int, error) {
	nameEnd, err := dns.PackDomainName(tlv.Name, buf, off, compression, compression != nil)
	if err != nil {
		return off, err
	}
	binary.BigEndian.PutUint16(buf[nameEnd:], tlv.RRType)
	binary.BigEndian.PutUint16(buf[nameEnd+2:], tlv.Class)
	return nameEnd + 4, nil
}

func (tlv Subscribe) len() int {
	return len(tlv.Name) + 1 + 2 + 2 // Name + \0 + RRType(2) + Class(2)
}

func unpackSubscribe(msg []byte, off int, tlvLen uint16) (tlv Subscribe, off1 int, err error) {
	if len(msg)-off < int(tlvLen) {
		return Subscribe{}, off, errMalformed
	}
	msg = msg[:off+int(tlvLen)] // for dns.Unpack*
	if tlv.Name, off1, err = dns.UnpackDomainName(msg, off); err != nil {
		return Subscribe{}, off, errors.Join(errMalformed, err)
	}
	if int(tlvLen)-(off1-off) != 4 {
		return tlv, off, errMalformed
	}
	tlv.RRType = binary.BigEndian.Uint16(msg[off1:])
	tlv.Class = binary.BigEndian.Uint16(msg[off1+2:])
	return tlv, off + int(tlvLen), nil
}

const (
	// RFC 8765, Section 6.3.1: If the TTL has the value 0xFFFFFFFF, then the DNS Resource Record
	// with the given name, type, class, and RDATA is removed.
	PushTTLRemove = 0xFFFFFFFF
	// RFC 8765, Section 6.3.1: If the TTL has the value 0xFFFFFFFE, then this is a 'collective'
	// remove notification.
	PushTTLCollectiveRemove = 0xFFFFFFFE
	// RFC 8765, Section 6.3.1: If the TTL is in the range 0 to 2,147,483,647 seconds
	// (0 to 231 - 1, or 0x7FFFFFFF), then a new DNS Resource Record with the given name,
	// type, class, and RDATA is added.
	PushTTLAddMin = 0
	// RFC 8765, Section 6.3.1: If the TTL is in the range 0 to 2,147,483,647 seconds
	// (0 to 2^(31) - 1, or 0x7FFFFFFF), then a new DNS Resource Record with the given name,
	// type, class, and RDATA is added.
	PushTTLAddMax = 0x7FFFFFFF
	// RFC 8765, Section 6.3.1: Servers may generate PUSH messages up to a maximum DNS message
	// length of 16,382 bytes, counting from the start of the DSO 12-byte header. Including
	// the two-byte length prefix that is used to frame DNS over a byte stream like TLS,
	// this makes a total of 16,384 bytes. Servers MUST NOT generate PUSH messages larger than this.
	PushLenMax = 16382

	// PushDomain is domain name of DSO Push server in given zone.
	PushDomain = "_dns-push-tls._tcp."
)

// Push is RFC 8765, Section 6.3 Push TLV.
type Push struct {
	// Changes (at least one) in RRs the receiver is subscribed to.
	//
	// RR's TTL value may carry special meaning, see RFC 8765, Section 6.3.1 for details.
	Change []dns.RR
}

// Type implements [TLV.Type].
func (tlv Push) Type() Type {
	return TypePush
}

// Verify implements [TLV.Verify].
func (tlv Push) Verify(usage Usage) error {
	if usage&UsagePush == 0 {
		return errUsage
	}

	var h *dns.RR_Header
	for _, rr := range tlv.Change {
		h = rr.Header()
		switch {
		// RFC 8765, Section 6.3.1: If the TTL is in the range ... 0x7FFFFFFF then a new DNS
		// Resource Record with the given name, type, class, and RDATA is added. Type and class
		// MUST NOT be 255 (ANY).
		// RFC 8765, Section 6.3.1: If the TTL has the value 0xFFFFFFFF, then the DNS Resource
		// Record with the given name, type, class, and RDATA is removed. Type and class
		// MUST NOT be 255 (ANY)
		case (h.Ttl == 0xFFFFFFFF || h.Ttl <= 0x7FFFFFFF) && (h.Class == dns.ClassANY || h.Rrtype == dns.TypeANY):
			return fmt.Errorf("%w: bad class (%d) / type (%d) in push tlv", ErrTLV, h.Class, h.Rrtype)

		// RFC 8765, Section 6.3.1: If the TTL has the value 0xFFFFFFFE, then this is a
		// 'collective' remove notification. For collective remove notifications,
		// RDLEN MUST be zero
		case h.Ttl == 0xFFFFFFFE && h.Rdlength != 0:
			return errBadPushCollective

		// RFC 8765, Section 6.3.1: If the TTL is any value other than 0xFFFFFFFF, 0xFFFFFFFE,
		// or a value in the range 0 to 0x7FFFFFFF, then the receiver SHOULD silently ignore
		// this particular change notification record.
		default:
		}
	}

	// RFC 8765, Section 6.3.1: A PUSH Message MUST contain at least one change notification.
	if h == nil {
		return errBadPush
	}

	return nil
}

// Equal implements [TLV.Equal].
func (tlv Push) Equal(tlv1 TLV) bool {
	push, ok := tlv1.(Push)
	return ok && slices.EqualFunc(tlv.Change, push.Change, func(rr, rr1 dns.RR) bool {
		return dns.IsDuplicate(rr, rr1) && rr.Header().Ttl == rr1.Header().Ttl
	})
}

// Copy implements [TLV.Copy].
func (tlv Push) Copy() TLV {
	tlv1 := Push{}
	tlv1.Change = make([]dns.RR, len(tlv.Change))
	for i, rr := range tlv.Change {
		tlv1.Change[i] = dns.Copy(rr)
	}
	return &tlv1
}

// String implements [TLV.String].
func (tlv Push) String() string {
	switch {
	case len(tlv.Change) == 0:
		return "<nil>"
	case len(tlv.Change) == 1:
		return tlv.Change[0].String()
	default:
		var s strings.Builder
		s.WriteString("\t" + tlv.Change[0].String())
		for _, r := range tlv.Change[1:] {
			s.WriteString("\n\t" + r.String())
		}
		return s.String()
	}
}

func (tlv Push) pack(buf []byte, off int, compression map[string]int) (off1 int, err error) {
	off1 = off
	for _, rr := range tlv.Change {
		off1, err = dns.PackRR(rr, buf, off1, compression, compression != nil)
		if err != nil {
			return off, err
		}
	}
	return off1, nil
}

func (tlv Push) len() (l int) {
	for _, rr := range tlv.Change {
		l += dns.Len(rr)
	}
	return l
}

func unpackPush(msg []byte, off int, tlvLen uint16) (tlv Push, off1 int, err error) {
	if len(msg)-off < int(tlvLen) {
		return Push{}, off, errMalformed
	}
	var (
		rr  dns.RR
		end = off + int(tlvLen)
	)
	msg = msg[:off+int(tlvLen)] // for dns.Unpack*
	off1 = off
	for off1 < end {
		if rr, off1, err = dns.UnpackRR(msg, off1); err != nil {
			return tlv, off, errors.Join(errMalformed, err)
		}
		tlv.Change = append(tlv.Change, rr)
	}
	if off1 != end {
		return Push{}, off, errMalformed
	}
	return tlv, off1, nil
}

func alignPushBuf(b []byte, blockLen uint16) []byte {
	return b[:(min(len(b), PushLenMax)/int(blockLen))*int(blockLen)]
}

// BuildPushMsg iteratively builds [Push] DSO unidirectional message by chunking RRs.
//
// RRs are written in given order until entire change is included.
// Unlike [MsgBuilder.WritePush] it is not necessary to know buffer length upfront.
//
// The iterator yields (msg, err) pair, which is never (nil, nil):
//   - msg is nil for Buf that is too small for even one RR; non-nil otherwise
//   - err is nil for final write; [PackError] otherwise
//
// The caller has the following options for partial writes:
//   - Do nothing and reuse current Buf for next chunk
//   - Upsize Buf and retry
//
// The iterator resepects enabled padding.
func BuildPushMsg(b *MsgBuilder, change []dns.RR) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		b.Off = 0
		b.SetMsgHeader(MsgHeader{0, false, dns.RcodeSuccess})
		clear(b.compression)

		var (
			alignedBuf  = alignPushBuf(b.Buf, b.blockLen)
			headerStart = b.Off
			headerEnd   = headerStart + TLVHeaderLen
			off         = headerEnd

			i = 0

			ok  bool
			err error
		)

		for i < len(change) {
			off, err = dns.PackRR(change[i], alignedBuf, off, b.compression, b.compression != nil)

			// Packing has the following outcomes:
			// - Successful
			// - Successful but not enough space for padding
			// - Failed

			if err == nil && (off%int(b.blockLen) == 0 || len(alignedBuf)-off >= TLVHeaderLen) {
				b.Off = off
				i++
				continue
			}

			err = &PackError{Index: i, cause: err}
			oldOff, oldLen, oldFreeLen := b.Off, len(alignedBuf), len(alignedBuf)-b.Off
			if b.Off != MsgHeaderLen {
				TLVHeader{TypePush, uint16(b.Off - headerEnd)}.pack(alignedBuf, headerStart)
				ok = yield(b.Message(), err)
			} else {
				ok = yield(nil, err)
			}
			if !ok {
				return
			}

			// The caller is given a chance to react by:
			// - Adjusting builder's Buf and/or blockLen to continue writing
			// - Reusing Buf for next chunk

			alignedBuf = alignPushBuf(b.Buf, b.blockLen)
			freeLen := len(alignedBuf) - b.Off
			if oldOff == MsgHeaderLen && oldFreeLen == freeLen {
				// Caller had nothing to consume but didn't resize.
				return
			}
			if oldOff != b.Off || oldLen >= len(alignedBuf) {
				b.Off = MsgHeaderLen
				off = headerEnd
				clear(b.compression)
			}
		}

		if b.Off != MsgHeaderLen {
			TLVHeader{TypePush, uint16(b.Off - headerEnd)}.pack(alignedBuf, headerStart)
			yield(b.Message(), nil)
		}
	}
}

// Unsubscribe is RFC 8765, Section 6.4 Unsubscribe TLV.
type Unsubscribe struct {
	// ID of the previously sent Subscribe request message.
	SubscribeID uint16
}

// Type implements [TLV.Type].
func (tlv Unsubscribe) Type() Type {
	return TypeUnsubscribe
}

// Verify implements [TLV.Verify].
func (tlv Unsubscribe) Verify(usage Usage) error {
	switch {
	case usage&UsageUnsubscribe == 0:
		return errUsage
	case tlv.SubscribeID == 0:
		// RFC 8765, Section 6.4.1: The DSO-DATA contains the value previously given in the MESSAGE ID
		// field of an active SUBSCRIBE request.
		return fmt.Errorf("%w: bad subscribe ID", ErrTLV)
	default:
		return nil
	}
}

// Equal implements [TLV.Equal].
func (tlv Unsubscribe) Equal(tlv1 TLV) bool {
	unsub, ok := tlv1.(Unsubscribe)
	return ok && tlv == unsub
}

// Copy implements [TLV.Copy].
func (tlv Unsubscribe) Copy() TLV {
	return &Unsubscribe{tlv.SubscribeID}
}

// String implements [TLV.String].
func (tlv Unsubscribe) String() (s string) {
	return strconv.Itoa(int(tlv.SubscribeID))
}

func (tlv Unsubscribe) pack(buf []byte, off int, _ map[string]int) (int, error) {
	binary.BigEndian.PutUint16(buf[off:off+UnsubscribeLen], tlv.SubscribeID)
	return off + UnsubscribeLen, nil
}

func (tlv Unsubscribe) len() int {
	return UnsubscribeLen
}

func unpackUnsubscribe(msg []byte, off int, tlvLen uint16) (Unsubscribe, int, error) {
	if tlvLen != UnsubscribeLen {
		return Unsubscribe{}, off, errMalformed
	}
	if len(msg)-off < UnsubscribeLen {
		return Unsubscribe{}, off, errMalformed
	}
	return Unsubscribe{binary.BigEndian.Uint16(msg[off:])}, off + UnsubscribeLen, nil
}

// Reconfirm is RFC 8765, Section 6.5 Reconfirm TLV.
type Reconfirm struct {
	// RR that the sender belives to be stale.
	//
	// RR's type must not be TypeANY (255), class must not be ClassANY (255), wildcarding
	// is not supported, case insensitivity applies, CNAME matches only a CNAME record.
	// RR's TTL is ignored and Rdlength is re-calculated.
	RR dns.RR
}

// Type implements [TLV.Type].
func (tlv Reconfirm) Type() Type {
	return TypeReconfirm
}

// Verify implements [TLV.Verify].
func (tlv Reconfirm) Verify(usage Usage) error {
	if usage&UsageReconfirm == 0 {
		return errMalformed
	}
	if h := tlv.RR.Header(); h.Class == dns.ClassANY || h.Rrtype == dns.TypeANY {
		return fmt.Errorf("%w: bad class (%d) / type (%d) in reconfirm tlv", ErrTLV, h.Class, h.Rrtype)
	}
	return nil
}

// Equal implements [TLV.Equal].
func (tlv Reconfirm) Equal(tlv1 TLV) bool {
	rec, ok := tlv1.(Reconfirm)
	return ok && dns.IsDuplicate(tlv.RR, rec.RR)
}

// Copy implements [TLV.Copy].
func (tlv Reconfirm) Copy() TLV {
	return &Reconfirm{dns.Copy(tlv.RR)}
}

// String implements [TLV.String].
func (tlv Reconfirm) String() string {
	return tlv.RR.String()
}

func (tlv Reconfirm) pack(buf []byte, off int, _ map[string]int) (off1 int, err error) {
	var (
		rrStart     = off
		rrEnd       int
		rrHeader    = tlv.RR.Header()
		oldRdlength = rrHeader.Rdlength
	)
	if rrEnd, err = dns.PackRR(tlv.RR, buf, rrStart, nil, false); err != nil {
		return off, err
	}
	copy(buf[rrEnd-int(rrHeader.Rdlength)-2-4:], buf[rrEnd-int(rrHeader.Rdlength):rrEnd]) // discard Rdlength(2) and TTL(4)
	rrHeader.Rdlength = oldRdlength                                                       // dns.PackRR overwrites Rdlength
	return rrEnd - 2 - 4, nil
}

func (tlv Reconfirm) len() int {
	return dns.Len(tlv.RR)
}

func unpackReconfirm(msg []byte, off int, tlvLen uint16) (tlv Reconfirm, off1 int, err error) {
	if len(msg)-off < int(tlvLen) {
		return Reconfirm{}, off, errMalformed
	}
	msg = msg[:off+int(tlvLen)] // for dns.Unpack*

	var h dns.RR_Header

	if h.Name, off1, err = dns.UnpackDomainName(msg, off); err != nil {
		return Reconfirm{}, off, errors.Join(errMalformed, err)
	}

	if int(tlvLen)-(off1-off) < 4 {
		return Reconfirm{}, off, errMalformed
	}
	h.Rrtype = binary.BigEndian.Uint16(msg[off1:])
	h.Class = binary.BigEndian.Uint16(msg[off1+2:])
	off1 += 4

	h.Rdlength = tlvLen - uint16(off1-off)
	if tlv.RR, off1, err = dns.UnpackRRWithHeader(h, msg, off1); err != nil {
		return Reconfirm{}, off, errors.Join(errMalformed, err)
	}

	if off1 != off+int(tlvLen) {
		return Reconfirm{}, off, errMalformed
	}
	return tlv, off1, nil
}

type Origin uint16

const (
	OriginServer Origin = Origin(UsageFromServer)
	OriginClient Origin = Origin(UsageFromClient)
)

// Usage is RFC 8490, Section 8.2 TLV usage matrix.
type Usage uint16

const (
	usageP  = 1 << 0
	usageU  = 1 << 1
	usageA  = 1 << 2
	usageRP = 1 << 3
	usageRA = 1 << 4

	usageClientOff = 5

	// UsageSP is primary TLV, sent in DSO request message, from server to client.
	UsageSP Usage = usageP
	// UsageSU is primary TLV, sent in DSO unidirectional message, from server to client.
	UsageSU Usage = usageU
	// UsageSA is additional TLV, optionally added to a DSO request message or DSO unidirectional message
	// from server to client.
	UsageSA Usage = usageA
	// UsageCRP is response primary TLV, included in response message sent back to the client
	// where the DSO-TYPE of the Response TLV matches the DSO-TYPE of the Primary TLV in the request.
	UsageCRP Usage = usageRP
	// UsageCRA is response additional TLV, included in response message sent back to the client where
	// the DSO-TYPE of the Response TLV does not match the DSO-TYPE of the Primary TLV in the request.
	UsageCRA Usage = usageRA

	// UsageCP is primary TLV, sent in DSO request message, from client to server.
	UsageCP Usage = usageP << usageClientOff
	// UsageCU is primary TLV, sent in DSO unidirectional message, from client to server.
	UsageCU Usage = usageU << usageClientOff
	// UsageCA is additional TLV, optionally added to a DSO request message or DSO unidirectional message
	// from client to server.
	UsageCA Usage = usageA << usageClientOff
	// UsageSRP is response primary TLV, included in response message sent back to the server where the DSO-TYPE
	// of the Response TLV matches the DSO-TYPE of the Primary TLV in the request.
	UsageSRP Usage = usageRP << usageClientOff
	// UsageSRA is response additional TLV, included in response message sent back to the server where the DSO-TYPE
	// of the Response TLV does not match the DSO-TYPE of the Primary TLV in the request.
	UsageSRA Usage = usageRA << usageClientOff

	UsagePrimary    Usage = UsageCP | UsageCU | UsageCRP | UsageSP | UsageSU | UsageSRP
	UsageAdditional Usage = UsageCA | UsageCRA | UsageSA | UsageSRA

	UsageFromServer Usage = UsageSP | UsageSU | UsageSA | UsageCRP | UsageCRA
	UsageFromClient Usage = UsageCP | UsageCU | UsageCA | UsageSRP | UsageSRA

	// UsageKeepAlive is allowed usage contexts of [KeepAlive].
	UsageKeepAlive Usage = UsageCP | UsageCRP | UsageSU
	// UsageRetryDelay is allowed usage contexts of [RetryDelay].
	UsageRetryDelay Usage = UsageCRA | UsageSU | UsageSRA
	// UsageEncryptionPadding is allowed usage contexts of [EncryptionPadding].
	UsageEncryptionPadding Usage = UsageCA | UsageCRA | UsageSA | UsageSRA
	// UsageSubscribe is allowed usage contexts of [Subscribe].
	UsageSubscribe Usage = UsageCP
	// UsagePush is allowed usage contexts of [Push].
	UsagePush Usage = UsageSU
	// UsageUnsubscribe is allowed usage contexts of [Unsubscribe].
	UsageUnsubscribe Usage = UsageCU
	// UsageReconfirm is allowed usage contexts of [Reconfirm].
	UsageReconfirm Usage = UsageCU
)

var (
	errUsage             = fmt.Errorf("%w: invalid usage context", ErrTLV)
	errMalformed         = fmt.Errorf("%w: malformed", ErrTLV)
	errBadKeepAlive      = fmt.Errorf("%w: bad keepalive interval", ErrTLV)
	errBadPush           = fmt.Errorf("%w: empty push tlv", ErrTLV)
	errBadPushCollective = fmt.Errorf("%w: non-empty collective removal in push tlv", ErrTLV)
)
