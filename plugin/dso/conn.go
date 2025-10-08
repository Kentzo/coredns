package dso

import (
	"net"
	"reflect"
	"unsafe"

	"github.com/miekg/dns"
)

type LingerConn interface {
	net.Conn
	SetLinger(sec int) error
}

type stubLingerConn struct {
	net.Conn
}

func (c stubLingerConn) SetLinger(int) error {
	return nil
}

// GetConn extracts underlying connection from the response writer.
func GetConn(w dns.ResponseWriter) LingerConn {
	var conn net.Conn
	if conner, ok := w.(interface{ Conn() net.Conn }); ok {
		conn = conner.Conn()
	} else {
		// Hopefully dns.response is embeded, lookup the "tcp" field.
		v := reflect.ValueOf(w).Elem()
		for v.IsValid() {
			if f := v.FieldByName("tcp"); f.IsValid() {
				f = reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem()
				if f.Type().Implements(reflect.TypeFor[net.Conn]()) {
					conn = f.Interface().(net.Conn)
					break
				}
			}
			v = v.FieldByName("ResponseWriter")
			if v.Kind() != reflect.Interface {
				break
			}
			v = v.Elem()
			if v.Kind() == reflect.Pointer {
				v = v.Elem()
			}
		}
	}

	if netConner, ok := conn.(interface{ NetConn() net.Conn }); ok {
		conn = netConner.NetConn()
	}
	if lingerConn, ok := conn.(LingerConn); ok {
		return lingerConn
	}
	return stubLingerConn{conn}
}

// CheckConn checks whether the connection is dead.
func CheckConn(conn net.Conn) error {
	_, err := conn.Read(nil)
	return err
}


func AbortConn(w dns.ResponseWriter) {
	netConn := GetConn(w)
	netConn.SetLinger(0)
	w.Close()
}
