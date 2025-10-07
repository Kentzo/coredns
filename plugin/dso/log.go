package dso

import (
	"context"
	"strings"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/replacer"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("dso")

type logOpts struct {
	incoming string
	outgoing string
}

type logHandler struct {
	opts logOpts
	repl replacer.Replacer
}

func newLogHandler(opts logOpts) *logHandler {
	return &logHandler{
		opts: opts,
	}
}

func (l *logHandler) newWriter(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) *logWriter {
	logstr := l.opts.incoming
	for l, f := range labels {
		logstr = strings.ReplaceAll(logstr, l, f(r))
	}
	log.Info(l.repl.Replace(ctx, request.Request{W: w, Req: r}, nil, logstr))
	return &logWriter{w, ctx, &l.opts, l.repl}
}

type logWriter struct {
	dns.ResponseWriter
	ctx  context.Context
	opts *logOpts
	repl replacer.Replacer
}

func (l *logWriter) WriteMsg(r *dns.Msg) error {
	logstr := l.opts.outgoing
	for l, f := range labels {
		logstr = strings.ReplaceAll(logstr, l, f(r))
	}
	log.Info(l.repl.Replace(l.ctx, request.Request{W: l.ResponseWriter, Req: r}, nil, logstr))
	return l.ResponseWriter.WriteMsg(r)
}
