# [RFC 8490 - DNS Stateful Operations][rfc8490]

DNS Stateful Operations, or DSO, messages have the same header as the standard DNS messages except that
all `*COUNT` fields are zeroed and the `Z` bits are unused. Resource records are replaced with a series
of Time-Length-Values, or TLVs. In general, DSO messages are not associated with any zone but act on
the DNS server at large.

This message format is not compatible with some of the in-tree plugins that require at least one Question.
For this reason DSO is opt-in. Additionally, there are two requirements when declaring `dso` plugin:
- It MUST appear in *plugin.cfg* ahead of plugins that require resource records.
- It MUST be declared in the *"."* zone.

DSO requires a TCP transport as the protocol must maintain a session and its messages can be sensitive
to the arrival order. The plugin ensures that appropriate session establishment flow is followed as well
as correctness, both format and protocol, of handled messages. For `KeepAlive` it derives values from
server's timeouts such that client is instructed to exchange messages at least as often as necessary
to consider the connection active.

When the server is restarted, e.g. due to *Corefile* reload, or gracefully shut down, `dso` notifies
the client with a `RetryDelay` allowing it, to terminate session gracefully, waiting for up to 5 seconds.

### [RFC 8765 - DNS Push Notifications][rfc8765]

DNS Push Notifications work on top of a DSO session and allow clients to get notified of changes
in DNS records. It requires a TLS transport.

A client can establish interest in a given resource record by subscribing. The plugin then periodically polls the upstream
to detect changes and notifies the client if needed. Queries are made to appear as if coming from the client so that
plugins such as `acl` and `view` participate in handling and there is no discrepancy between DSO and standard DNS queries.

The cached answer is updated for `NoError` and removed for `NoData`, `NameError` and `RcodeRefused` responses.
All other responses are treated as transient errors and ignored.

The client can ask the server to reconfirm a given subscription. These requests are propagated to all clients indiscriminatly
and the RRs are refreshed ahead of periodic polling.

When the client loses its interest in a resource record it sends an unsubscription request.

`dso` must be declared at the root zone but subsciptions carry a resource record name and for this reason a list of zones
can be specified to further restrict (in addition to `acl` and/or `view`) access.

## Configuration

- `cleanup` configures the interval of periodic checks for dead connections.
- `log` enables logging of DSO messages.
- `push` enables Push Notifications and optionally configures the authorized zones for subscription requests.
- `push_refresh` configures the resolution interval of subscriptions.
- `push_any_types` and `push_any_classes` configure expansion of wildcard type and class in subscriptions.
- `push_burst_debounce` configures the subscription and reconfirm debounce interval.
- `push_max_subs` configures the maximum number of non-expanded subscriptions per session.

## RFC Conformance

- CoreDNS does not inform plugins about closed or dead connections, `dso` uses periodic
  zero-byte reads for cleanup.
- CoreDNS's server timeouts cannot be adjusted once they start serving, therefore KeepAlive
  intervals requested by the user are ignored and overridden with server's configuration.
- TLS Primary data is not checked for disallowed TLVs: Go's crypto/tls limitation.
- Standard DNS messages are not checked for the edns-tcp-keepalive EDNS0 option.
- If a session is established using a non-KeepAlive request message, the server immediately
  sends the client an appropriate KeepAlive unidirectional message.
- `ANY` is Push Notification subscriptions is not expanded to mean every type and class.
  Instead the user must configure the expansion list.

### Forcible Abort Checklist:

If at any time client begins to misbehave, the session is forcibly aborted.

- RFC 8490, Section [5.4.1][rfc8490-5.4.1], [5.4.3][rfc8490-5.4.3]: Invalid combinations of the ID, QR flag and Primary TLV(s).
- RFC 8490, Section [5.4.5][rfc8490-5.4.5]: Unidirectional messages with unrecognized Primary TLV(s).
- RFC 8490, Section [6.4.1][rfc8490-6.4.1], [6.5.1][rfc8490-6.5.1]: Inactive DSO sessions.
- RFC 8490, Section [6.6.1][rfc8490-6.6.1]: Client's failure to close the connection after server sends RetryDelay.
- RFC 8765, Section [6.2.1][rfc8765-6.2.1]: Duplicate subscriptions both by ID and by TLV.
- RFC 8765 Section [6.3][rfc8765-6.3], [6.4][rfc8765-6.4] and [6.5][rfc8765-6.5]: Invalid TLVs.

[timeouts]: https://coredns.io/plugins/timeouts/
[rfc8490]: https://www.rfc-editor.org/rfc/rfc8490.html
[rfc8490-5.4.1]: https://www.rfc-editor.org/rfc/rfc8490.html#section-5.4.1
[rfc8490-5.4.3]: https://www.rfc-editor.org/rfc/rfc8490.html#section-5.4.3
[rfc8490-5.4.5]: https://www.rfc-editor.org/rfc/rfc8490.html#section-5.4.5
[rfc8490-6.4.1]: https://www.rfc-editor.org/rfc/rfc8490.html#section-6.4.1
[rfc8490-6.5.1]: https://www.rfc-editor.org/rfc/rfc8490.html#section-6.4.1
[rfc8490-6.6.1]: https://www.rfc-editor.org/rfc/rfc8490.html#section-6.4.1
[rfc8765]: https://www.rfc-editor.org/rfc/rfc8765.html
[rfc8765-6.2.1]: https://www.rfc-editor.org/rfc/rfc8765#name-subscribe-request
[rfc8765-6.3]: https://www.rfc-editor.org/rfc/rfc8765#name-dns-push-notification-updat
[rfc8765-6.4]: https://www.rfc-editor.org/rfc/rfc8765#name-dns-push-notification-unsub
[rfc8765-6.5]: https://www.rfc-editor.org/rfc/rfc8765#name-dns-push-notification-recon
