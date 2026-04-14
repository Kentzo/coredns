## Limitations

The plugin 

## Bugs

In CoreDNS multiple server blocks may define a single DNS server and a single server block may define multiple
DNS servers (e.g. `bind`, `multisocket`).  On the other hand, there must be 1:1 correspondance between DNS
and DSO servers therefore the plugin has to aggregate DSO definitions possibly discarding overlapping values.
