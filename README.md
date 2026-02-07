# addled

An authoritative DNS lookup tool. It finds the authoritative nameservers for a domain, queries each one directly, and tells you whether they all return the expected records.

## Examples

A successful check produces no output:

```
$ addled --type A --name one.one.one.one --expect 1.0.0.1,1.1.1.1
$ echo $?
0
```

A failing check shows what went wrong:

```
$ addled --type A --name one.one.one.one --expect 1.0.0.1,1.1.1.0
one.one.one.one: 6 of 6 servers returned unexpected A records
terin.ns.cloudflare.com. (172.64.33.236): got 1.0.0.1, 1.1.1.1
terin.ns.cloudflare.com. (173.245.59.236): got 1.1.1.1, 1.0.0.1
dorthy.ns.cloudflare.com. (172.64.32.249): got 1.1.1.1, 1.0.0.1
dorthy.ns.cloudflare.com. (108.162.192.249): got 1.1.1.1, 1.0.0.1
```

Exits 0 on success, 1 on failure, so it works naturally in scripts:

```bash
if addled --type A --name example.com --expect 93.184.216.34 2>/dev/null; then
  echo "dns is correct"
else
  echo "dns has not updated yet"
fi
```

## Install

```
go install github.com/jacob2161/addled@latest
```

## Usage

```
$ addled --help
  -expect string
    	expected record value(s), comma-separated
  -name string
    	domain name to check
  -timeout duration
    	timeout for the entire check (default 5s)
  -type string
    	DNS record type (A, AAAA, CNAME, TXT, MX)
  -verbose
    	enable verbose logging
```

## Library

The `dnscheck` package can also be used as a Go library:

```go
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jacob2161/addled/dnscheck"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := dnscheck.Check(ctx, dnscheck.CheckArgs{
		Domain:     "one.one.one.one",
		RecordType: dnscheck.TypeA,
		Expected:   []string{"1.1.1.1", "1.0.0.1"},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	matched, reason := result.Match()
	if matched {
		fmt.Println("all nameservers returned the expected records")
	} else {
		fmt.Println(reason)
	}
}
```
