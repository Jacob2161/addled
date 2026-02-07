package dnscheck_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/jacob2161/addled/dnscheck"
)

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return ctx
}

const testDomain = "one.one.one.one"

// nameserverIPv4s returns all IPv4 addresses for all nameservers of the test
// domain, for use in tests that need to try multiple IPs.
func nameserverIPv4s(t *testing.T) []string {
	t.Helper()
	ctx := testContext(t)
	servers, err := dnscheck.FindNameservers(ctx, testDomain, "8.8.8.8:53")
	if err != nil {
		t.Fatalf("FindNameservers error: %v", err)
	}
	var ips []string
	for _, ns := range servers {
		addresses, err := net.DefaultResolver.LookupHost(ctx, ns)
		if err != nil {
			continue
		}
		for _, addr := range addresses {
			if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil {
				ips = append(ips, addr)
			}
		}
	}
	if len(ips) == 0 {
		t.Fatal("could not resolve any nameserver to an IPv4 address")
	}
	return ips
}

// queryWithRetry tries querying each nameserver IP until one returns a
// non-empty result. This handles flaky connectivity to Cloudflare anycast IPs.
func queryWithRetry(t *testing.T, ips []string, recordType dnscheck.RecordType) []string {
	t.Helper()
	ctx := testContext(t)
	for _, ip := range ips {
		values, err := dnscheck.QueryServer(ctx, ip, testDomain, recordType)
		if err == nil && len(values) > 0 {
			t.Logf("successful query to %s: %v", ip, values)
			return values
		}
		if err != nil {
			t.Logf("query to %s failed: %v", ip, err)
		} else {
			t.Logf("query to %s returned empty", ip)
		}
	}
	return nil
}

func TestFindNameservers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := testContext(t)
	servers, err := dnscheck.FindNameservers(ctx, testDomain, "8.8.8.8:53")
	if err != nil {
		t.Fatalf("FindNameservers(%q) error: %v", testDomain, err)
	}
	if len(servers) < 2 {
		t.Errorf("expected at least 2 nameservers, got %d: %v", len(servers), servers)
	}
	t.Logf("nameservers: %v", servers)
}

func TestQueryServerA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ips := nameserverIPv4s(t)
	values := queryWithRetry(t, ips, dnscheck.TypeA)
	if len(values) == 0 {
		t.Fatal("got no A records from any nameserver")
	}

	expected := map[string]bool{"1.1.1.1": false, "1.0.0.1": false}
	for _, v := range values {
		if _, ok := expected[v]; ok {
			expected[v] = true
		}
	}
	for ip, found := range expected {
		if !found {
			t.Errorf("expected A record %s not found in results: %v", ip, values)
		}
	}
}

func TestQueryServerAAAA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ips := nameserverIPv4s(t)
	values := queryWithRetry(t, ips, dnscheck.TypeAAAA)
	if len(values) == 0 {
		t.Fatal("got no AAAA records from any nameserver")
	}

	expected := map[string]bool{
		"2606:4700:4700::1111": false,
		"2606:4700:4700::1001": false,
	}
	for _, v := range values {
		if _, ok := expected[v]; ok {
			expected[v] = true
		}
	}
	for ip, found := range expected {
		if !found {
			t.Errorf("expected AAAA record %s not found in results: %v", ip, values)
		}
	}
}

func TestCheckMatchAllA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := testContext(t)
	result, err := dnscheck.Check(ctx, dnscheck.CheckArgs{
		Domain:     testDomain,
		RecordType: dnscheck.TypeA,
		Expected:   []string{"1.1.1.1", "1.0.0.1"},
	})
	if err != nil {
		t.Fatalf("Check error: %v", err)
	}

	// In environments with flaky connectivity, some nameserver IPs may
	// be unreachable or return empty answers. We verify that at least
	// one server returned a matching result.
	var matched int
	for _, s := range result.Servers {
		if s.Error != nil {
			t.Logf("  %s (%s): error: %v", s.Nameserver, s.Address, s.Error)
		} else if s.Match {
			t.Logf("  %s (%s): match values=%v", s.Nameserver, s.Address, s.Values)
			matched++
		} else {
			t.Logf("  %s (%s): no match values=%v", s.Nameserver, s.Address, s.Values)
		}
	}
	if matched == 0 {
		t.Errorf("expected at least one server to match, none did")
	}
}

func TestCheckPartialAFails(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Expecting only one of the two A records should fail with strict matching.
	ctx := testContext(t)
	result, err := dnscheck.Check(ctx, dnscheck.CheckArgs{
		Domain:     testDomain,
		RecordType: dnscheck.TypeA,
		Expected:   []string{"1.1.1.1"},
	})
	if err != nil {
		t.Fatalf("Check error: %v", err)
	}

	matched, _ := result.Match()
	if matched {
		t.Errorf("expected Match()=false (strict matching should reject extra records), got true")
	}
}

func TestCheckNoMatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := testContext(t)
	result, err := dnscheck.Check(ctx, dnscheck.CheckArgs{
		Domain:     testDomain,
		RecordType: dnscheck.TypeA,
		Expected:   []string{"9.9.9.9"},
	})
	if err != nil {
		t.Fatalf("Check error: %v", err)
	}

	matched, _ := result.Match()
	if matched {
		t.Errorf("expected Match()=false for wrong IP, got true")
	}
}

func TestCheckAAAA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := testContext(t)
	result, err := dnscheck.Check(ctx, dnscheck.CheckArgs{
		Domain:     testDomain,
		RecordType: dnscheck.TypeAAAA,
		Expected:   []string{"2606:4700:4700::1111", "2606:4700:4700::1001"},
	})
	if err != nil {
		t.Fatalf("Check error: %v", err)
	}

	var matched int
	for _, s := range result.Servers {
		if s.Error != nil {
			t.Logf("  %s (%s): error: %v", s.Nameserver, s.Address, s.Error)
		} else if s.Match {
			t.Logf("  %s (%s): match values=%v", s.Nameserver, s.Address, s.Values)
			matched++
		} else {
			t.Logf("  %s (%s): no match values=%v", s.Nameserver, s.Address, s.Values)
		}
	}
	if matched == 0 {
		t.Errorf("expected at least one server to match AAAA records, none did")
	}
}

func TestCheckCustomResolver(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := testContext(t)
	result, err := dnscheck.Check(ctx, dnscheck.CheckArgs{
		Domain:     testDomain,
		RecordType: dnscheck.TypeA,
		Expected:   []string{"1.1.1.1", "1.0.0.1"},
		Resolver:   "1.1.1.1:53",
	})
	if err != nil {
		t.Fatalf("Check with custom resolver error: %v", err)
	}

	var matched int
	for _, s := range result.Servers {
		if s.Error != nil {
			t.Logf("  %s (%s): error: %v", s.Nameserver, s.Address, s.Error)
		} else if s.Match {
			t.Logf("  %s (%s): match values=%v", s.Nameserver, s.Address, s.Values)
			matched++
		} else {
			t.Logf("  %s (%s): no match values=%v", s.Nameserver, s.Address, s.Values)
		}
	}
	if matched == 0 {
		t.Errorf("expected at least one server to match with custom resolver, none did")
	}
}
