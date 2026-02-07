package dnscheck

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// DefaultResolver is the recursive resolver used when CheckArgs.Resolver is empty.
var DefaultResolver = "8.8.8.8:53"

var dnsClient = &dns.Client{}

var dnsTCPClient = &dns.Client{
	Net: "tcp",
}

// exchange sends a DNS query, falling back to TCP if UDP fails.
func exchange(ctx context.Context, msg *dns.Msg, address string) (*dns.Msg, error) {
	response, _, err := dnsClient.ExchangeContext(ctx, msg, address)
	if err != nil {
		response, _, err = dnsTCPClient.ExchangeContext(ctx, msg, address)
	}
	return response, err
}

// RecordType wraps a DNS record type so callers don't need to import miekg/dns.
type RecordType uint16

const (
	TypeA     RecordType = RecordType(dns.TypeA)
	TypeAAAA  RecordType = RecordType(dns.TypeAAAA)
	TypeCNAME RecordType = RecordType(dns.TypeCNAME)
	TypeTXT   RecordType = RecordType(dns.TypeTXT)
	TypeMX    RecordType = RecordType(dns.TypeMX)
)

func (t RecordType) String() string {
	switch t {
	case TypeA:
		return "A"
	case TypeAAAA:
		return "AAAA"
	case TypeCNAME:
		return "CNAME"
	case TypeTXT:
		return "TXT"
	case TypeMX:
		return "MX"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", uint16(t))
	}
}

// ParseRecordType maps a string like "A" or "aaaa" to a RecordType.
func ParseRecordType(value string) (RecordType, error) {
	switch strings.ToUpper(value) {
	case "A":
		return TypeA, nil
	case "AAAA":
		return TypeAAAA, nil
	case "CNAME":
		return TypeCNAME, nil
	case "TXT":
		return TypeTXT, nil
	case "MX":
		return TypeMX, nil
	default:
		return 0, fmt.Errorf("unsupported record type: %q", value)
	}
}

// CheckArgs holds the parameters for a DNS propagation check.
type CheckArgs struct {
	Domain     string
	RecordType RecordType
	Expected   []string
	Resolver   string      // defaults to "8.8.8.8:53" if empty
	Logger     *slog.Logger // optional; discards logs if nil
}

// ServerResult holds the result of querying a single nameserver IP.
type ServerResult struct {
	Nameserver string
	Address    string
	Values     []string
	Match      bool
	Error      error
}

// CheckResult holds the full result of a DNS propagation check.
type CheckResult struct {
	Domain      string
	RecordType  RecordType
	Expected    []string
	Nameservers []string
	Servers     []ServerResult
}

// Match reports whether every server returned the expected records.
// On success it returns true with an empty string. On failure it returns
// false with a short description of what went wrong.
func (r *CheckResult) Match() (bool, string) {
	if len(r.Servers) == 0 {
		return false, fmt.Sprintf("%s: no servers responded", r.Domain)
	}

	var errors, mismatches int
	for _, s := range r.Servers {
		if s.Error != nil {
			errors++
		} else if !s.Match {
			mismatches++
		}
	}

	failed := errors + mismatches
	if failed == 0 {
		return true, ""
	}

	total := len(r.Servers)
	return false, fmt.Sprintf("%s: %d of %d servers returned unexpected %s records", r.Domain, failed, total, r.RecordType)
}

// FindNameservers walks up the domain tree to find the zone's NS records.
// The resolver parameter specifies the recursive resolver to use (e.g. "8.8.8.8:53").
func FindNameservers(ctx context.Context, domain, resolver string) ([]string, error) {
	fqdn := dns.Fqdn(domain)
	current := fqdn
	for {
		msg := new(dns.Msg)
		msg.SetQuestion(current, dns.TypeNS)
		msg.RecursionDesired = true

		response, err := exchange(ctx, msg, resolver)
		if err != nil {
			return nil, fmt.Errorf("NS lookup for %s: %w", current, err)
		}

		var servers []string
		for _, record := range response.Answer {
			if ns, ok := record.(*dns.NS); ok {
				servers = append(servers, ns.Ns)
			}
		}
		if len(servers) > 0 {
			return servers, nil
		}

		// Move up one label.
		index := strings.Index(current, ".")
		if index < 0 {
			break
		}
		next := current[index+1:]
		if next == "" || next == "." {
			break
		}
		current = next
	}

	return nil, fmt.Errorf("no nameservers found for %s", fqdn)
}

// QueryServer sends a non-recursive query to a specific nameserver IP.
func QueryServer(ctx context.Context, server, domain string, recordType RecordType) ([]string, error) {
	fqdn := dns.Fqdn(domain)
	msg := new(dns.Msg)
	msg.SetQuestion(fqdn, uint16(recordType))
	// Set RecursionDesired even though we're querying authoritative nameservers
	// directly. Some nameservers (e.g. Cloudflare anycast IPs) return empty
	// answers for non-recursive queries, so we need this to get reliable results.
	msg.RecursionDesired = true

	target := net.JoinHostPort(server, "53")
	response, err := exchange(ctx, msg, target)
	if err != nil {
		return nil, err
	}

	var values []string
	for _, record := range response.Answer {
		switch r := record.(type) {
		case *dns.A:
			values = append(values, r.A.String())
		case *dns.AAAA:
			values = append(values, r.AAAA.String())
		case *dns.CNAME:
			values = append(values, r.Target)
		case *dns.TXT:
			values = append(values, strings.Join(r.Txt, ""))
		case *dns.MX:
			values = append(values, r.Mx)
		}
	}
	return values, nil
}

// Check performs a full DNS propagation check: finds nameservers, resolves
// each to IPs, queries each IP, and compares results against expected values.
func Check(ctx context.Context, args CheckArgs) (*CheckResult, error) {
	log := args.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	resolver := args.Resolver
	if resolver == "" {
		resolver = DefaultResolver
	}

	log.Info("finding nameservers", "domain", args.Domain, "resolver", resolver)
	nameservers, err := FindNameservers(ctx, args.Domain, resolver)
	if err != nil {
		return nil, err
	}
	log.Info("found nameservers", "nameservers", nameservers)

	result := &CheckResult{
		Domain:      args.Domain,
		RecordType:  args.RecordType,
		Expected:    args.Expected,
		Nameservers: nameservers,
	}

	for _, ns := range nameservers {
		log.Info("resolving nameserver", "nameserver", ns)
		addresses, err := net.DefaultResolver.LookupHost(ctx, ns)
		if err != nil {
			log.Warn("could not resolve nameserver", "nameserver", ns, "error", err)
			result.Servers = append(result.Servers, ServerResult{
				Nameserver: ns,
				Error:      fmt.Errorf("could not resolve nameserver: %w", err),
			})
			continue
		}

		// Filter to IPv4 addresses only, since IPv6 connectivity is not
		// always available and would cause spurious failures.
		var ipv4Addresses []string
		for _, addr := range addresses {
			if net.ParseIP(addr) != nil && net.ParseIP(addr).To4() != nil {
				ipv4Addresses = append(ipv4Addresses, addr)
			}
		}
		if len(ipv4Addresses) == 0 {
			log.Warn("no IPv4 addresses for nameserver", "nameserver", ns)
			result.Servers = append(result.Servers, ServerResult{
				Nameserver: ns,
				Error:      fmt.Errorf("no IPv4 addresses found for nameserver"),
			})
			continue
		}
		log.Info("resolved nameserver", "nameserver", ns, "addresses", ipv4Addresses)

		for _, addr := range ipv4Addresses {
			log.Info("querying server", "nameserver", ns, "address", addr, "type", args.RecordType)
			values, err := QueryServer(ctx, addr, args.Domain, args.RecordType)
			if err != nil {
				log.Warn("query failed", "nameserver", ns, "address", addr, "error", err)
				result.Servers = append(result.Servers, ServerResult{
					Nameserver: ns,
					Address:    addr,
					Error:      fmt.Errorf("query failed: %w", err),
				})
				continue
			}

			match := valuesMatch(values, args.Expected)
			log.Info("query result", "nameserver", ns, "address", addr, "values", values, "match", match)
			result.Servers = append(result.Servers, ServerResult{
				Nameserver: ns,
				Address:    addr,
				Values:     values,
				Match:      match,
			})
		}
	}

	return result, nil
}

// valuesMatch performs a strict set comparison between got and expected values.
// Both sets must contain exactly the same elements (order-independent,
// case-insensitive, FQDN-aware).
func valuesMatch(got, expected []string) bool {
	if len(got) != len(expected) {
		return false
	}

	normalize := func(s string) string {
		return strings.ToLower(strings.TrimSuffix(s, "."))
	}

	expectedSet := make(map[string]int, len(expected))
	for _, v := range expected {
		expectedSet[normalize(v)]++
	}

	for _, v := range got {
		key := normalize(v)
		count, ok := expectedSet[key]
		if !ok || count == 0 {
			return false
		}
		expectedSet[key] = count - 1
	}

	return true
}
