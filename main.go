package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/jacob2161/addled/dnscheck"
)

func main() {
	var recordType, name, expect string
	var timeout time.Duration
	var verbose bool
	flag.StringVar(&recordType, "type", "", "DNS record type (A, AAAA, CNAME, TXT, MX)")
	flag.StringVar(&name, "name", "", "domain name to check")
	flag.StringVar(&expect, "expect", "", "expected record value(s), comma-separated")
	flag.DurationVar(&timeout, "timeout", 5*time.Second, "timeout for the entire check")
	flag.BoolVar(&verbose, "verbose", false, "enable verbose logging")
	flag.Parse()

	if recordType == "" || name == "" || expect == "" {
		fmt.Fprintf(os.Stderr, "usage: addled --type TYPE --name NAME --expect VALUE[,VALUE...]\n")
		os.Exit(1)
	}

	rt, err := dnscheck.ParseRecordType(recordType)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	expected := strings.Split(expect, ",")
	for i := range expected {
		expected[i] = strings.TrimSpace(expected[i])
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var logger *slog.Logger
	if verbose {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}

	result, err := dnscheck.Check(ctx, dnscheck.CheckArgs{
		Domain:     name,
		RecordType: rt,
		Expected:   expected,
		Logger:     logger,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	matched, reason := result.Match()
	if !matched {
		fmt.Fprintln(os.Stderr, reason)
		for _, s := range result.Servers {
			label := s.Nameserver
			if s.Address != "" {
				label += " (" + s.Address + ")"
			}
			if s.Error != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", label, s.Error)
			} else if !s.Match {
				fmt.Fprintf(os.Stderr, "%s: got %s\n", label, strings.Join(s.Values, ", "))
			}
		}
		os.Exit(1)
	}
}
