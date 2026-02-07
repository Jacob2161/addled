package dnscheck

import (
	"testing"
)

func TestParseRecordType(t *testing.T) {
	tests := []struct {
		input   string
		want    RecordType
		wantErr bool
	}{
		{"A", TypeA, false},
		{"AAAA", TypeAAAA, false},
		{"CNAME", TypeCNAME, false},
		{"TXT", TypeTXT, false},
		{"MX", TypeMX, false},
		// case insensitivity
		{"a", TypeA, false},
		{"aaaa", TypeAAAA, false},
		{"cname", TypeCNAME, false},
		{"Txt", TypeTXT, false},
		{"mx", TypeMX, false},
		// invalid
		{"INVALID", 0, true},
		{"", 0, true},
		{"NS", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseRecordType(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRecordType(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseRecordType(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseRecordTypeErrorMessage(t *testing.T) {
	_, err := ParseRecordType("BOGUS")
	if err == nil {
		t.Fatal("expected error for invalid record type")
	}
	want := `unsupported record type: "BOGUS"`
	if err.Error() != want {
		t.Errorf("error message = %q, want %q", err.Error(), want)
	}
}

func TestRecordTypeString(t *testing.T) {
	tests := []struct {
		rt   RecordType
		want string
	}{
		{TypeA, "A"},
		{TypeAAAA, "AAAA"},
		{TypeCNAME, "CNAME"},
		{TypeTXT, "TXT"},
		{TypeMX, "MX"},
		{RecordType(9999), "UNKNOWN(9999)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.rt.String(); got != tt.want {
				t.Errorf("RecordType(%d).String() = %q, want %q", uint16(tt.rt), got, tt.want)
			}
		})
	}
}

func TestValuesMatch(t *testing.T) {
	tests := []struct {
		name     string
		got      []string
		expected []string
		want     bool
	}{
		{
			name:     "exact match single",
			got:      []string{"1.1.1.1"},
			expected: []string{"1.1.1.1"},
			want:     true,
		},
		{
			name:     "exact match multiple same order",
			got:      []string{"1.1.1.1", "1.0.0.1"},
			expected: []string{"1.1.1.1", "1.0.0.1"},
			want:     true,
		},
		{
			name:     "order independence",
			got:      []string{"1.0.0.1", "1.1.1.1"},
			expected: []string{"1.1.1.1", "1.0.0.1"},
			want:     true,
		},
		{
			name:     "extra value in got fails",
			got:      []string{"1.1.1.1", "1.0.0.1"},
			expected: []string{"1.1.1.1"},
			want:     false,
		},
		{
			name:     "missing value in got fails",
			got:      []string{"1.1.1.1"},
			expected: []string{"1.1.1.1", "1.0.0.1"},
			want:     false,
		},
		{
			name:     "no match",
			got:      []string{"9.9.9.9"},
			expected: []string{"1.1.1.1"},
			want:     false,
		},
		{
			name:     "both empty",
			got:      []string{},
			expected: []string{},
			want:     true,
		},
		{
			name:     "both nil",
			got:      nil,
			expected: nil,
			want:     true,
		},
		{
			name:     "got empty expected non-empty",
			got:      []string{},
			expected: []string{"1.1.1.1"},
			want:     false,
		},
		{
			name:     "case insensitivity",
			got:      []string{"Example.Com."},
			expected: []string{"example.com"},
			want:     true,
		},
		{
			name:     "FQDN normalization got has dot",
			got:      []string{"example.com."},
			expected: []string{"example.com"},
			want:     true,
		},
		{
			name:     "FQDN normalization expected has dot",
			got:      []string{"example.com"},
			expected: []string{"example.com."},
			want:     true,
		},
		{
			name:     "FQDN normalization both have dots",
			got:      []string{"example.com."},
			expected: []string{"example.com."},
			want:     true,
		},
		{
			name:     "duplicate values match",
			got:      []string{"1.1.1.1", "1.1.1.1"},
			expected: []string{"1.1.1.1", "1.1.1.1"},
			want:     true,
		},
		{
			name:     "duplicate values mismatch",
			got:      []string{"1.1.1.1", "1.1.1.1"},
			expected: []string{"1.1.1.1"},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := valuesMatch(tt.got, tt.expected); got != tt.want {
				t.Errorf("valuesMatch(%v, %v) = %v, want %v", tt.got, tt.expected, got, tt.want)
			}
		})
	}
}
