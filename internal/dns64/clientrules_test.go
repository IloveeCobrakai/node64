package dns64

import (
	"context"
	"html/template"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func compiledRule(network, name, a, aaaa string) compiledClientRule {
	return compiledClientRule{rule: ClientRule{Network: network, Name: name, A: a, AAAA: aaaa}, prefix: netip.MustParsePrefix(network)}
}

func TestClientRulePageTemplateParses(t *testing.T) {
	if _, err := template.New("client-rules").ParseFS(templateFS, "templates/pages/client-rules.html"); err != nil {
		t.Fatal(err)
	}
}

func TestLookupClientMostSpecificNetwork(t *testing.T) {
	m := &Module{}
	m.clientRules.Store(&clientRuleTable{exact: map[string][]compiledClientRule{
		"service.example.com": {
			compiledRule("10.0.0.0/8", "service.example.com", "192.0.2.10", "2001:db8::10"),
			compiledRule("10.10.0.0/16", "service.example.com", "192.0.2.20", "2001:db8::20"),
			compiledRule("10.10.1.0/24", "service.example.com", "192.0.2.30", ""),
		},
	}})
	client := netip.MustParseAddr("10.10.1.25")

	rrs, rule, ok := m.LookupClient("service.example.com", dns.TypeA, client)
	if !ok || rule != "service.example.com @ 10.10.1.0/24" {
		t.Fatalf("A rule = %q, %v; want most specific /24", rule, ok)
	}
	if got := rrs[0].(*dns.A).A.String(); got != "192.0.2.30" {
		t.Fatalf("A answer = %s, want 192.0.2.30", got)
	}

	rrs, rule, ok = m.LookupClient("service.example.com", dns.TypeAAAA, client)
	if !ok || rule != "service.example.com @ 10.10.0.0/16" {
		t.Fatalf("AAAA rule = %q, %v; want next matching rule with AAAA", rule, ok)
	}
	if got := rrs[0].(*dns.AAAA).AAAA.String(); got != "2001:db8::20" {
		t.Fatalf("AAAA answer = %s, want 2001:db8::20", got)
	}
}

func TestLookupClientExactNameAndWildcard(t *testing.T) {
	m := &Module{}
	m.clientRules.Store(&clientRuleTable{
		exact: map[string][]compiledClientRule{
			"host.example.com": {compiledRule("192.168.50.0/24", "host.example.com", "192.0.2.2", "")},
		},
		wild: map[string][]compiledClientRule{
			"example.com": {compiledRule("192.168.50.0/24", "*.example.com", "192.0.2.1", "")},
		},
	})
	client := netip.MustParseAddr("192.168.50.25")

	rrs, rule, ok := m.LookupClient("host.example.com.", dns.TypeA, client)
	if !ok || rule != "host.example.com @ 192.168.50.0/24" {
		t.Fatalf("exact-name rule = %q, %v; want exact name", rule, ok)
	}
	if got := rrs[0].(*dns.A).A.String(); got != "192.0.2.2" {
		t.Fatalf("exact-name answer = %s, want 192.0.2.2", got)
	}

	rrs, rule, ok = m.LookupClient("other.example.com", dns.TypeA, client)
	if !ok || rule != "*.example.com @ 192.168.50.0/24" {
		t.Fatalf("wildcard rule = %q, %v; want wildcard", rule, ok)
	}
	if got := rrs[0].(*dns.A).A.String(); got != "192.0.2.1" {
		t.Fatalf("wildcard answer = %s, want 192.0.2.1", got)
	}
}

func TestLookupClientFallsThroughWhenNoRuleMatches(t *testing.T) {
	m := &Module{}
	m.clientRules.Store(&clientRuleTable{exact: map[string][]compiledClientRule{
		"service.example.com": {compiledRule("10.10.0.0/16", "service.example.com", "192.0.2.10", "")},
	}})
	for _, tc := range []struct {
		name   string
		qtype  uint16
		client netip.Addr
	}{
		{name: "service.example.com", qtype: dns.TypeA, client: netip.MustParseAddr("192.168.1.2")},
		{name: "service.example.com", qtype: dns.TypeAAAA, client: netip.MustParseAddr("10.10.1.2")},
		{name: "other.example.com", qtype: dns.TypeA, client: netip.MustParseAddr("10.10.1.2")},
		{name: "service.example.com", qtype: dns.TypeTXT, client: netip.MustParseAddr("10.10.1.2")},
	} {
		if rrs, rule, ok := m.LookupClient(tc.name, tc.qtype, tc.client); ok || rrs != nil || rule != "" {
			t.Errorf("LookupClient(%q, %d, %s) = %v, %q, %v; want no match", tc.name, tc.qtype, tc.client, rrs, rule, ok)
		}
	}
}

func TestClientRuleCRUDReloadsResolver(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	broad, err := m.AddClientRule(ctx, ClientRule{Network: "10.0.0.0/8", Name: "service.example.com", A: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	narrow, err := m.AddClientRule(ctx, ClientRule{Network: "10.10.0.0/16", Name: "service.example.com", A: "192.0.2.20"})
	if err != nil {
		t.Fatal(err)
	}
	client := netip.MustParseAddr("10.10.1.8")
	if _, rule, ok := m.LookupClient("service.example.com", dns.TypeA, client); !ok || rule != "service.example.com @ 10.10.0.0/16" {
		t.Fatalf("initial match = %q, %v; want /16", rule, ok)
	}
	if err := m.SetClientRuleEnabled(ctx, narrow.ID, false); err != nil {
		t.Fatal(err)
	}
	if rrs, rule, ok := m.LookupClient("service.example.com", dns.TypeA, client); !ok || rule != "service.example.com @ 10.0.0.0/8" || rrs[0].(*dns.A).A.String() != "192.0.2.10" {
		t.Fatalf("after disable = %v, %q, %v; want broad rule", rrs, rule, ok)
	}
	_, err = m.UpdateClientRule(ctx, broad.ID, ClientRule{Network: "10.0.0.0/8", Name: "service.example.com", A: "192.0.2.30"})
	if err != nil {
		t.Fatal(err)
	}
	if rrs, _, ok := m.LookupClient("service.example.com", dns.TypeA, client); !ok || rrs[0].(*dns.A).A.String() != "192.0.2.30" {
		t.Fatalf("after update = %v, %v; want 192.0.2.30", rrs, ok)
	}
	if err := m.DeleteClientRule(ctx, broad.ID); err != nil {
		t.Fatal(err)
	}
	if rrs, rule, ok := m.LookupClient("service.example.com", dns.TypeA, client); ok || rrs != nil || rule != "" {
		t.Fatalf("after delete = %v, %q, %v; want no match", rrs, rule, ok)
	}
}
