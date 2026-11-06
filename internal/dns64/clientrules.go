package dns64

import (
	"context"
	"database/sql"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ClientRule beantwortet A- und AAAA-Anfragen fuer einen Namen aus einem Clientnetz.
type ClientRule struct {
	ID        int64     `json:"id"`
	Network   string    `json:"network"` // einzelne IP oder CIDR, normalisiert als CIDR
	Name      string    `json:"name"`    // exakt oder *.example.com
	A         string    `json:"a,omitempty"`
	AAAA      string    `json:"aaaa,omitempty"`
	TTL       int       `json:"ttl"`
	Comment   string    `json:"comment,omitempty"`
	LocalOnly bool      `json:"local_only,omitempty"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

type compiledClientRule struct {
	rule       ClientRule
	prefix     netip.Prefix
	wildSuffix string
}

type clientRuleTable struct {
	exact map[string][]compiledClientRule
	wild  map[string][]compiledClientRule // Schluessel ohne "*."
}

// ClientRules liefert die Regeln nach Name und spezifischstem Netz sortiert.
func (m *Module) ClientRules(ctx context.Context) ([]ClientRule, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT id, network, name, a, aaaa, ttl, comment, local_only, enabled, created_at FROM dns64_client_rules ORDER BY name, network`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ClientRule{}
	for rows.Next() {
		var r ClientRule
		var created string
		if err := rows.Scan(&r.ID, &r.Network, &r.Name, &r.A, &r.AAAA, &r.TTL, &r.Comment, &r.LocalOnly, &r.Enabled, &created); err != nil {
			return nil, err
		}
		r.CreatedAt, _ = time.Parse(time.RFC3339, created)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortClientRules(out)
	return out, nil
}

// buildClientRules baut die unveraenderliche Momentaufnahme fuer die schnelle Abfrage.
func (m *Module) buildClientRules(ctx context.Context) error {
	list, err := m.ClientRules(ctx)
	if err != nil {
		return err
	}
	t := &clientRuleTable{exact: map[string][]compiledClientRule{}, wild: map[string][]compiledClientRule{}}
	for _, r := range list {
		if !r.Enabled {
			continue
		}
		p, err := netip.ParsePrefix(r.Network)
		if err != nil { // gespeicherte Eintraege sind normalisiert
			continue
		}
		x := compiledClientRule{rule: r, prefix: p}
		if s, ok := strings.CutPrefix(r.Name, "*."); ok {
			x.wildSuffix = s
			t.wild[s] = append(t.wild[s], x)
		} else {
			t.exact[r.Name] = append(t.exact[r.Name], x)
		}
	}
	m.clientRules.Store(t)
	return nil
}

// LookupClient liefert einen Netztreffer fuer A/AAAA; der Logtext enthaelt Regelname und CIDR.
func (m *Module) LookupClient(name string, qtype uint16, client netip.Addr) ([]dns.RR, string, bool) {
	if qtype != dns.TypeA && qtype != dns.TypeAAAA || !client.IsValid() {
		return nil, "", false
	}
	t := m.clientRules.Load()
	if t == nil {
		return nil, "", false
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	client = client.Unmap().WithZone("")
	var best *compiledClientRule
	consider := func(list []compiledClientRule) {
		for i := range list {
			x := &list[i]
			if !x.prefix.Contains(client) || (qtype == dns.TypeA && x.rule.A == "") || (qtype == dns.TypeAAAA && x.rule.AAAA == "") {
				continue
			}
			if best == nil || betterClientRule(*x, *best) {
				best = x
			}
		}
	}
	consider(t.exact[name])
	for s := name; ; {
		i := strings.IndexByte(s, '.')
		if i < 0 {
			break
		}
		s = s[i+1:]
		consider(t.wild[s])
	}
	if best == nil {
		return nil, "", false
	}
	r := best.rule
	h := hdr(name, qtype, r.TTL)
	if qtype == dns.TypeA {
		ip, _ := netip.ParseAddr(r.A)
		return []dns.RR{&dns.A{Hdr: h, A: ip.AsSlice()}}, r.Name + " @ " + r.Network, true
	}
	ip, _ := netip.ParseAddr(r.AAAA)
	return []dns.RR{&dns.AAAA{Hdr: h, AAAA: ip.AsSlice()}}, r.Name + " @ " + r.Network, true
}

// betterClientRule waehlt zuerst das spezifischste Netz, dann den genauesten Namen.
func betterClientRule(a, b compiledClientRule) bool {
	if a.prefix.Bits() != b.prefix.Bits() {
		return a.prefix.Bits() > b.prefix.Bits()
	}
	if a.wildSuffix == "" || b.wildSuffix == "" {
		return a.wildSuffix == "" && b.wildSuffix != ""
	}
	return len(a.wildSuffix) > len(b.wildSuffix)
}

func normalizeClientRule(r *ClientRule) error {
	r.Network = strings.TrimSpace(r.Network)
	r.Name = strings.TrimSpace(r.Name)
	r.A = strings.TrimSpace(r.A)
	r.AAAA = strings.TrimSpace(r.AAAA)
	r.Comment = strings.TrimSpace(r.Comment)
	if len(r.Comment) > 200 {
		return errCfg("err_comment")
	}
	if r.TTL == 0 {
		r.TTL = 300
	}
	if r.TTL < 1 || r.TTL > 86400 {
		return errCfg("err_ttl")
	}
	if r.Name == "" {
		return errCfg("err_name")
	}
	wild := strings.HasPrefix(r.Name, "*.")
	base := r.Name
	if wild {
		base = strings.TrimPrefix(base, "*.")
	}
	base = hostName(base)
	if !validName(base) {
		return errCfg("err_name")
	}
	r.Name = base
	if wild {
		r.Name = "*." + base
	}
	p, err := parseClientPrefix(r.Network)
	if err != nil {
		return errCfg("err_client_network")
	}
	r.Network = p.String()
	if r.A != "" {
		a, err := netip.ParseAddr(strings.Trim(r.A, "[]"))
		if err != nil || !a.Is4() || a.Zone() != "" || a.Is4In6() {
			return errCfg("err_ip_a")
		}
		r.A = a.String()
	}
	if r.AAAA != "" {
		a, err := netip.ParseAddr(strings.Trim(r.AAAA, "[]"))
		if err != nil || !a.Is6() || a.Is4In6() || a.Zone() != "" {
			return errCfg("err_ip_aaaa")
		}
		r.AAAA = a.String()
	}
	if r.A == "" && r.AAAA == "" {
		return errCfg("err_client_answer")
	}
	return nil
}

func parseClientPrefix(raw string) (netip.Prefix, error) {
	var p netip.Prefix
	if x, err := netip.ParsePrefix(raw); err == nil {
		p = x
	} else {
		a, addrErr := netip.ParseAddr(strings.Trim(raw, "[]"))
		if addrErr != nil {
			return netip.Prefix{}, addrErr
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	p = p.Masked()
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, errCfg("err_client_network")
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p, nil
}

// AddClientRule legt eine Antwortregel an.
func (m *Module) AddClientRule(ctx context.Context, r ClientRule) (ClientRule, error) {
	if err := normalizeClientRule(&r); err != nil {
		return r, err
	}
	if err := m.checkClientRule(ctx, &r, 0); err != nil {
		return r, err
	}
	r.Enabled, r.CreatedAt = true, time.Now().UTC()
	res, err := m.core.Writer().ExecContext(ctx, `INSERT INTO dns64_client_rules (network, name, a, aaaa, ttl, comment, local_only, enabled, created_at) VALUES (?,?,?,?,?,?,?,?,?)`,
		r.Network, r.Name, r.A, r.AAAA, r.TTL, r.Comment, r.LocalOnly, true, r.CreatedAt.Format(time.RFC3339))
	if err != nil {
		return r, err
	}
	r.ID, _ = res.LastInsertId()
	return r, m.loadRecords(ctx)
}

// UpdateClientRule aendert eine Antwortregel; an/aus bleibt.
func (m *Module) UpdateClientRule(ctx context.Context, id int64, r ClientRule) (ClientRule, error) {
	if err := normalizeClientRule(&r); err != nil {
		return r, err
	}
	if err := m.checkClientRule(ctx, &r, id); err != nil {
		return r, err
	}
	res, err := m.core.Writer().ExecContext(ctx, `UPDATE dns64_client_rules SET network = ?, name = ?, a = ?, aaaa = ?, ttl = ?, comment = ?, local_only = ? WHERE id = ?`,
		r.Network, r.Name, r.A, r.AAAA, r.TTL, r.Comment, r.LocalOnly, id)
	if err != nil {
		return r, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return r, errNotFound
	}
	if err := m.loadRecords(ctx); err != nil {
		return r, err
	}
	list, err := m.ClientRules(ctx)
	for _, x := range list {
		if x.ID == id {
			return x, err
		}
	}
	return r, err
}

func (m *Module) checkClientRule(ctx context.Context, r *ClientRule, self int64) error {
	var id int64
	err := m.core.Reader().QueryRowContext(ctx, `SELECT id FROM dns64_client_rules WHERE network = ? AND name = ?`, r.Network, r.Name).Scan(&id)
	switch {
	case err == nil && id != self:
		return errCfg("err_client_rule_dup")
	case err == nil:
		return nil
	case err == sql.ErrNoRows:
		return nil
	default:
		return err
	}
}

// DeleteClientRule loescht eine Antwortregel.
func (m *Module) DeleteClientRule(ctx context.Context, id int64) error {
	return m.clientRuleExec(ctx, `DELETE FROM dns64_client_rules WHERE id = ?`, id)
}

// SetClientRuleEnabled schaltet eine Antwortregel an oder aus.
func (m *Module) SetClientRuleEnabled(ctx context.Context, id int64, on bool) error {
	return m.clientRuleExec(ctx, `UPDATE dns64_client_rules SET enabled = ? WHERE id = ?`, on, id)
}

func (m *Module) clientRuleExec(ctx context.Context, query string, args ...any) error {
	res, err := m.core.Writer().ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return m.loadRecords(ctx)
}

func sortClientRules(list []ClientRule) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Name != list[j].Name {
			return list[i].Name < list[j].Name
		}
		a, _ := netip.ParsePrefix(list[i].Network)
		b, _ := netip.ParsePrefix(list[j].Network)
		if a.Bits() != b.Bits() {
			return a.Bits() > b.Bits()
		}
		return a.Addr().Less(b.Addr())
	})
}
