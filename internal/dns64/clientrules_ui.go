package dns64

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/ipv64net/node64/internal/module"
)

func (m *Module) clientRuleRoutes(mux *http.ServeMux, g module.Guards) {
	page := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /dns64/local/client-rules", page(m.pageTab("client-rules", "dns64.client_rules.title")))
	mux.Handle("POST /dns64/client-rules", page(m.pageClientRuleSave))
	mux.Handle("POST /dns64/client-rules/{id}/edit", page(m.pageClientRuleSave))
	mux.Handle("POST /dns64/client-rules/{id}/delete", page(m.pageClientRuleDelete))
	mux.Handle("POST /dns64/client-rules/{id}/toggle", page(m.pageClientRuleToggle))

	api := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /api/dns64/client-rules", api(m.apiClientRules))
	mux.Handle("POST /api/dns64/client-rules", api(m.apiClientRuleAdd))
	mux.Handle("PUT /api/dns64/client-rules/{id}", api(m.apiClientRuleUpdate))
	mux.Handle("DELETE /api/dns64/client-rules/{id}", api(m.apiClientRuleDelete))
	mux.Handle("POST /api/dns64/client-rules/{id}/enable", api(m.apiClientRuleToggle(true)))
	mux.Handle("POST /api/dns64/client-rules/{id}/disable", api(m.apiClientRuleToggle(false)))
}

func clientRuleForm(r *http.Request) ClientRule {
	ttl := formInt(r, "ttl")
	if ttl < 0 {
		ttl = 0
	}
	return ClientRule{Name: r.PostFormValue("name"), Network: r.PostFormValue("network"), A: r.PostFormValue("a"), AAAA: r.PostFormValue("aaaa"), TTL: ttl,
		Comment: r.PostFormValue("comment"), LocalOnly: r.PostFormValue("local_only") == "1"}
}

func (m *Module) pageClientRuleSave(w http.ResponseWriter, r *http.Request) {
	x := clientRuleForm(r)
	var err error
	if id := pathID(r); id > 0 {
		x, err = m.UpdateClientRule(r.Context(), id, x)
		if err == nil {
			m.audit(r, "dns64.client_rule.edit", x.Name, x.Network)
		}
	} else {
		x, err = m.AddClientRule(r.Context(), x)
		if err == nil {
			m.log.Info("client DNS rule added", "name", x.Name, "network", x.Network, "by", m.g.Actor(r))
			m.audit(r, "dns64.client_rule.add", x.Name, x.Network)
		}
	}
	m.clientRuleBack(w, r, err, "dns64.client_rules.saved")
}

func (m *Module) pageClientRuleDelete(w http.ResponseWriter, r *http.Request) {
	err := m.DeleteClientRule(r.Context(), pathID(r))
	if err == nil {
		m.audit(r, "dns64.client_rule.delete", r.PathValue("id"), "")
	}
	m.clientRuleBack(w, r, err, "dns64.client_rules.deleted")
}

func (m *Module) pageClientRuleToggle(w http.ResponseWriter, r *http.Request) {
	on := r.PostFormValue("on") == "1"
	err := m.SetClientRuleEnabled(r.Context(), pathID(r), on)
	if err == nil {
		m.audit(r, "dns64.client_rule."+onOff(on), r.PathValue("id"), "")
	}
	m.clientRuleBack(w, r, err, "")
}

func (m *Module) clientRuleBack(w http.ResponseWriter, r *http.Request, err error, okKey string) {
	if err != nil {
		m.g.Flash(w, r, "danger", m.errText(r, err))
	} else if okKey != "" {
		m.g.Flash(w, r, "success", m.g.T(r, okKey))
	}
	http.Redirect(w, r, "/dns64/local/client-rules", http.StatusSeeOther)
}

func (m *Module) apiClientRules(w http.ResponseWriter, r *http.Request) {
	list, err := m.ClientRules(r.Context())
	if err != nil {
		m.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (m *Module) apiClientRuleAdd(w http.ResponseWriter, r *http.Request) {
	var in ClientRule
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	x, err := m.AddClientRule(r.Context(), in)
	if err != nil {
		m.writeClientRuleError(w, r, err)
		return
	}
	m.log.Info("client DNS rule added", "name", x.Name, "network", x.Network, "via", "api", "by", m.g.Actor(r))
	m.audit(r, "dns64.client_rule.add", x.Name, x.Network)
	writeJSON(w, http.StatusCreated, x)
}

func (m *Module) apiClientRuleUpdate(w http.ResponseWriter, r *http.Request) {
	var in ClientRule
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	x, err := m.UpdateClientRule(r.Context(), pathID(r), in)
	if err != nil {
		m.writeClientRuleError(w, r, err)
		return
	}
	m.audit(r, "dns64.client_rule.edit", x.Name, x.Network)
	writeJSON(w, http.StatusOK, x)
}

func (m *Module) apiClientRuleDelete(w http.ResponseWriter, r *http.Request) {
	err := m.DeleteClientRule(r.Context(), pathID(r))
	if errors.Is(err, errNotFound) {
		writeErr(w, http.StatusNotFound, m.errText(r, err))
		return
	}
	if err != nil {
		m.fail(w, err)
		return
	}
	m.audit(r, "dns64.client_rule.delete", r.PathValue("id"), "")
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) apiClientRuleToggle(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := m.SetClientRuleEnabled(r.Context(), pathID(r), on)
		if errors.Is(err, errNotFound) {
			writeErr(w, http.StatusNotFound, m.errText(r, err))
			return
		}
		if err != nil {
			m.fail(w, err)
			return
		}
		m.audit(r, "dns64.client_rule."+onOff(on), r.PathValue("id"), "")
		list, err := m.ClientRules(r.Context())
		if err != nil {
			m.fail(w, err)
			return
		}
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		for _, x := range list {
			if x.ID == id {
				writeJSON(w, http.StatusOK, x)
				return
			}
		}
		writeErr(w, http.StatusNotFound, m.g.T(r, "dns64.err.not_found"))
	}
}

func (m *Module) writeClientRuleError(w http.ResponseWriter, r *http.Request, err error) {
	var ce *cfgError
	switch {
	case errors.As(err, &ce):
		writeErr(w, http.StatusBadRequest, m.errText(r, err))
	case errors.Is(err, errNotFound):
		writeErr(w, http.StatusNotFound, m.errText(r, err))
	default:
		m.fail(w, err)
	}
}
