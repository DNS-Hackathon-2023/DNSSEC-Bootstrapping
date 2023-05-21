/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "contrib/ctype.h"
#include "contrib/macros.h"
#include "contrib/net.h"
#include "contrib/sockaddr.h"
#include "contrib/wire_ctx.h"
#include "knot/include/module.h"
#include "knot/nameserver/process_query.h"
#include "knot/nameserver/query_module.h"
#include "knot/zone/zone-tree.h"

#define MOD_TTL		"\x03""ttl"

const yp_item_t auth_signal_conf[] = {
	{ MOD_TTL,    YP_TINT,   YP_VINT = { 0, UINT32_MAX, 3600, YP_STIME } },
	{ NULL }
};

int auth_signal_conf_check(knotd_conf_check_args_t *args)
{
	// Check type.
//	knotd_conf_t type = knotd_conf_check_item(args, MOD_TYPE);
//	if (type.count == 0) {
//		args->err_str = "no synthesis type specified";
//		return KNOT_EINVAL;
//	}

	return KNOT_EOK;
}

typedef struct {
	uint32_t ttl;
} synth_template_t;

/*! \brief Check if query fits the template requirements. */
static knotd_in_state_t template_match(knotd_in_state_t state, const synth_template_t *tpl,
                                       knot_pkt_t *pkt, knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	const knot_dname_t *label = qdata->name;
	const knot_dname_t *dname = mod->zone;
	knotd_mod_log(mod, LOG_WARNING, "label: %s", label);
	knotd_mod_log(mod, LOG_WARNING, "zone: %s", dname);

    uint16_t qtype = knot_pkt_qtype(qdata->query);
    if (!(qtype == KNOT_RRTYPE_CDS || qtype == KNOT_RRTYPE_CDNSKEY)) {
		knotd_mod_log(mod, LOG_WARNING, "Wrong qtype: %d", qtype);
        qdata->rcode = KNOT_RCODE_NOERROR;
        return KNOTD_IN_STATE_NODATA;
    }

	// Check for prefix mismatch.
	char *prefix = "\x07_dsboot";
	size_t prefix_len = strlen(prefix);

	if (label[0] != prefix_len - 1 ||
	    memcmp(label, prefix, prefix_len) != 0) {
		knotd_mod_log(mod, LOG_WARNING, "BAD!");
        qdata->rcode = KNOT_RCODE_NOERROR;
        return KNOTD_IN_STATE_NODATA;
	}
	knotd_mod_log(mod, LOG_WARNING, "GOOD!");

	// Copy target zone name
	knot_dname_t target[255];
	unsigned name_len = strlen((const char*)label) - strlen((const char*)dname) - prefix_len;
	memcpy(target, label + prefix_len, name_len);
	target[name_len] = '\0';
	knotd_mod_log(mod, LOG_WARNING, "target zone: %s", target);

    server_t *server = qdata->params->server;
    zone_t *zone = knot_zonedb_find(server->zone_db, target);

    if (zone == NULL) {
        knotd_mod_log(mod, LOG_WARNING, "don't know zone: %s", target);
        qdata->rcode = KNOT_RCODE_NXDOMAIN;
        return KNOTD_IN_STATE_MISS;
    }
	knot_rrset_t rrset = node_rrset(zone->contents->apex, qtype);
    if (rrset.owner == NULL) {
        knotd_mod_log(mod, LOG_WARNING, "zone apex doesn't have: %s", target);
        qdata->rcode = KNOT_RCODE_NOERROR;
        return KNOTD_IN_STATE_NODATA;
    }
    knotd_mod_log(mod, LOG_WARNING, "zone apex %s has qtype %d", target, qtype);
    knotd_mod_log(mod, LOG_WARNING, "TTL: %d", rrset.ttl);

    rrset.owner = qdata->name;

	// Insert synthetic response into packet.
	if (knot_pkt_put(pkt, 0, &rrset, KNOT_PF_FREE) != KNOT_EOK) {
		return KNOTD_IN_STATE_ERROR;
	}

	// Authoritative response.
	knot_wire_set_aa(pkt->wire);

	return KNOTD_IN_STATE_HIT;
}

static knotd_in_state_t solve_auth_signal(knotd_in_state_t state, knot_pkt_t *pkt,
                                          knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata && mod);

	// Applicable when search in zone fails.
	if (state != KNOTD_IN_STATE_MISS) {
		return state;
	}

	// Check if template fits.
	return template_match(state, knotd_mod_ctx(mod), pkt, qdata, mod);
}

int auth_signal_load(knotd_mod_t *mod)
{
	// Create synthesis template.
	synth_template_t *tpl = calloc(1, sizeof(*tpl));
	if (tpl == NULL) {
		return KNOT_ENOMEM;
	}

	// Set ttl.
	knotd_conf_t conf = knotd_conf_mod(mod, MOD_TTL);
	tpl->ttl = conf.single.integer;

	knotd_mod_ctx_set(mod, tpl);

	return knotd_mod_in_hook(mod, KNOTD_STAGE_ANSWER, solve_auth_signal);
}

void auth_signal_unload(knotd_mod_t *mod)
{
	synth_template_t *tpl = knotd_mod_ctx(mod);

	free(tpl);
}

KNOTD_MOD_API(authsignal, KNOTD_MOD_FLAG_SCOPE_ZONE,
              auth_signal_load, auth_signal_unload, auth_signal_conf,
              auth_signal_conf_check);
