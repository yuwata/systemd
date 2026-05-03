/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/rtnetlink.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "dhcp-relay-internal.h"
#include "hashmap.h"
#include "iovec-util.h"
#include "networkd-address.h"
#include "networkd-dhcp-relay.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "parse-util.h"
#include "string-table.h"
#include "string-util.h"

int manager_setup_dhcp_relay(Manager *manager) {
        int r;

        assert(manager);
        assert(manager->event);

        if (manager->dhcp_relay)
                return 0;

        if (in4_addr_is_null(&manager->dhcp_relay_server_address))
                return -EADDRNOTAVAIL;

        _cleanup_(sd_dhcp_relay_unrefp) sd_dhcp_relay *relay = NULL;
        r = sd_dhcp_relay_new(&relay);
        if (r < 0)
                return r;

        r = sd_dhcp_relay_attach_event(relay, manager->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return r;

        r = sd_dhcp_relay_set_remote_id(relay, &manager->dhcp_relay_remote_id);
        if (r < 0)
                return r;

        r = sd_dhcp_relay_set_server_identifier_override(relay, manager->dhcp_relay_override_server_id);
        if (r < 0)
                return r;

        r = dhcp_relay_set_extra_options(relay, &manager->dhcp_relay_extra_options);
        if (r < 0)
                return r;

        manager->dhcp_relay = TAKE_PTR(relay);
        return 0;
}

static bool link_address_is_suitable_for_relay(Link *link, const Address *address) {
        assert(link);
        assert(address);

        if (address->family != AF_INET)
                return false;

        if (address->scope != RT_SCOPE_UNIVERSE)
                return false;

        if (in4_addr_is_localhost(&address->in_addr.in))
                return false;

        if (in4_addr_is_link_local(&address->in_addr.in))
                return false;

        if (!address->link && address_get(link, address, (Address**) &address) < 0)
                return false;

        if (address->source != NETWORK_CONFIG_SOURCE_STATIC)
                return false;

        if (!address_is_ready(address))
                return false;

        if (FLAGS_SET(address->flags, IFA_F_SECONDARY))
                return false;

        return true;
}

static int link_find_relay_agent_address(Link *link, struct in_addr *ret) {
        assert(link);
        assert(link->network);
        assert(ret);

        Address *a;
        ORDERED_HASHMAP_FOREACH(a, link->network->addresses_by_section)
                if (!link_address_is_suitable_for_relay(link, a)) {
                        *ret = a->in_addr.in;
                        return 0;
                }

        return -ENXIO;
}

int link_setup_dhcp_relay(Link *link) {
        int r;

        assert(link);
        assert(link->manager);
        assert(link->network);
        assert(!link->dhcp_relay_interface);

        if (link->network->dhcp_relay == DHCP_RELAY_INTERFACE_NO)
                return 0;

        r = manager_setup_dhcp_relay(link->manager);
        if (r == -EADDRNOTAVAIL) {
                log_link_warning_errno(link, r, "[DHCPRelay] ServerAddress= in networkd.conf is not configured. DHCP Relay agent is disabled.");
                return 0;
        }
        if (r < 0)
                return r;

        bool upstream = link->network->dhcp_relay == DHCP_RELAY_INTERFACE_UPSTREAM;

        _cleanup_(sd_dhcp_relay_interface_unrefp) sd_dhcp_relay_interface *interface = NULL;
        r = sd_dhcp_relay_add_interface(link->manager->dhcp_relay, link->ifindex, upstream, &interface);
        if (r < 0)
                return r;

        r = sd_dhcp_relay_interface_set_ifname(interface, link->ifname);
        if (r < 0)
                return r;

        if (upstream) {
                r = sd_dhcp_relay_upstream_set_priority(interface, link->network->dhcp_relay_interface_priority);
                if (r < 0)
                        return r;
        } else {
                r = sd_dhcp_relay_downstream_set_gateway_address(interface, &link->network->dhcp_relay_gateway_address);
                if (r < 0)
                        return r;

                if (iovec_is_set(&link->network->dhcp_relay_circuit_id))
                        r = sd_dhcp_relay_downstream_set_circuit_id(interface, &link->network->dhcp_relay_circuit_id);
                else
                        r = sd_dhcp_relay_downstream_set_circuit_id(interface, &IOVEC_MAKE_STRING(link->ifname));
                if (r < 0)
                        return r;

                r = sd_dhcp_relay_downstream_set_virtual_subnet_selection(interface, &link->network->dhcp_relay_vss);
                if (r < 0)
                        return r;

                r = downstream_set_extra_options(interface, &link->network->dhcp_relay_extra_options);
                if (r < 0)
                        return r;
        }

        if (in4_addr_is_set(&link->network->dhcp_relay_agent_address)) {
                r = sd_dhcp_relay_interface_set_address(interface, &link->network->dhcp_relay_agent_address);
                if (r < 0)
                        return r;
        } else {
                struct in_addr a;
                if (link_find_relay_agent_address(link, &a) >= 0) {
                        r = sd_dhcp_relay_interface_set_address(interface, &a);
                        if (r < 0)
                                return r;
                }
        }

        link->dhcp_relay_interface = TAKE_PTR(interface);
        return 0;
}

int link_set_dhcp_relay_agent_address(Link *link, const Address *address) {
        int r;

        assert(link);
        assert(link->manager);
        assert(address);

        /* This is called when an address is assigned/updated. */

        if (!link->dhcp_relay_interface)
                return 0;

        if (link->manager->state != MANAGER_RUNNING)
                return 0;

        if (!link->network)
                return 0;

        /* r == 1 means an address is already set. */
        r = sd_dhcp_relay_interface_get_address(link->dhcp_relay_interface, /* ret= */ NULL);
        if (r < 0)
                return r;
        if (r > 0)
                return 0; /* already set. */

        if (!link_address_is_suitable_for_relay(link, address))
                return 0;

        r = sd_dhcp_relay_interface_set_address(link->dhcp_relay_interface, &address->in_addr.in);
        if (r < 0)
                return r;

        return 1; /* set */
}

int link_drop_dhcp_relay_agent_address(Link *link, const Address *address) {
        int r;

        assert(link);
        assert(link->manager);
        assert(address);

        /* This is called when an address is removed from the interface. */

        if (!link->dhcp_relay_interface)
                return 0;

        if (link->manager->state != MANAGER_RUNNING)
                return 0;

        if (!link->network)
                return 0;

        struct in_addr a;
        r = sd_dhcp_relay_interface_get_address(link->dhcp_relay_interface, &a);
        if (r <= 0)
                return r;

        if (address->family != AF_INET)
                return 0;

        if (!in4_addr_equal(&address->in_addr.in, &a))
                return 0;

        r = sd_dhcp_relay_interface_stop(link->dhcp_relay_interface);
        if (r < 0)
                return r;

        r = sd_dhcp_relay_interface_set_address(link->dhcp_relay_interface, NULL);
        if (r < 0)
                return r;

        /* When the agent address is unset, we need to reset the gateway address. */
        if (link->network->dhcp_relay == DHCP_RELAY_INTERFACE_DOWNSTREAM) {
                r = sd_dhcp_relay_downstream_set_gateway_address(link->dhcp_relay_interface, &link->network->dhcp_relay_gateway_address);
                if (r < 0)
                        return r;
        }

        return 0;
}

int link_start_dhcp_relay(Link *link) {
        int r;

        assert(link);
        assert(link->manager);

        /* This is called when the link gained a carrier. */

        if (!link->dhcp_relay_interface)
                return 0;

        if (link->manager->state != MANAGER_RUNNING)
                return 0;

        if (!link->network)
                return 0;

        if (!link_has_carrier(link))
                return 0;

        if (sd_dhcp_relay_interface_is_running(link->dhcp_relay_interface))
                return 0;

        r = sd_dhcp_relay_interface_get_address(link->dhcp_relay_interface, /* ret= */ NULL);
        if (r <= 0)
                return r;

        return sd_dhcp_relay_interface_start(link->dhcp_relay_interface);
}

static const char * const dhcp_relay_interface_mode_table[_DHCP_RELAY_INTERFACE_MAX] = {
        [DHCP_RELAY_INTERFACE_NO] = "no",
        [DHCP_RELAY_INTERFACE_UPSTREAM] = "upstream",
        [DHCP_RELAY_INTERFACE_DOWNSTREAM] = "downstream",
};

DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(dhcp_relay_interface_mode, DHCPRelayInterfaceMode);

int config_parse_dhcp_relay_interface_mode(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        DHCPRelayInterfaceMode m, *mode = ASSERT_PTR(data);

        if (isempty(rvalue) || parse_boolean(rvalue) == 0) {
                *mode = DHCP_RELAY_INTERFACE_NO;
                return 0;
        }

        m = dhcp_relay_interface_mode_from_string(rvalue);
        if (m < 0)
                return log_syntax_parse_error(unit, filename, line, m, lvalue, rvalue);

        *mode = m;
        return 0;
}
