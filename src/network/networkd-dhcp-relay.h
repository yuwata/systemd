/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

typedef enum DHCPRelayInterfaceMode {
        DHCP_RELAY_INTERFACE_NO,
        DHCP_RELAY_INTERFACE_UPSTREAM,
        DHCP_RELAY_INTERFACE_DOWNSTREAM,
        _DHCP_RELAY_INTERFACE_MAX,
        _DHCP_RELAY_INTERFACE_INVALID = -EINVAL,
} DHCPRelayInterfaceMode;

int manager_setup_dhcp_relay(Manager *manager);

int link_setup_dhcp_relay(Link *link);
int link_set_dhcp_relay_agent_address(Link *link, const Address *address);
int link_drop_dhcp_relay_agent_address(Link *link, const Address *address);
int link_start_dhcp_relay(Link *link);

DECLARE_STRING_TABLE_LOOKUP(dhcp_relay_interface_mode, DHCPRelayInterfaceMode);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_relay_interface_mode);
