/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "ether-addr-util.h"
#include "in-addr-util.h"
#include "networkd-forward.h"
#include "networkd-util.h"

typedef enum NeighborKind {
        NEIGHBOR_KIND_STATIC,
        NEIGHBOR_KIND_PROXY,
        _NEIGHBOR_KIND_MAX,
        _NEIGHBOR_KIND_INVALID = -EINVAL,
} NeighborKind;

typedef struct Neighbor {
        Network *network;
        Link *link;
        ConfigSection *section;
        NetworkConfigSource source;
        NetworkConfigState state;

        unsigned n_ref;

        NeighborKind kind;

        struct in_addr_data dst_addr; /* NDA_DST */
        struct hw_addr_data ll_addr;  /* NDA_LLADDR */
} Neighbor;

DECLARE_TRIVIAL_REF_UNREF_FUNC(Neighbor, neighbor);

int neighbor_get(Link *link, const Neighbor *in, Neighbor **ret);
int neighbor_remove(Neighbor *neighbor, Link *link);

int network_drop_invalid_neighbors(Network *network);

int link_drop_static_neighbors(Link *link);
int link_drop_unmanaged_neighbors(Link *link);

int link_request_static_neighbors(Link *link);

int manager_rtnl_process_neighbor(sd_netlink *rtnl, sd_netlink_message *message, Manager *m);

DEFINE_NETWORK_CONFIG_STATE_FUNCTIONS(Neighbor, neighbor);

typedef enum NeighborConfParserType {
        NEIGHBOR_DESTINATION_ADDRESS,
        NEIGHBOR_LINK_LAYER_ADDRESS,
        _NEIGHBOR_CONF_PARSER_MAX,
        _NEIGHBOR_CONF_PARSER_INVALID = -EINVAL,
} NeighborConfParserType;

CONFIG_PARSER_PROTOTYPE(config_parse_neighbor_section);
CONFIG_PARSER_PROTOTYPE(config_parse_proxy_neighbor);
