/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "ether-addr-util.h"
#include "in-addr-util.h"
#include "networkd-forward.h"
#include "networkd-util.h"

typedef enum NeighborKind {
        NEIGHBOR_KIND_STATIC,
        NEIGHBOR_KIND_PROXY,
        NEIGHBOR_KIND_BRIDGE_FDB,
        NEIGHBOR_KIND_VXLAN_FDB,
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

        uint8_t flags;                /* ndm_flags */
        struct in_addr_data dst_addr; /* NDA_DST */
        struct hw_addr_data ll_addr;  /* NDA_LLADDR */
        uint16_t vlan_id;             /* NDA_VLAN */
        uint16_t port;                /* NDA_PORT */
        uint32_t vni;                 /* NDA_VNI */
        int ifindex;                  /* NDA_IFINDEX */
        char *ifname;
        uint32_t src_vni;             /* NDA_SRC_VNI */
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

typedef enum FDBConfParserType {
        FDB_MAC_ADDRESS,
        FDB_FLAGS,
        FDB_VLAN_ID,
        FDB_DESTINATION,
        FDB_VNI,
        FDB_INTERFACE,
        _FDB_CONF_PARSER_MAX,
        _FDB_CONF_PARSER_INVALID = -EINVAL,
} FDBConfParserType;

CONFIG_PARSER_PROTOTYPE(config_parse_neighbor_section);
CONFIG_PARSER_PROTOTYPE(config_parse_proxy_neighbor);
CONFIG_PARSER_PROTOTYPE(config_parse_bridge_fdb_section);
CONFIG_PARSER_PROTOTYPE(config_parse_vxlan_fdb_section);
