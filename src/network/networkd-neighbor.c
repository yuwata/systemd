/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-netlink.h"

#include "alloc-util.h"
#include "conf-parser.h"
#include "errno-util.h"
#include "hashmap.h"
#include "netlink-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-neighbor.h"
#include "networkd-network.h"
#include "networkd-queue.h"
#include "ordered-set.h"
#include "parse-util.h"
#include "set.h"
#include "siphash24.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "vxlan.h"

static const char * const neighbor_kind_table[_NEIGHBOR_KIND_MAX] = {
        [NEIGHBOR_KIND_STATIC]     = "static neighbor",
        [NEIGHBOR_KIND_PROXY]      = "proxy neighbor",
        [NEIGHBOR_KIND_BRIDGE_FDB] = "bridge fdb",
        [NEIGHBOR_KIND_VXLAN_FDB]  = "vxlan fdb",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(neighbor_kind, NeighborKind);

static Neighbor* neighbor_detach_impl(Neighbor *neighbor) {
        assert(neighbor);
        assert(!neighbor->link || !neighbor->network);

        if (neighbor->network) {
                assert(neighbor->section);
                ordered_hashmap_remove(neighbor->network->neighbors_by_section, neighbor->section);
                neighbor->network = NULL;
                return neighbor;
        }

        if (neighbor->link) {
                set_remove(neighbor->link->neighbors, neighbor);
                neighbor->link = NULL;
                return neighbor;
        }

        return NULL;
}

static void neighbor_detach(Neighbor *neighbor) {
        neighbor_unref(neighbor_detach_impl(neighbor));
}

static Neighbor* neighbor_free(Neighbor *neighbor) {
        if (!neighbor)
                return NULL;

        neighbor_detach_impl(neighbor);

        config_section_free(neighbor->section);

        free(neighbor->ifname);

        return mfree(neighbor);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(Neighbor, neighbor, neighbor_free);
DEFINE_SECTION_CLEANUP_FUNCTIONS(Neighbor, neighbor_unref);

static void neighbor_hash_func(const Neighbor *neighbor, struct siphash *state);
static int neighbor_compare_func(const Neighbor *a, const Neighbor *b);

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
        neighbor_hash_ops_detach,
        Neighbor,
        neighbor_hash_func,
        neighbor_compare_func,
        neighbor_detach);

DEFINE_PRIVATE_HASH_OPS(
        neighbor_hash_ops,
        Neighbor,
        neighbor_hash_func,
        neighbor_compare_func);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        neighbor_section_hash_ops,
        ConfigSection,
        config_section_hash_func,
        config_section_compare_func,
        Neighbor,
        neighbor_detach);

static int neighbor_new(NeighborKind kind, Neighbor **ret) {
        Neighbor *neighbor;

        assert(ret);
        assert(kind >= 0);

        neighbor = new(Neighbor, 1);
        if (!neighbor)
                return -ENOMEM;

        *neighbor = (Neighbor) {
                .n_ref = 1,
                .kind = kind,
        };

        *ret = TAKE_PTR(neighbor);
        return 0;
}

static int neighbor_new_static(Network *network, const char *filename, unsigned section_line, NeighborKind kind, Neighbor **ret) {
        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(neighbor_unrefp) Neighbor *neighbor = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        neighbor = ordered_hashmap_get(network->neighbors_by_section, n);
        if (neighbor) {
                assert(neighbor->kind == kind);
                *ret = TAKE_PTR(neighbor);
                return 0;
        }

        r = neighbor_new(kind, &neighbor);
        if (r < 0)
                return r;

        neighbor->network = network;
        neighbor->section = TAKE_PTR(n);
        neighbor->source = NETWORK_CONFIG_SOURCE_STATIC;

        r = ordered_hashmap_ensure_put(&network->neighbors_by_section, &neighbor_section_hash_ops, neighbor->section, neighbor);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(neighbor);
        return 0;
}

static int neighbor_dup(const Neighbor *neighbor, Neighbor **ret) {
        _cleanup_(neighbor_unrefp) Neighbor *dest = NULL;
        int r;

        assert(neighbor);
        assert(ret);

        dest = newdup(Neighbor, neighbor, 1);
        if (!dest)
                return -ENOMEM;

        /* Clear the reference counter and all pointers */
        dest->n_ref = 1;
        dest->link = NULL;
        dest->network = NULL;
        dest->section = NULL;
        dest->ifname = NULL;

        r = strdup_to(&dest->ifname, neighbor->ifname);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(dest);
        return 0;
}

static void neighbor_hash_func(const Neighbor *neighbor, struct siphash *state) {
        assert(neighbor);

        siphash24_compress_typesafe(neighbor->kind, state);

        switch (neighbor->kind) {
        case NEIGHBOR_KIND_STATIC:
        case NEIGHBOR_KIND_PROXY:
                siphash24_compress_typesafe(neighbor->dst_addr.family, state);

                if (!IN_SET(neighbor->dst_addr.family, AF_INET, AF_INET6))
                        /* treat any other address family as AF_UNSPEC */
                        return;

                /* Equality of neighbors are given by the destination address.
                 * See neigh_lookup() in the kernel. */
                in_addr_hash_func(&neighbor->dst_addr.address, neighbor->dst_addr.family, state);
                break;

        case NEIGHBOR_KIND_BRIDGE_FDB:
                assert(neighbor->ll_addr.length == ETH_ALEN);
                siphash24_compress_typesafe(neighbor->ll_addr.ether, state);
                siphash24_compress_typesafe(neighbor->vlan_id, state);
                break;

        case NEIGHBOR_KIND_VXLAN_FDB:
                assert(neighbor->ll_addr.length == ETH_ALEN);
                siphash24_compress_typesafe(neighbor->ll_addr.ether, state);
                siphash24_compress_typesafe(neighbor->src_vni, state);

                if (ether_addr_is_multicast(&neighbor->ll_addr.ether) ||
                    ether_addr_is_null(&neighbor->ll_addr.ether)) {
                        /* For multicast or NULL MAC address, multiple remote destinations. */
                        siphash24_compress_typesafe(neighbor->dst_addr.family, state);
                        in_addr_hash_func(&neighbor->dst_addr.address, neighbor->dst_addr.family, state);
                        siphash24_compress_typesafe(neighbor->port, state);
                        siphash24_compress_typesafe(neighbor->vni, state);
                        siphash24_compress_typesafe(neighbor->ifindex, state);
                        if (neighbor->ifindex == 0)
                                siphash24_compress_string(neighbor->ifname, state); /* For Network or Request object. */
                }
                break;

        default:
                assert_not_reached();
        }
}

static int neighbor_compare_func(const Neighbor *a, const Neighbor *b) {
        int r;

        r = CMP(a->kind, b->kind);
        if (r != 0)
                return r;

        switch (a->kind) {
        case NEIGHBOR_KIND_STATIC:
        case NEIGHBOR_KIND_PROXY:
                r = CMP(a->dst_addr.family, b->dst_addr.family);
                if (r != 0)
                        return r;

                if (!IN_SET(a->dst_addr.family, AF_INET, AF_INET6))
                        /* treat any other address family as AF_UNSPEC */
                        return 0;

                return memcmp(&a->dst_addr.address, &b->dst_addr.address, FAMILY_ADDRESS_SIZE(a->dst_addr.family));

        case NEIGHBOR_KIND_BRIDGE_FDB:
                assert(a->ll_addr.length == ETH_ALEN);
                assert(b->ll_addr.length == ETH_ALEN);
                r = memcmp(&a->ll_addr.ether, &b->ll_addr.ether, ETH_ALEN);
                if (r != 0)
                        return r;

                return CMP(a->vlan_id, b->vlan_id);

        case NEIGHBOR_KIND_VXLAN_FDB:
                assert(a->ll_addr.length == ETH_ALEN);
                assert(b->ll_addr.length == ETH_ALEN);
                r = memcmp(&a->ll_addr.ether, &b->ll_addr.ether, ETH_ALEN);
                if (r != 0)
                        return r;

                r = CMP(a->src_vni, b->src_vni);
                if (r != 0)
                        return r;

                if (ether_addr_is_multicast(&a->ll_addr.ether) ||
                    ether_addr_is_null(&a->ll_addr.ether)) {
                        r = CMP(a->dst_addr.family, b->dst_addr.family);
                        if (r != 0)
                                return r;

                        r = memcmp(&a->dst_addr.address, &b->dst_addr.address, FAMILY_ADDRESS_SIZE(a->dst_addr.family));
                        if (r != 0)
                                return r;

                        r = CMP(a->port, b->port);
                        if (r != 0)
                                return r;

                        r = CMP(a->vni, b->vni);
                        if (r != 0)
                                return r;

                        r = CMP(a->ifindex, b->ifindex);
                        if (r != 0)
                                return r;

                        if (a->ifindex == 0) {
                                r = strcmp_ptr(a->ifname, b->ifname);
                                if (r != 0)
                                        return r;
                        }
                }

                return 0;

        default:
                assert_not_reached();
        }
}

static int neighbor_get_request(Link *link, const Neighbor *neighbor, Request **ret) {
        Request *req;

        assert(link);
        assert(link->manager);
        assert(neighbor);

        req = ordered_set_get(
                        link->manager->request_queue,
                        &(Request) {
                                .link = link,
                                .type = REQUEST_TYPE_NEIGHBOR,
                                .userdata = (void*) neighbor,
                                .hash_func = (hash_func_t) neighbor_hash_func,
                                .compare_func = (compare_func_t) neighbor_compare_func,
                        });
        if (!req)
                return -ENOENT;

        if (ret)
                *ret = req;
        return 0;
}

int neighbor_get(Link *link, const Neighbor *in, Neighbor **ret) {
        Neighbor *existing;

        assert(link);
        assert(in);

        existing = set_get(link->neighbors, in);
        if (!existing)
                return -ENOENT;

        if (ret)
                *ret = existing;
        return 0;
}

static int neighbor_attach(Link *link, Neighbor *neighbor) {
        int r;

        assert(link);
        assert(neighbor);
        assert(!neighbor->link);

        r = set_ensure_put(&link->neighbors, &neighbor_hash_ops_detach, neighbor);
        if (r < 0)
                return r;
        if (r == 0)
                return -EEXIST;

        neighbor->link = link;
        neighbor_ref(neighbor);
        return 0;
}

static int neighbor_get_link(Manager *manager, const Neighbor *neighbor, Link **ret) {
        assert(neighbor);

        if (neighbor->ifindex > 0)
                return link_get_by_index(manager, neighbor->ifindex, ret);
        if (neighbor->ifname)
                return link_get_by_name(manager, neighbor->ifname, ret);

        if (ret)
                *ret = NULL;
        return 0;
}

static void log_neighbor_debug(const Neighbor *neighbor, const char *str, const Link *link) {
        _cleanup_free_ char *state = NULL;

        assert(neighbor);
        assert(str);
        assert(link);

        if (!DEBUG_LOGGING)
                return;

        (void) network_config_state_to_string_alloc(neighbor->state, &state);

        switch (neighbor->kind) {
        case NEIGHBOR_KIND_STATIC:
                log_link_debug(link,
                               "%s %s %s (%s): %s -> %s",
                               str, strna(network_config_source_to_string(neighbor->source)),
                               neighbor_kind_to_string(neighbor->kind), strna(state),
                               IN_ADDR_TO_STRING(neighbor->dst_addr.family, &neighbor->dst_addr.address),
                               HW_ADDR_TO_STR(&neighbor->ll_addr));
                break;

        case NEIGHBOR_KIND_PROXY:
                log_link_debug(link,
                               "%s %s %s (%s): %s",
                               str, strna(network_config_source_to_string(neighbor->source)),
                               neighbor_kind_to_string(neighbor->kind), strna(state),
                               IN_ADDR_TO_STRING(neighbor->dst_addr.family, &neighbor->dst_addr.address));
                break;

        case NEIGHBOR_KIND_BRIDGE_FDB:
                log_link_debug(link,
                               "%s %s %s (%s): %s, vlan: %"PRIu32,
                               str, strna(network_config_source_to_string(neighbor->source)),
                               neighbor_kind_to_string(neighbor->kind), strna(state),
                               HW_ADDR_TO_STR(&neighbor->ll_addr), neighbor->vlan_id);
                break;

        case NEIGHBOR_KIND_VXLAN_FDB: {
                Link *out = NULL;
                (void) neighbor_get_link(link->manager, neighbor, &out);

                log_link_debug(link,
                               "%s %s %s (%s): (%s, src_vni: %"PRIu32") -> (%s, port: %u, vni: %"PRIu32", interface: %s)",
                               str, strna(network_config_source_to_string(neighbor->source)),
                               neighbor_kind_to_string(neighbor->kind), strna(state),
                               HW_ADDR_TO_STR(&neighbor->ll_addr), neighbor->src_vni,
                               IN_ADDR_TO_STRING(neighbor->dst_addr.family, &neighbor->dst_addr.address),
                               neighbor->port, neighbor->vni, strna(out ? out->ifname : NULL));
                break;
        }

        default:
                assert_not_reached();
        }
}

static void neighbor_forget(Link *link, Neighbor *neighbor, const char *msg) {
        assert(link);
        assert(neighbor);
        assert(msg);

        Request *req;
        if (neighbor_get_request(link, neighbor, &req) >= 0)
                neighbor_enter_removed(req->userdata);

        if (!neighbor->link && neighbor_get(link, neighbor, &neighbor) < 0)
                return;

        neighbor_enter_removed(neighbor);
        log_neighbor_debug(neighbor, msg, link);
        neighbor_detach(neighbor);
}

static int neighbor_get_ndm_family(const Neighbor *neighbor) {
        assert(neighbor);

        switch (neighbor->kind) {
        case NEIGHBOR_KIND_STATIC:
        case NEIGHBOR_KIND_PROXY:
                assert(IN_SET(neighbor->dst_addr.family, AF_INET, AF_INET6));
                return neighbor->dst_addr.family;

        case NEIGHBOR_KIND_BRIDGE_FDB:
        case NEIGHBOR_KIND_VXLAN_FDB:
                return AF_BRIDGE;

        default:
                assert_not_reached();
        }
}

static uint16_t neighbor_get_ndm_state(const Neighbor *neighbor) {
        assert(neighbor);

        switch (neighbor->kind) {
        case NEIGHBOR_KIND_STATIC:
        case NEIGHBOR_KIND_PROXY:
                return NUD_PERMANENT;

        case NEIGHBOR_KIND_BRIDGE_FDB:
        case NEIGHBOR_KIND_VXLAN_FDB:
                return NUD_PERMANENT | NUD_NOARP;

        default:
                assert_not_reached();
        }
}

static uint8_t neighbor_get_ndm_flags(Link *link, const Neighbor *neighbor) {
        assert(link);
        assert(neighbor);

        switch (neighbor->kind) {
        case NEIGHBOR_KIND_STATIC:
                return 0;

        case NEIGHBOR_KIND_PROXY:
                return NTF_PROXY;

        case NEIGHBOR_KIND_BRIDGE_FDB:
                return (streq_ptr(link->kind, "bridge") ? NTF_SELF : NTF_MASTER) | (neighbor->flags & NTF_USE);

        case NEIGHBOR_KIND_VXLAN_FDB:
                return NTF_SELF | (neighbor->flags & (NTF_USE | NTF_ROUTER));

        default:
                assert_not_reached();
        }
}

static int neighbor_configure(Neighbor *neighbor, Link *link, Request *req) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(neighbor);
        assert(link);
        assert(link->ifindex > 0);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(req);

        log_neighbor_debug(neighbor, "Configuring", link);

        r = sd_rtnl_message_new_neigh(link->manager->rtnl, &m, RTM_NEWNEIGH,
                                      link->ifindex, neighbor_get_ndm_family(neighbor));
        if (r < 0)
                return r;

        r = sd_rtnl_message_neigh_set_state(m, neighbor_get_ndm_state(neighbor));
        if (r < 0)
                return r;

        r = sd_rtnl_message_neigh_set_flags(m, neighbor_get_ndm_flags(link, neighbor));
        if (r < 0)
                return r;

        if (in_addr_is_set(neighbor->dst_addr.family, &neighbor->dst_addr.address)) {
                r = netlink_message_append_in_addr_union(m, NDA_DST, neighbor->dst_addr.family, &neighbor->dst_addr.address);
                if (r < 0)
                        return r;
        }

        if (neighbor->ll_addr.length > 0) {
                r = netlink_message_append_hw_addr(m, NDA_LLADDR, &neighbor->ll_addr);
                if (r < 0)
                        return r;
        }

        if (neighbor->vlan_id > 0) {
                r = sd_netlink_message_append_u32(m, NDA_VLAN, neighbor->vlan_id);
                if (r < 0)
                        return r;
        }

        if (neighbor->vni > 0) {
                r = sd_netlink_message_append_u32(m, NDA_VNI, neighbor->vni);
                if (r < 0)
                        return r;
        }

        if (neighbor->ifindex > 0) {
                r = sd_netlink_message_append_u32(m, NDA_IFINDEX, neighbor->ifindex);
                if (r < 0)
                        return r;
        }

        return request_call_netlink_async(link->manager->rtnl, m, req);
}

static bool neighbor_needs_adjust(const Neighbor *neighbor) {
        assert(neighbor);

        return neighbor->ifindex == 0 && !isempty(neighbor->ifname);
}

static int neighbor_adjust(Neighbor *neighbor, Manager *manager) {
        int r;

        assert(neighbor);
        assert(manager);

        Link *link;
        r = neighbor_get_link(manager, neighbor, &link);
        if (r < 0)
                return r;

        neighbor->ifindex = link->ifindex;
        neighbor->ifname = mfree(neighbor->ifname);
        return 0;
}

static int neighbor_is_ready_to_configure(const Neighbor *neighbor, Link *link) {
        assert(neighbor);
        assert(link);

        if (!link_is_ready_to_configure(link, /* allow_unmanaged= */ false))
                return false;

        Link *out;
        if (neighbor_get_link(link->manager, neighbor, &out) < 0)
                return false;
        if (out && !link_is_ready_to_configure(out, /* allow_unmanaged= */ true))
                return false;

        return true;
}

static int neighbor_requeue_request(Request *req, Link *link, Neighbor *neighbor) {
        int r;

        assert(req);
        assert(link);
        assert(link->manager);
        assert(neighbor);

        /* It is not possible to adjust the Neighbor object owned by Request, as it is used as a key to
         * manage Request objects in the queue. Hence, we need to re-request with the updated object. */

        if (!neighbor_needs_adjust(neighbor))
                return 0; /* The Neighbor object does not need the adjustment. Continue with it. */

        _cleanup_(neighbor_unrefp) Neighbor *tmp = NULL;
        r = neighbor_dup(neighbor, &tmp);
        if (r < 0)
                return r;

        r = neighbor_adjust(tmp, link->manager);
        if (r < 0)
                return r;

        /* Avoid the request to be freed by request_detach(). */
        _unused_ _cleanup_(request_unrefp) Request *req_unref = request_ref(req);

        /* First, detach the request from the queue, to make not the new request is deduped. */
        request_detach(req);

        /* Then, request with the adjusted Neighbor object. */
        r = link_requeue_request(link, req, tmp, /* ret= */ NULL);
        if (r < 0)
                return r;
        if (r == 0)
                /* Already queued?? That's OK. Maybe, [VXLANFDB] section is effectively duplicated. */
                return 1;

        TAKE_PTR(tmp);
        return 1; /* New request is queued. Finish to process the old request. */
}

static int neighbor_process_request(Request *req, Link *link, Neighbor *neighbor) {
        Neighbor *existing;
        int r;

        assert(req);
        assert(link);
        assert(neighbor);

        if (!neighbor_is_ready_to_configure(neighbor, link))
                return 0;

        r = neighbor_requeue_request(req, link, neighbor);
        if (r != 0)
                return r;

        r = neighbor_configure(neighbor, link, req);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure %s: %m", neighbor_kind_to_string(neighbor->kind));

        neighbor_enter_configuring(neighbor);
        if (neighbor_get(link, neighbor, &existing) >= 0)
                neighbor_enter_configuring(existing);

        return 1;
}

static int static_neighbor_configure_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, Neighbor *neighbor) {
        int r;

        assert(m);
        assert(link);

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Could not set %s", neighbor_kind_to_string(neighbor->kind));
                link_enter_failed(link);
                return 1;
        }

        if (link->static_neighbor_messages == 0) {
                log_link_debug(link, "Neighbors set");
                link->static_neighbors_configured = true;
                link_check_ready(link);
        }

        return 1;
}

static int link_request_neighbor(Link *link, const Neighbor *neighbor) {
        _cleanup_(neighbor_unrefp) Neighbor *tmp = NULL;
        Neighbor *existing = NULL;
        int r;

        assert(link);
        assert(neighbor);
        assert(neighbor->source != NETWORK_CONFIG_SOURCE_FOREIGN);

        if (neighbor->kind != NEIGHBOR_KIND_PROXY &&
            neighbor->ll_addr.length != link->hw_addr.length) {
                log_link_debug(link,
                               "The link layer address length (%zu) for %s %s does not match with "
                               "the hardware address length (%zu), ignoring the setting.",
                               neighbor->ll_addr.length,
                               neighbor_kind_to_string(neighbor->kind),
                               IN_ADDR_TO_STRING(neighbor->dst_addr.family, &neighbor->dst_addr.address),
                               link->hw_addr.length);
                return 0;
        }

        if (neighbor_get_request(link, neighbor, NULL) >= 0)
                return 0; /* already requested, skipping. */

        r = neighbor_dup(neighbor, &tmp);
        if (r < 0)
                return r;

        if (neighbor_get(link, neighbor, &existing) >= 0)
                /* Copy state for logging below. */
                tmp->state = existing->state;

        log_neighbor_debug(tmp, "Requesting", link);
        r = link_queue_request_safe(link, REQUEST_TYPE_NEIGHBOR,
                                    tmp,
                                    neighbor_unref,
                                    neighbor_hash_func,
                                    neighbor_compare_func,
                                    neighbor_process_request,
                                    &link->static_neighbor_messages,
                                    static_neighbor_configure_handler,
                                    NULL);
        if (r <= 0)
                return r;

        neighbor_enter_requesting(tmp);
        if (existing)
                neighbor_enter_requesting(existing);

        TAKE_PTR(tmp);
        return 1;
}

int link_request_static_neighbors(Link *link) {
        Neighbor *neighbor;
        int r;

        assert(link);
        assert(link->network);
        assert(link->state != _LINK_STATE_INVALID);

        link->static_neighbors_configured = false;

        ORDERED_HASHMAP_FOREACH(neighbor, link->network->neighbors_by_section) {
                r = link_request_neighbor(link, neighbor);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not request %s: %m", neighbor_kind_to_string(neighbor->kind));
        }

        struct in_addr_data *a;
        SET_FOREACH(a, link->network->proxy_neighbors) {
                Neighbor n = {
                        .source = NETWORK_CONFIG_SOURCE_STATIC,
                        .kind = NEIGHBOR_KIND_PROXY,
                        .dst_addr = *a,
                };

                r = link_request_neighbor(link, &n);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not request %s: %m", neighbor_kind_to_string(n.kind));
        }

        if (link->static_neighbor_messages == 0) {
                link->static_neighbors_configured = true;
                link_check_ready(link);
        } else {
                log_link_debug(link, "Requesting neighbors");
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

        return 0;
}

static int neighbor_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, RemoveRequest *rreq) {
        int r;

        assert(m);
        assert(rreq);

        Link *link = ASSERT_PTR(rreq->link);
        Neighbor *neighbor = ASSERT_PTR(rreq->userdata);

        if (link->state == LINK_STATE_LINGER)
                return 0;

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                /* Neighbor may not exist because it already got deleted, ignore that. */
                log_link_message_full_errno(link, m,
                                            (r == -ESRCH || !neighbor->link) ? LOG_DEBUG : LOG_WARNING,
                                            r, "Could not remove %s",
                                            neighbor_kind_to_string(neighbor->kind));

                /* If the neighbor cannot be removed, then assume the neighbor is already removed. */
                neighbor_forget(link, neighbor, "Forgetting");
        }

        return 1;
}

int neighbor_remove(Neighbor *neighbor, Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(neighbor);
        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);

        /* If the neighbor is remembered, then use the remembered object. */
        (void) neighbor_get(link, neighbor, &neighbor);

        log_neighbor_debug(neighbor, "Removing", link);

        r = sd_rtnl_message_new_neigh(link->manager->rtnl, &m, RTM_DELNEIGH,
                                      link->ifindex, neighbor_get_ndm_family(neighbor));
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate RTM_DELNEIGH message: %m");

        r = sd_rtnl_message_neigh_set_flags(m, neighbor_get_ndm_flags(link, neighbor));
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set neighbor flags: %m");

        switch (neighbor->kind) {
        case NEIGHBOR_KIND_STATIC:
        case NEIGHBOR_KIND_PROXY:
                r = netlink_message_append_in_addr_union(m, NDA_DST, neighbor->dst_addr.family, &neighbor->dst_addr.address);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append NDA_DST attribute: %m");
                break;

        case NEIGHBOR_KIND_BRIDGE_FDB:
                r = netlink_message_append_hw_addr(m, NDA_LLADDR, &neighbor->ll_addr);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append NDA_LLADDR attribute: %m");

                if (neighbor->vlan_id > 0) {
                        r = sd_netlink_message_append_u32(m, NDA_VLAN, neighbor->vlan_id);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Could not append NDA_VLAN attribute: %m");
                }
                break;

        case NEIGHBOR_KIND_VXLAN_FDB:
                r = netlink_message_append_hw_addr(m, NDA_LLADDR, &neighbor->ll_addr);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append NDA_LLADDR attribute: %m");

                if (neighbor->src_vni > 0) {
                        r = sd_netlink_message_append_u32(m, NDA_SRC_VNI, neighbor->src_vni);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Could not append NDA_SRC_VNI attribute: %m");
                }

                if (ether_addr_is_multicast(&neighbor->ll_addr.ether) ||
                    ether_addr_is_null(&neighbor->ll_addr.ether)) {
                        r = netlink_message_append_in_addr_union(m, NDA_DST, neighbor->dst_addr.family, &neighbor->dst_addr.address);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Could not append NDA_DST attribute: %m");

                        if (neighbor->port > 0) {
                                r = sd_netlink_message_append_u16(m, NDA_PORT, neighbor->port);
                                if (r < 0)
                                        return log_link_error_errno(link, r, "Could not append NDA_PORT attribute: %m");
                        }

                        if (neighbor->vni > 0) {
                                r = sd_netlink_message_append_u32(m, NDA_VNI, neighbor->vni);
                                if (r < 0)
                                        return log_link_error_errno(link, r, "Could not append NDA_VNI attribute: %m");
                        }

                        if (neighbor->ifindex > 0) {
                                r = sd_netlink_message_append_u32(m, NDA_IFINDEX, neighbor->ifindex);
                                if (r < 0)
                                        return log_link_error_errno(link, r, "Could not append NDA_IFINDEX attribute: %m");
                        }
                }
                break;

        default:
                assert_not_reached();
        }

        r = link_remove_request_add(link, neighbor, neighbor, link->manager->rtnl, m, neighbor_remove_handler);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not queue rtnetlink message: %m");

        neighbor_enter_removing(neighbor);
        return 0;
}

int link_drop_unmanaged_neighbors(Link *link) {
        Neighbor *neighbor;
        int r = 0;

        assert(link);
        assert(link->network);

        /* First, mark all neighbors. */
        SET_FOREACH(neighbor, link->neighbors) {
                /* Ignore neighbors not assigned yet or already removing. */
                if (!neighbor_exists(neighbor))
                        continue;

                /* Do not remove foreign vxlan FDB entries when the vxlan is in the external mode. */
                if (link->vxlan_is_external &&
                    neighbor->kind == NEIGHBOR_KIND_VXLAN_FDB &&
                    neighbor->source == NETWORK_CONFIG_SOURCE_FOREIGN)
                        continue;

                if (!link_should_mark_config(link, /* only_static= */ false, neighbor->source, RTPROT_STATIC))
                        continue;

                neighbor_mark(neighbor);
        }

        /* Next, unmark requested neighbors. They will be configured later. */
        ORDERED_HASHMAP_FOREACH(neighbor, link->network->neighbors_by_section) {
                _cleanup_(neighbor_unrefp) Neighbor *tmp = NULL;
                if (neighbor_needs_adjust(neighbor)) {
                        if (neighbor_get_link(link->manager, neighbor, /* ret= */ NULL) < 0)
                                continue;

                        r = neighbor_dup(neighbor, &tmp);
                        if (r < 0)
                                return r;

                        r = neighbor_adjust(tmp, link->manager);
                        if (r < 0)
                                return r;
                }

                Neighbor *existing;
                if (neighbor_get(link, tmp ?: neighbor, &existing) >= 0)
                        neighbor_unmark(existing);
        }

        struct in_addr_data *a;
        SET_FOREACH(a, link->network->proxy_neighbors) {
                Neighbor n = {
                        .kind = NEIGHBOR_KIND_PROXY,
                        .dst_addr = *a,
                };

                Neighbor *existing;
                if (neighbor_get(link, &n, &existing) >= 0)
                        neighbor_unmark(existing);
        }

        /* Finally, remove all marked neighbors. */
        SET_FOREACH(neighbor, link->neighbors) {
                if (!neighbor_is_marked(neighbor))
                        continue;

                RET_GATHER(r, neighbor_remove(neighbor, link));
        }

        return r;
}

int link_drop_static_neighbors(Link *link) {
        Neighbor *neighbor;
        int r = 0;

        assert(link);

        SET_FOREACH(neighbor, link->neighbors) {
                /* Do not touch nexthops managed by kernel or other tools. */
                if (neighbor->source != NETWORK_CONFIG_SOURCE_STATIC)
                        continue;

                /* Ignore neighbors not assigned yet or already removing. */
                if (!neighbor_exists(neighbor))
                        continue;

                RET_GATHER(r, neighbor_remove(neighbor, link));
        }

        return r;
}

static int neighbor_kind_get(Link *link, sd_netlink_message *message, NeighborKind *ret) {
        int r;

        assert(link);
        assert(message);
        assert(ret);

        int family;
        r = sd_rtnl_message_neigh_get_family(message, &family);
        if (r < 0)
                return r;
        if (IN_SET(family, AF_INET, AF_INET6)) {
                uint8_t flags;

                r = sd_rtnl_message_neigh_get_flags(message, &flags);
                if (r < 0)
                        return r;

                if (FLAGS_SET(flags, NTF_PROXY))
                        *ret = NEIGHBOR_KIND_PROXY;
                else
                        *ret = NEIGHBOR_KIND_STATIC;
                return 0;
        }

        if (family == AF_BRIDGE) {
                r = sd_netlink_message_read_u32(message, NDA_MASTER, /* ret= */ NULL);
                if (r >= 0) {
                        *ret = NEIGHBOR_KIND_BRIDGE_FDB;
                        return 0;
                }
                if (r != -ENODATA)
                        return r;

                if (streq_ptr(link->kind, "vxlan")) {
                        *ret = NEIGHBOR_KIND_VXLAN_FDB;
                        return 0;
                }
        }

        return -EOPNOTSUPP;
}

int manager_rtnl_process_neighbor(sd_netlink *rtnl, sd_netlink_message *message, Manager *m) {
        int r;

        assert(rtnl);
        assert(message);
        assert(m);

        if (sd_netlink_message_is_error(message)) {
                r = sd_netlink_message_get_errno(message);
                if (r < 0)
                        log_message_warning_errno(message, r, "rtnl: failed to receive neighbor message, ignoring");

                return 0;
        }

        uint16_t type;
        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get message type, ignoring: %m");
                return 0;
        } else if (!IN_SET(type, RTM_NEWNEIGH, RTM_DELNEIGH)) {
                log_warning("rtnl: received unexpected message type %u when processing neighbor, ignoring.", type);
                return 0;
        }

        uint16_t state;
        r = sd_rtnl_message_neigh_get_state(message, &state);
        if (r < 0) {
                log_warning_errno(r, "rtnl: received neighbor message with invalid state, ignoring: %m");
                return 0;
        } else if (!FLAGS_SET(state, NUD_PERMANENT))
                /* Currently, we are interested in only static neighbors. */
                return 0;

        int ifindex;
        r = sd_rtnl_message_neigh_get_ifindex(message, &ifindex);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get ifindex from message, ignoring: %m");
                return 0;
        } else if (ifindex <= 0) {
                log_warning("rtnl: received neighbor message with invalid ifindex %d, ignoring.", ifindex);
                return 0;
        }

        Link *link;
        r = link_get_by_index(m, ifindex, &link);
        if (r < 0)
                /* when enumerating we might be out of sync, but we will get the neighbor again. Also,
                 * kernel sends messages about neighbors after a link is removed. So, just ignore it. */
                return 0;

        NeighborKind kind;
        if (neighbor_kind_get(link, message, &kind) < 0)
                return 0;

        _cleanup_(neighbor_unrefp) Neighbor *tmp = NULL;
        r = neighbor_new(kind, &tmp);
        if (r < 0)
                return log_oom();

        /* First, retrieve the fundamental information about the neighbor. */
        switch (kind) {
        case NEIGHBOR_KIND_STATIC:
        case NEIGHBOR_KIND_PROXY:
                r = sd_rtnl_message_neigh_get_family(message, &tmp->dst_addr.family);
                if (r < 0) {
                        log_link_warning(link, "rtnl: received neighbor message without family, ignoring.");
                        return 0;
                }

                r = netlink_message_read_in_addr_union(message, NDA_DST, tmp->dst_addr.family, &tmp->dst_addr.address);
                if (r < 0) {
                        log_link_warning_errno(link, r, "rtnl: received neighbor message without valid address, ignoring: %m");
                        return 0;
                }
                break;

        case NEIGHBOR_KIND_BRIDGE_FDB:
                r = sd_netlink_message_read_ether_addr(message, NDA_LLADDR, &tmp->ll_addr.ether);
                if (r < 0) {
                        log_link_warning_errno(link, r, "rtnl: received neighbor message without valid link layer address, ignoring: %m");
                        return 0;
                }
                tmp->ll_addr.length = ETH_ALEN;

                r = sd_netlink_message_read_u16(message, NDA_VLAN, &tmp->vlan_id);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received neighbor message without valid vlan ID, ignoring: %m");
                        return 0;
                }
                break;

        case NEIGHBOR_KIND_VXLAN_FDB: {
                r = sd_netlink_message_read_ether_addr(message, NDA_LLADDR, &tmp->ll_addr.ether);
                if (r < 0) {
                        log_link_warning_errno(link, r, "rtnl: received neighbor message without valid link layer address, ignoring: %m");
                        return 0;
                }
                tmp->ll_addr.length = ETH_ALEN;

                /* No NDA_SRC_VNI means the interface uses the default VNI. */
                r = sd_netlink_message_read_u32(message, NDA_SRC_VNI, &tmp->src_vni);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received neighbor message without valid source VNI, ignoring: %m");
                        return 0;
                }

                r = netlink_message_read_in_addr_union_auto(message, NDA_DST, &tmp->dst_addr.family, &tmp->dst_addr.address);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received neighbor message without valid address, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_read_u16(message, NDA_PORT, &tmp->port);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received neighbor message without valid port, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_read_u32(message, NDA_VNI, &tmp->vni);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received neighbor message without valid VNI, ignoring: %m");
                        return 0;
                }

                uint32_t u;
                r = sd_netlink_message_read_u32(message, NDA_IFINDEX, &u);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received neighbor message without valid ifindex, ignoring: %m");
                        return 0;
                }
                tmp->ifindex = u;
                break;
        }
        default:
                assert_not_reached();
        }

        /* Then, find the managed Neighbor object corresponding to the netlink notification. */
        Neighbor *neighbor = NULL;
        (void) neighbor_get(link, tmp, &neighbor);

        if (type == RTM_DELNEIGH) {
                if (neighbor)
                        neighbor_forget(link, neighbor, "Forgetting removed");
                else
                        log_neighbor_debug(tmp, "Kernel removed unknown", link);
                return 0;
        }

        /* If we did not know the neighbor, then save it. */
        bool is_new = false;
        if (!neighbor) {
                r = neighbor_attach(link, tmp);
                if (r < 0) {
                        log_link_warning_errno(link, r, "Failed to save received %s, ignoring: %m", neighbor_kind_to_string(tmp->kind));
                        return 0;
                }
                neighbor = tmp;
                is_new = true;
        }

        /* Also update information that cannot be obtained through netlink notification. */
        Request *req = NULL;
        (void) neighbor_get_request(link, tmp, &req);
        if (req && req->waiting_reply) {
                Neighbor *n = ASSERT_PTR(req->userdata);

                neighbor->source = n->source;
        }

        /* Then, update miscellaneous info. */
        switch (kind) {
        case NEIGHBOR_KIND_STATIC:
                r = netlink_message_read_hw_addr(message, NDA_LLADDR, &neighbor->ll_addr);
                if (r < 0 && r != -ENODATA)
                        log_link_debug_errno(link, r, "rtnl: received neighbor message without valid link layer address, ignoring: %m");
                break;

        case NEIGHBOR_KIND_PROXY:
        case NEIGHBOR_KIND_BRIDGE_FDB:
        case NEIGHBOR_KIND_VXLAN_FDB:
                break;

        default:
                assert_not_reached();
        }

        neighbor_enter_configured(neighbor);
        if (req)
                neighbor_enter_configured(req->userdata);

        log_neighbor_debug(neighbor, is_new ? "Remembering" : "Received remembered", link);
        return 1;
}

#define log_neighbor_section(neighbor, fmt, ...)                        \
        ({                                                              \
                const Neighbor *_neighbor = (neighbor);                 \
                log_section_warning_errno(                              \
                                _neighbor ? _neighbor->section : NULL,  \
                                SYNTHETIC_ERRNO(EINVAL),                \
                                fmt " Ignoring [Neighbor] section.",    \
                                ##__VA_ARGS__);                         \
        })

#define log_bridge_fdb_section(neighbor, fmt, ...)                      \
        ({                                                              \
                const Neighbor *_neighbor = (neighbor);                 \
                log_section_warning_errno(                              \
                                _neighbor ? _neighbor->section : NULL,  \
                                SYNTHETIC_ERRNO(EINVAL),                \
                                fmt " Ignoring [BridgeFDB] section.",   \
                                ##__VA_ARGS__);                         \
        })

#define log_vxlan_fdb_section(neighbor, fmt, ...)                       \
        ({                                                              \
                const Neighbor *_neighbor = (neighbor);                 \
                log_section_warning_errno(                              \
                                _neighbor ? _neighbor->section : NULL,  \
                                SYNTHETIC_ERRNO(EINVAL),                \
                                fmt " Ignoring [VXLANFDB] section.",   \
                                ##__VA_ARGS__);                         \
        })

static int neighbor_section_verify(Neighbor *neighbor) {
        assert(neighbor);

        if (section_is_invalid(neighbor->section))
                return -EINVAL;

        switch (neighbor->kind) {
        case NEIGHBOR_KIND_STATIC:
                if (neighbor->dst_addr.family == AF_UNSPEC)
                        return log_neighbor_section(neighbor, "Neighbor section without Address= configured.");

                if (neighbor->dst_addr.family == AF_INET6 && !socket_ipv6_is_supported())
                        return log_neighbor_section(neighbor, "Neighbor section with an IPv6 destination address configured, but the kernel does not support IPv6.");
                break;

        case NEIGHBOR_KIND_BRIDGE_FDB:
                /* Previously, we allowed to configure both bridge FDB and vxlan FDB by [bridgeFDB] section.
                 * vlan_id is for bridge FDB, but dst_addr, vni, and ifindex/ifname are for vxlan FDB. */
                if (in_addr_is_set(neighbor->dst_addr.family, &neighbor->dst_addr.address) ||
                    neighbor->vni > 0 ||
                    neighbor->ifname ||
                    neighbor->ifindex > 0) {

                        if (neighbor->vlan_id > 0)
                                return log_bridge_fdb_section(neighbor, "BridgeFDB section contains settings for vxlan FDB.");

                        /* Assume this is a vxlan FDB entry. */
                        neighbor->kind = NEIGHBOR_KIND_VXLAN_FDB;
                        goto vxlan_fdb;
                }

                if (neighbor->ll_addr.length != ETH_ALEN)
                        return log_bridge_fdb_section(neighbor, "BridgeFDB section without MACAddress= configured.");
                break;

        case NEIGHBOR_KIND_VXLAN_FDB:
        vxlan_fdb:
                /* When MAC address is unspecified, assume NULL MAC address. */
                if (neighbor->ll_addr.length == 0)
                        neighbor->ll_addr = (struct hw_addr_data) {
                                .length = ETH_ALEN,
                        };

                if (!in_addr_is_set(neighbor->dst_addr.family, &neighbor->dst_addr.address))
                        return log_vxlan_fdb_section(neighbor, "VXLANFDB section without Destination= configured.");

                if (neighbor->vni > VXLAN_VID_MAX)
                        return log_vxlan_fdb_section(neighbor, "VXLANFDB section has VNI > %"PRIu32".", neighbor->vni);
                break;

        default:
                assert_not_reached();
        }

        return 0;
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        trivial_hash_ops_neighbor_detach,
        void,
        trivial_hash_func,
        trivial_compare_func,
        Neighbor,
        neighbor_detach);

int network_drop_invalid_neighbors(Network *network) {
        _cleanup_set_free_ Set *neighbors = NULL, *duplicated_neighbors = NULL;
        Neighbor *neighbor;
        int r;

        assert(network);

        ORDERED_HASHMAP_FOREACH(neighbor, network->neighbors_by_section) {
                Neighbor *dup;

                if (neighbor_section_verify(neighbor) < 0) {
                        /* Drop invalid [Neighbor] sections. Note that neighbor_detach() will drop the
                         * neighbor from neighbors_by_section. */
                        neighbor_detach(neighbor);
                        continue;
                }

                /* Always use the setting specified later. So, remove the previously assigned setting. */
                dup = set_remove(neighbors, neighbor);
                if (dup) {
                        log_warning("%s: Duplicated neighbor settings for %s is specified at line %u and %u, "
                                    "dropping the neighbor setting specified at line %u.",
                                    dup->section->filename,
                                    IN_ADDR_TO_STRING(neighbor->dst_addr.family, &neighbor->dst_addr.address),
                                    neighbor->section->line,
                                    dup->section->line, dup->section->line);

                        /* Do not call nexthop_detach() for 'dup' now, as we can remove only the current
                         * entry in the loop. We will drop the nexthop from nexthops_by_section later. */
                        r = set_ensure_put(&duplicated_neighbors, &trivial_hash_ops_neighbor_detach, dup);
                        if (r < 0)
                                return log_oom();
                        assert(r > 0);
                }

                /* Use neighbor_hash_ops, instead of neighbor_hash_ops_detach. Otherwise, the Neighbor objects
                 * will be detached. */
                r = set_ensure_put(&neighbors, &neighbor_hash_ops, neighbor);
                if (r < 0)
                        return log_oom();
                assert(r > 0);
        }

        struct in_addr_data *a;
        SET_FOREACH(a, network->proxy_neighbors) {
                switch (a->family) {
                case AF_INET:
                        /* IPv4 proxy ARP entry does NOT require that proxy_arp sysctl is enabled.
                         * When an IPv4 proxy ARP entry is specified, enable IPv4ProxyARP= if unspecified. */
                        if (network->proxy_arp < 0)
                                network->proxy_arp = true;
                        break;

                case AF_INET6:
                        if (!socket_ipv6_is_supported()) {
                                log_warning("%s: Specified IPv6 proxy NDP address %s, but IPv6 is not supported by kernel, ignoring.",
                                            network->filename, IN_ADDR_TO_STRING(a->family, &a->address));
                                free(set_remove(network->proxy_neighbors, a));
                                continue;
                        }

                        if (network->ipv6_proxy_ndp == 0) {
                                log_warning("%s: Specified IPv6 proxy NDP address %s, but IPv6ProxyNDP= is disabled, ignoring.",
                                            network->filename, IN_ADDR_TO_STRING(a->family, &a->address));
                                free(set_remove(network->proxy_neighbors, a));
                                continue;
                        }

                        /* IPv6 proxy NDP entry requires that proxy_ndp sysctl is enabled. */
                        network->ipv6_proxy_ndp = true;
                        break;

                default:
                        assert_not_reached();
                }
        }

        return 0;
}

int config_parse_neighbor_section(
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

        static const ConfigSectionParser table[_NEIGHBOR_CONF_PARSER_MAX] = {
                [NEIGHBOR_DESTINATION_ADDRESS] = { .parser = config_parse_in_addr_data, .ltype = 0, .offset = offsetof(Neighbor, dst_addr), },
                [NEIGHBOR_LINK_LAYER_ADDRESS]  = { .parser = config_parse_hw_addr,      .ltype = 0, .offset = offsetof(Neighbor, ll_addr),  },
        };

        _cleanup_(neighbor_unref_or_set_invalidp) Neighbor *neighbor = NULL;
        Network *network = ASSERT_PTR(userdata);
        int r;

        assert(filename);

        r = neighbor_new_static(network, filename, section_line, NEIGHBOR_KIND_STATIC, &neighbor);
        if (r < 0)
                return log_oom();

        r = config_section_parse(table, ELEMENTSOF(table),
                                 unit, filename, line, section, section_line, lvalue, ltype, rvalue, neighbor);
        if (r <= 0) /* 0 means non-critical error, but the section will be ignored. */
                return r;

        TAKE_PTR(neighbor);
        return 0;
}

int config_parse_proxy_neighbor(
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

        Network *network = ASSERT_PTR(userdata);
        int r;

        assert(filename);
        assert(rvalue);

        if (isempty(rvalue)) {
                network->proxy_neighbors = set_free(network->proxy_neighbors);
                return 0;
        }

        struct in_addr_data a;
        r = in_addr_from_string_auto(rvalue, &a.family, &a.address);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse proxy ARP/NDP address, ignoring: %s", rvalue);
                return 0;
        }

        if (in_addr_is_null(a.family, &a.address)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Proxy ARP/NDP address cannot be the ANY address, ignoring: %s", rvalue);
                return 0;
        }

        _cleanup_free_ struct in_addr_data *copy = newdup(struct in_addr_data, &a, 1);
        if (!copy)
                return log_oom();

        r = set_ensure_consume(&network->proxy_neighbors, &in_addr_data_hash_ops_free, TAKE_PTR(copy));
        if (r < 0)
                return log_oom();

        return 0;
}

static int config_parse_fdb_flags(
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

        uint8_t *flags = ASSERT_PTR(data);

        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *flags = 0;
                return 1;
        }

        if (streq(rvalue, "use")) {
                *flags |= NTF_USE;
                return 1;
        }

        if (streq(rvalue, "router")) {
                *flags |= NTF_ROUTER;
                return 1;
        }

        /* Deprecated. Silently ignored. */
        if (STR_IN_SET(rvalue, "self", "master"))
                return 1;

        return log_syntax_parse_error(unit, filename, line, 0, lvalue, rvalue);
}

static int config_parse_fdb_interface(
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

        Neighbor *neighbor = ASSERT_PTR(userdata);
        int r;

        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                neighbor->ifname = mfree(neighbor->ifname);
                neighbor->ifindex = 0;
                return 1;
        }

        r = parse_ifindex(rvalue);
        if (r > 0) {
                neighbor->ifname = mfree(neighbor->ifname);
                neighbor->ifindex = r;
                return 1;
        }

        if (!ifname_valid_full(rvalue, IFNAME_VALID_ALTERNATIVE)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid interface name in %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        r = free_and_strdup(&neighbor->ifname, rvalue);
        if (r < 0)
                return log_oom();

        neighbor->ifindex = 0;
        return 1;
}

int config_parse_bridge_fdb_section(
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

        static const ConfigSectionParser table[_FDB_CONF_PARSER_MAX] = {
                [FDB_MAC_ADDRESS] = { .parser = config_parse_hw_addr,       .ltype = ETH_ALEN, .offset = offsetof(Neighbor, ll_addr),  },
                [FDB_FLAGS]       = { .parser = config_parse_fdb_flags,     .ltype = 0,        .offset = offsetof(Neighbor, flags),    },
                [FDB_VLAN_ID]     = { .parser = config_parse_vlanid,        .ltype = 0,        .offset = offsetof(Neighbor, vlan_id),  },
                /* for vxlan FDB, but for backward compatibility */
                [FDB_DESTINATION] = { .parser = config_parse_in_addr_data,  .ltype = 0,        .offset = offsetof(Neighbor, dst_addr), },
                [FDB_VNI]         = { .parser = config_parse_uint32,        .ltype = 0,        .offset = offsetof(Neighbor, vni),      },
                [FDB_INTERFACE]   = { .parser = config_parse_fdb_interface, .ltype = 0,        .offset = 0,                            },
        };

        _cleanup_(neighbor_unref_or_set_invalidp) Neighbor *neighbor = NULL;
        Network *network = ASSERT_PTR(userdata);
        int r;

        assert(filename);

        r = neighbor_new_static(network, filename, section_line, NEIGHBOR_KIND_BRIDGE_FDB, &neighbor);
        if (r < 0)
                return log_oom();

        r = config_section_parse(table, ELEMENTSOF(table),
                                 unit, filename, line, section, section_line, lvalue, ltype, rvalue, neighbor);
        if (r <= 0) /* 0 means non-critical error, but the section will be ignored. */
                return r;

        TAKE_PTR(neighbor);
        return 0;
}

int config_parse_vxlan_fdb_section(
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

        static const ConfigSectionParser table[_FDB_CONF_PARSER_MAX] = {
                [FDB_MAC_ADDRESS] = { .parser = config_parse_hw_addr,       .ltype = ETH_ALEN, .offset = offsetof(Neighbor, ll_addr),  },
                [FDB_FLAGS]       = { .parser = config_parse_fdb_flags,     .ltype = 0,        .offset = offsetof(Neighbor, flags),    },
                [FDB_DESTINATION] = { .parser = config_parse_in_addr_data,  .ltype = 0,        .offset = offsetof(Neighbor, dst_addr), },
                [FDB_VNI]         = { .parser = config_parse_uint32,        .ltype = 0,        .offset = offsetof(Neighbor, vni),      },
                [FDB_INTERFACE]   = { .parser = config_parse_fdb_interface, .ltype = 0,        .offset = 0,                            },
        };

        _cleanup_(neighbor_unref_or_set_invalidp) Neighbor *neighbor = NULL;
        Network *network = ASSERT_PTR(userdata);
        int r;

        assert(filename);

        r = neighbor_new_static(network, filename, section_line, NEIGHBOR_KIND_VXLAN_FDB, &neighbor);
        if (r < 0)
                return log_oom();

        r = config_section_parse(table, ELEMENTSOF(table),
                                 unit, filename, line, section, section_line, lvalue, ltype, rvalue, neighbor);
        if (r <= 0) /* 0 means non-critical error, but the section will be ignored. */
                return r;

        TAKE_PTR(neighbor);
        return 0;
}
