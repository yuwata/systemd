/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/icmp6.h>

#include "dns-domain.h"
#include "ether-addr-util.h"
#include "hostname-util.h"
#include "in-addr-util.h"
#include "missing_network.h"
#include "ndisc-protocol.h"
#include "network-common.h"
#include "strv.h"
#include "unaligned.h"

/* RFC does not say anything about the maximum number of options, but let's limit the number of options for
 * safety. Typically, the number of options in an ICMPv6 message should be only a few. */
#define MAX_OPTIONS 128

int ndisc_option_parse(
                ICMP6Packet *p,
                size_t offset,
                uint8_t *ret_type,
                size_t *ret_len,
                const uint8_t **ret_opt) {

        assert(p);

        if (offset == p->raw_size)
                return -ESPIPE; /* end of the packet */

        if (offset > p->raw_size)
                return -EBADMSG;

        if (p->raw_size - offset < sizeof(struct nd_opt_hdr))
                return -EBADMSG;

        assert_cc(alignof(struct nd_opt_hdr) == 1);
        const struct nd_opt_hdr *hdr = (const struct nd_opt_hdr*) (p->raw_packet + offset);
        if (hdr->nd_opt_len == 0)
                return -EBADMSG;

        size_t len = hdr->nd_opt_len * 8;
        if (p->raw_size - offset < len)
                return -EBADMSG;

        if (ret_type)
                *ret_type = hdr->nd_opt_type;
        if (ret_len)
                *ret_len = len;
        if (ret_opt)
                *ret_opt = p->raw_packet + offset;

        return 0;
}

static sd_ndisc_option* ndisc_option_new(uint8_t type, size_t offset) {
        sd_ndisc_option *p = new0(sd_ndisc_option, 1); /* use new0() here to make the fuzzers silent. */
        if (!p)
                return NULL;

        /* As the same reason in the above, do not use the structured initializer here. */
        p->type = type;
        p->offset = offset;

        return p;
}

static void ndisc_rdnss_done(sd_ndisc_rdnss *rdnss) {
        if (!rdnss)
                return;

        free(rdnss->addresses);
}

static void ndisc_dnssl_done(sd_ndisc_dnssl *dnssl) {
        if (!dnssl)
                return;

        strv_free(dnssl->domains);
}

static sd_ndisc_option* ndisc_option_free(sd_ndisc_option *option) {
        if (!option)
                return NULL;

        switch (option->type) {
        case SD_NDISC_OPTION_RDNSS:
                ndisc_rdnss_done(&option->rdnss);
                break;

        case SD_NDISC_OPTION_DNSSL:
                ndisc_dnssl_done(&option->dnssl);
                break;

        case SD_NDISC_OPTION_CAPTIVE_PORTAL:
                free(option->captive_portal);
                break;
        }

        return mfree(option);
}

static int ndisc_option_compare_func(const sd_ndisc_option *x, const sd_ndisc_option *y) {
        int r;

        assert(x);
        assert(y);

        r = CMP(x->type, y->type);
        if (r != 0)
                return r;

        switch (x->type) {
        case SD_NDISC_OPTION_SOURCE_LL_ADDRESS:
        case SD_NDISC_OPTION_TARGET_LL_ADDRESS:
        case SD_NDISC_OPTION_REDIRECTED_HEADER:
        case SD_NDISC_OPTION_MTU:
        case SD_NDISC_OPTION_FLAGS_EXTENSION:
        case SD_NDISC_OPTION_CAPTIVE_PORTAL:
                /* These options cannot be specified multiple times. */
                return 0;

        case SD_NDISC_OPTION_PREFIX_INFORMATION:
                /* Should not specify the same prefix multiple times. */
                r = CMP(x->prefix.prefixlen, y->prefix.prefixlen);
                if (r != 0)
                        return r;

                return memcmp(&x->prefix.address, &y->prefix.address, sizeof(struct in6_addr));

        case SD_NDISC_OPTION_ROUTE_INFORMATION:
                r = CMP(x->route.prefixlen, y->route.prefixlen);
                if (r != 0)
                        return r;

                return memcmp(&x->route.address, &y->route.address, sizeof(struct in6_addr));

        case SD_NDISC_OPTION_PREF64:
                r = CMP(x->prefix64.prefixlen, y->prefix64.prefixlen);
                if (r != 0)
                        return r;

                return memcmp(&x->prefix64.prefix, &y->prefix64.prefix, sizeof(struct in6_addr));

        default:
                /* DNSSL, RDNSS, and other unsupported options can be specified multiple times. */
                return CMP(x->offset, y->offset);
        }
}

static void ndisc_option_hash_func(const sd_ndisc_option *option, struct siphash *state) {
        assert(option);
        assert(state);

        siphash24_compress_typesafe(option->type, state);

        switch (option->type) {
        case SD_NDISC_OPTION_SOURCE_LL_ADDRESS:
        case SD_NDISC_OPTION_TARGET_LL_ADDRESS:
        case SD_NDISC_OPTION_REDIRECTED_HEADER:
        case SD_NDISC_OPTION_MTU:
        case SD_NDISC_OPTION_FLAGS_EXTENSION:
        case SD_NDISC_OPTION_CAPTIVE_PORTAL:
                break;

        case SD_NDISC_OPTION_PREFIX_INFORMATION:
                siphash24_compress_typesafe(option->prefix.prefixlen, state);
                siphash24_compress_typesafe(option->prefix.address, state);
                break;

        case SD_NDISC_OPTION_ROUTE_INFORMATION:
                siphash24_compress_typesafe(option->route.prefixlen, state);
                siphash24_compress_typesafe(option->route.address, state);
                break;

        case SD_NDISC_OPTION_PREF64:
                siphash24_compress_typesafe(option->prefix64.prefixlen, state);
                siphash24_compress_typesafe(option->prefix64.prefix, state);
                break;

        default:
                siphash24_compress_typesafe(option->offset, state);
        }
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                ndisc_option_hash_ops,
                sd_ndisc_option,
                ndisc_option_hash_func,
                ndisc_option_compare_func,
                ndisc_option_free);

static int ndisc_option_consume(Set **options, sd_ndisc_option *p) {
        if (set_size(*options) >= MAX_OPTIONS) {
                ndisc_option_free(p);
                return -ETOOMANYREFS; /* recognizable error code */
        }

        return set_ensure_consume(options, &ndisc_option_hash_ops, p);
}

static int ndisc_option_parse_link_layer_address(size_t offset, size_t len, const uint8_t *opt, Set **options) {
        assert(opt);
        assert(options);

        if (len != sizeof(struct ether_addr) + 2)
                return -EBADMSG;

        if (!IN_SET(opt[0], SD_NDISC_OPTION_SOURCE_LL_ADDRESS, SD_NDISC_OPTION_TARGET_LL_ADDRESS))
                return -EBADMSG;

        struct ether_addr mac;
        memcpy(&mac, opt + 2, sizeof(struct ether_addr));

        if (ether_addr_is_null(&mac))
                return -EBADMSG;

        sd_ndisc_option *p = ndisc_option_new(opt[0], offset);
        if (!p)
                return -ENOMEM;

        p->mac = mac;

        return set_ensure_consume(options, &ndisc_option_hash_ops, p);
}

static int ndisc_option_parse_prefix(size_t offset, size_t len, const uint8_t *opt, Set **options) {
        const struct nd_opt_prefix_info *pi = (const struct nd_opt_prefix_info*) ASSERT_PTR(opt);

        assert(options);

        if (len != sizeof(struct nd_opt_prefix_info))
                return -EBADMSG;

        if (pi->nd_opt_pi_type != SD_NDISC_OPTION_PREFIX_INFORMATION)
                return -EBADMSG;

        if (pi->nd_opt_pi_prefix_len > 128)
                return -EBADMSG;

        if (in6_addr_is_link_local(&pi->nd_opt_pi_prefix))
                return -EBADMSG;

        usec_t valid = be32_sec_to_usec(pi->nd_opt_pi_valid_time, /* max_as_infinity = */ true);
        usec_t pref = be32_sec_to_usec(pi->nd_opt_pi_preferred_time, /* max_as_infinity = */ true);
        if (pref > valid)
                return -EBADMSG;

        /* We only support 64 bits interface identifier for addrconf. */
        uint8_t flags = pi->nd_opt_pi_flags_reserved;
        if (FLAGS_SET(flags, ND_OPT_PI_FLAG_AUTO) && pi->nd_opt_pi_prefix_len != 64)
                flags &= ~ND_OPT_PI_FLAG_AUTO;

        sd_ndisc_option *p = ndisc_option_new(SD_NDISC_OPTION_PREFIX_INFORMATION, offset);
        if (!p)
                return -ENOMEM;

        p->prefix = (sd_ndisc_prefix) {
                .flags = flags,
                .prefixlen = pi->nd_opt_pi_prefix_len,
                .address = pi->nd_opt_pi_prefix,
                .valid_lifetime = valid,
                .preferred_lifetime = pref,
        };

        return ndisc_option_consume(options, p);
}

static int ndisc_option_parse_redirected_header(size_t offset, size_t len, const uint8_t *opt, Set **options) {
        assert(opt);
        assert(options);

        if (len < sizeof(struct nd_opt_rd_hdr) + sizeof(struct ip6_hdr))
                return -EBADMSG;

        if (opt[0] != SD_NDISC_OPTION_REDIRECTED_HEADER)
                return -EBADMSG;

        sd_ndisc_option *p = ndisc_option_new(SD_NDISC_OPTION_REDIRECTED_HEADER, offset);
        if (!p)
                return -ENOMEM;

        /* For safety, here we copy only IPv6 header. */
        memcpy(&p->hdr, opt + sizeof(struct nd_opt_rd_hdr), sizeof(struct ip6_hdr));

        return ndisc_option_consume(options, p);
}

static int ndisc_option_parse_mtu(size_t offset, size_t len, const uint8_t *opt, Set **options) {
        const struct nd_opt_mtu *pm = (const struct nd_opt_mtu*) ASSERT_PTR(opt);

        assert(options);

        if (len != sizeof(struct nd_opt_mtu))
                return -EBADMSG;

        if (pm->nd_opt_mtu_type != SD_NDISC_OPTION_MTU)
                return -EBADMSG;

        uint32_t mtu = be32toh(pm->nd_opt_mtu_mtu);
        if (mtu < IPV6_MIN_MTU) /* ignore invalidly small MTUs */
                return -EINVAL;

        sd_ndisc_option *p = ndisc_option_new(SD_NDISC_OPTION_MTU, offset);
        if (!p)
                return -ENOMEM;

        p->mtu = mtu;

        return ndisc_option_consume(options, p);
}

static int ndisc_option_parse_route(size_t offset, size_t len, const uint8_t *opt, Set **options) {
        assert(opt);
        assert(options);

        if (!IN_SET(len, 1*8, 2*8, 3*8))
                return -EBADMSG;

        if (opt[0] != SD_NDISC_OPTION_ROUTE_INFORMATION)
                return -EBADMSG;

        uint8_t prefixlen = opt[2];
        if (prefixlen > 128)
                return -EBADMSG;

        if (len < (size_t) (DIV_ROUND_UP(prefixlen, 64) + 1) * 8)
                return -EBADMSG;

        /* RFC 4191 section 2.3
         * Prf (Route Preference)
         * 2-bit signed integer. The Route Preference indicates whether to prefer the router associated with
         * this prefix over others, when multiple identical prefixes (for different routers) have been
         * received. If the Reserved (10) value is received, the Route Information Option MUST be ignored. */
        uint8_t preference = (opt[3] >> 3) & 0x03;
        if (preference == SD_NDISC_PREFERENCE_RESERVED)
                return -EBADMSG;

        usec_t lifetime = unaligned_be32_sec_to_usec(opt + 4, /* max_as_infinity = */ true);

        struct in6_addr prefix;
        memcpy(&prefix, opt + 8, len - 8);
        in6_addr_mask(&prefix, prefixlen);

        sd_ndisc_option *p = ndisc_option_new(SD_NDISC_OPTION_ROUTE_INFORMATION, offset);
        if (!p)
                return -ENOMEM;

        p->route = (sd_ndisc_route) {
                .preference = preference,
                .prefixlen = prefixlen,
                .address = prefix,
                .lifetime = lifetime,
        };

        return ndisc_option_consume(options, p);
}

static int ndisc_option_parse_rdnss(size_t offset, size_t len, const uint8_t *opt, Set **options) {
        assert(opt);
        assert(options);

        if (len < 8 + sizeof(struct in6_addr) || (len % sizeof(struct in6_addr)) != 8)
                return -EBADMSG;

        if (opt[0] != SD_NDISC_OPTION_RDNSS)
                return -EBADMSG;

        usec_t lifetime = unaligned_be32_sec_to_usec(opt + 4, /* max_as_infinity = */ true);

        size_t n_addrs = len / sizeof(struct in6_addr);
        _cleanup_free_ struct in6_addr *addrs = newdup(struct in6_addr, opt + 8, n_addrs);
        if (!addrs)
                return -ENOMEM;

        sd_ndisc_option *p = ndisc_option_new(SD_NDISC_OPTION_RDNSS, offset);
        if (!p)
                return -ENOMEM;

        p->rdnss = (sd_ndisc_rdnss) {
                .n_addresses = n_addrs,
                .addresses = TAKE_PTR(addrs),
                .lifetime = lifetime,
        };

        return ndisc_option_consume(options, p);
}

static int ndisc_option_parse_flags_extension(size_t offset, size_t len, const uint8_t *opt, Set **options) {
        assert(opt);
        assert(options);

        if (len != 8)
                return -EBADMSG;

        if (opt[0] != SD_NDISC_OPTION_FLAGS_EXTENSION)
                return -EBADMSG;

        sd_ndisc_option *p = ndisc_option_new(SD_NDISC_OPTION_FLAGS_EXTENSION, offset);
        if (!p)
                return -ENOMEM;

        p->extended_flags = (unaligned_read_be64(opt) & 0xffffffffffff0000) >> 8;

        return ndisc_option_consume(options, p);
}

static int ndisc_option_parse_dnssl(size_t offset, size_t len, const uint8_t *opt, Set **options) {
        int r;

        assert(opt);
        assert(options);

        if (len < 2*8)
                return -EBADMSG;

        if (opt[0] != SD_NDISC_OPTION_DNSSL)
                return -EBADMSG;

        usec_t lifetime = unaligned_be32_sec_to_usec(opt + 4, /* max_as_infinity = */ true);

        _cleanup_strv_free_ char **l = NULL;
        _cleanup_free_ char *e = NULL;
        size_t n = 0;
        for (size_t c, pos = 8; pos < len; pos += c) {

                c = opt[pos];
                pos++;

                if (c == 0) {
                        /* Found NUL termination */

                        if (n > 0) {
                                _cleanup_free_ char *normalized = NULL;

                                e[n] = 0;
                                r = dns_name_normalize(e, 0, &normalized);
                                if (r < 0)
                                        return r;

                                /* Ignore the root domain name or "localhost" and friends */
                                if (!is_localhost(normalized) && !dns_name_is_root(normalized)) {
                                        r = strv_consume(&l, TAKE_PTR(normalized));
                                        if (r < 0)
                                                return r;
                                }
                        }

                        n = 0;
                        continue;
                }

                /* Check for compression (which is not allowed) */
                if (c > 63)
                        return -EBADMSG;

                if (pos + c >= len)
                        return -EBADMSG;

                if (!GREEDY_REALLOC(e, n + (n != 0) + DNS_LABEL_ESCAPED_MAX + 1U))
                        return -ENOMEM;

                if (n != 0)
                        e[n++] = '.';

                r = dns_label_escape((const char*) (opt + pos), c, e + n, DNS_LABEL_ESCAPED_MAX);
                if (r < 0)
                        return r;

                n += r;
        }

        if (n > 0) /* Not properly NUL terminated */
                return -EBADMSG;

        if (strv_isempty(l))
                return -EBADMSG; /* no valid domains? */

        sd_ndisc_option *p = ndisc_option_new(SD_NDISC_OPTION_DNSSL, offset);
        if (!p)
                return -ENOMEM;

        p->dnssl = (sd_ndisc_dnssl) {
                .domains = TAKE_PTR(l),
                .lifetime = lifetime,
        };

        return ndisc_option_consume(options, p);
}

static int ndisc_option_parse_captive_portal(size_t offset, size_t len, const uint8_t *opt, Set **options) {
        assert(opt);
        assert(options);

        if (len < 8)
                return -EBADMSG;

        if (opt[0] != SD_NDISC_OPTION_CAPTIVE_PORTAL)
                return -EBADMSG;

        _cleanup_free_ char *portal = memdup_suffix0(opt + 2, len - 2);
        if (!portal)
                return -ENOMEM;

        size_t size = strlen(portal);
        if (size == 0)
                return -EBADMSG;

        /* Check that the message is not truncated by an embedded NUL.
         * NUL padding to a multiple of 8 is expected. */
        if (DIV_ROUND_UP(size + 2, 8) * 8 != len && DIV_ROUND_UP(size + 3, 8) * 8 != len)
                return -EBADMSG;

        if (!in_charset(portal, URI_VALID))
                return -EBADMSG;

        sd_ndisc_option *p = ndisc_option_new(SD_NDISC_OPTION_CAPTIVE_PORTAL, offset);
        if (!p)
                return -ENOMEM;

        p->captive_portal = TAKE_PTR(portal);

        return ndisc_option_consume(options, p);
}

static const uint8_t prefix_length_code_to_prefix_length[_PREFIX_LENGTH_CODE_MAX] = {
        [PREFIX_LENGTH_CODE_96] = 96,
        [PREFIX_LENGTH_CODE_64] = 64,
        [PREFIX_LENGTH_CODE_56] = 56,
        [PREFIX_LENGTH_CODE_48] = 48,
        [PREFIX_LENGTH_CODE_40] = 40,
        [PREFIX_LENGTH_CODE_32] = 32,
};

int pref64_plc_to_prefix_length(uint16_t plc, uint8_t *ret) {
        plc &= PREF64_PLC_MASK;
        if (plc >= _PREFIX_LENGTH_CODE_MAX)
                return -EINVAL;

        if (ret)
                *ret = prefix_length_code_to_prefix_length[plc];
        return 0;
}

int pref64_prefix_length_to_plc(uint8_t prefixlen, uint8_t *ret) {
        assert(ret);

        for (size_t i = 0; i < ELEMENTSOF(prefix_length_code_to_prefix_length); i++)
                if (prefix_length_code_to_prefix_length[i] == prefixlen) {
                        *ret = i;
                        return 0;
                }

        return -EINVAL;
}

static int pref64_lifetime_and_plc_parse(uint16_t lifetime_and_plc, uint8_t *ret_prefixlen, usec_t *ret_lifetime) {
        uint16_t plc = lifetime_and_plc & PREF64_PLC_MASK;
        if (plc >= _PREFIX_LENGTH_CODE_MAX)
                return -EINVAL;

        if (ret_prefixlen)
                *ret_prefixlen = prefix_length_code_to_prefix_length[plc];
        if (ret_lifetime)
                *ret_lifetime = (lifetime_and_plc & PREF64_SCALED_LIFETIME_MASK) * USEC_PER_SEC;
        return 0;
}

static int ndisc_option_parse_prefix64(size_t offset, size_t len, const uint8_t *opt, Set **options) {
        int r;

        assert(opt);
        assert(options);

        if (len != 2*8)
                return -EBADMSG;

        if (opt[0] != SD_NDISC_OPTION_PREF64)
                return -EBADMSG;

        uint8_t prefixlen;
        usec_t lifetime;
        r = pref64_lifetime_and_plc_parse(unaligned_read_be16(opt + 2), &prefixlen, &lifetime);
        if (r < 0)
                return r;

        struct in6_addr prefix;
        memcpy(&prefix, opt + 4, len - 4);
        in6_addr_mask(&prefix, prefixlen);

        sd_ndisc_option *p = ndisc_option_new(SD_NDISC_OPTION_PREF64, offset);
        if (!p)
                return -ENOMEM;

        p->prefix64 = (sd_ndisc_prefix64) {
                .prefixlen = prefixlen,
                .prefix = prefix,
                .lifetime = lifetime,
        };

        return ndisc_option_consume(options, p);
}

static int ndisc_option_parse_default(size_t offset, size_t len, const uint8_t *opt, Set **options) {
        assert(options);
        assert(opt);
        assert(len > 0);

        sd_ndisc_option *p = ndisc_option_new(opt[0], offset);
        if (!p)
                return -ENOMEM;

        return ndisc_option_consume(options, p);
}

int ndisc_parse_options(ICMP6Packet *packet, size_t offset, Set **ret_options) {
        _cleanup_set_free_ Set *options = NULL;
        int r;

        assert(packet);
        assert(ret_options);

        for (size_t length; offset < packet->raw_size; offset += length) {
                uint8_t type;
                const uint8_t *opt;

                r = ndisc_option_parse(packet, offset, &type, &length, &opt);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse NDisc option: %m");

                switch (type) {
                case SD_NDISC_OPTION_SOURCE_LL_ADDRESS:
                case SD_NDISC_OPTION_TARGET_LL_ADDRESS:
                        r = ndisc_option_parse_link_layer_address(offset, length, opt, &options);
                        break;

                case SD_NDISC_OPTION_PREFIX_INFORMATION:
                        r = ndisc_option_parse_prefix(offset, length, opt, &options);
                        break;

                case SD_NDISC_OPTION_REDIRECTED_HEADER:
                        r = ndisc_option_parse_redirected_header(offset, length, opt, &options);
                        break;

                case SD_NDISC_OPTION_MTU:
                        r = ndisc_option_parse_mtu(offset, length, opt, &options);
                        break;

                case SD_NDISC_OPTION_ROUTE_INFORMATION:
                        r = ndisc_option_parse_route(offset, length, opt, &options);
                        break;

                case SD_NDISC_OPTION_RDNSS:
                        r = ndisc_option_parse_rdnss(offset, length, opt, &options);
                        break;

                case SD_NDISC_OPTION_FLAGS_EXTENSION:
                        r = ndisc_option_parse_flags_extension(offset, length, opt, &options);
                        break;

                case SD_NDISC_OPTION_DNSSL:
                        r = ndisc_option_parse_dnssl(offset, length, opt, &options);
                        break;

                case SD_NDISC_OPTION_CAPTIVE_PORTAL:
                        r = ndisc_option_parse_captive_portal(offset, length, opt, &options);
                        break;

                case SD_NDISC_OPTION_PREF64:
                        r = ndisc_option_parse_prefix64(offset, length, opt, &options);
                        break;

                default:
                        r = ndisc_option_parse_default(offset, length, opt, &options);
                }
                if (r == -ENOMEM)
                        return log_oom_debug();
                if (r < 0)
                        log_debug_errno(r, "Failed to parse NDisc option %u, ignoring: %m", type);
        }

        *ret_options = TAKE_PTR(options);
        return 0;
}

int ndisc_option_get_mac(Set *options, uint8_t type, struct ether_addr *ret) {
        assert(IN_SET(type, SD_NDISC_OPTION_SOURCE_LL_ADDRESS, SD_NDISC_OPTION_TARGET_LL_ADDRESS));

        sd_ndisc_option *p = ndisc_option_get(options, type);
        if (!p)
                return -ENODATA;

        if (ret)
                *ret = p->mac;
        return 0;
}
