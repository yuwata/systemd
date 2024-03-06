/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include "sd-ndisc.h"

#include "icmp6-packet.h"
#include "ndisc-protocol.h"
#include "time-util.h"

struct sd_ndisc_router {
        unsigned n_ref;

        ICMP6Packet *packet;

        /* From RA header */
        uint8_t hop_limit;
        uint8_t flags;
        uint8_t preference;
        usec_t lifetime_usec;
        usec_t reachable_time_usec;
        usec_t retransmission_time_usec;

        /* Options */
        Set *options;
        Iterator iterator;
        sd_ndisc_option *current_option;
};

sd_ndisc_router* ndisc_router_new(ICMP6Packet *packet);
int ndisc_router_parse(sd_ndisc *nd, sd_ndisc_router *rt);
