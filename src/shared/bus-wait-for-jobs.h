/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "macro.h"

typedef struct BusWaitForJobs BusWaitForJobs;

int bus_wait_for_jobs_new(sd_bus *bus, BusWaitForJobs **ret);
BusWaitForJobs* bus_wait_for_jobs_free(BusWaitForJobs *d);
int bus_wait_for_jobs_add(BusWaitForJobs *d, const char *path);
int bus_wait_for_jobs(BusWaitForJobs *d, bool quiet, const char* const* extra_args);
int bus_wait_for_jobs_one(BusWaitForJobs *d, const char *path, bool quiet, const char* const* extra_args);
int bus_subscribe_and_match_job_removed_async(sd_bus *bus, sd_bus_message_handler_t match_callback, void *userdata);
static inline int bus_subscribe_async(sd_bus *bus) {
        return bus_subscribe_and_match_job_removed_async(bus, NULL, NULL);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(BusWaitForJobs*, bus_wait_for_jobs_free);
