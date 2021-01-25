/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "hashmap.h"
#include "macro.h"

typedef struct LogDomain {
        char *name;
        int max_level; /* if < 0: use default log level maintained by log.c */
} LogDomain;

LogDomain *log_domain_free(LogDomain *domain);
DEFINE_TRIVIAL_CLEANUP_FUNC(LogDomain*, log_domain_free);
int log_domain_new(const char *name, int level, LogDomain **ret);

int log_domain_add(Hashmap **domains, const char *name, int level, LogDomain **ret);
int log_domain_add_from_string(Hashmap **domains, const char *str);
int log_domain_get(Hashmap *domains, const char *name, LogDomain **ret);
