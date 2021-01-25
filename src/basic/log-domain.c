/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/syslog.h>

#include "extract-word.h"
#include "log-domain.h"
#include "log.h"
#include "syslog-util.h"

LogDomain *log_domain_free(LogDomain *domain) {
        if (!domain)
                return NULL;

        free(domain->name);

        return mfree(domain);
}

int log_domain_new(const char *name, int level, LogDomain **ret) {
        _cleanup_(log_domain_freep) LogDomain *d = NULL;
        _cleanup_free_ char *n = NULL;

        assert(name);
        assert((level & LOG_PRIMASK) == level);
        assert(ret);

        n = strdup(name);
        if (!name)
                return -ENOMEM;

        d = new(LogDomain, 1);
        if (!d)
                return -ENOMEM;

        *d = (LogDomain) {
                .name = TAKE_PTR(n),
                .max_level = level,
        };

        *ret = TAKE_PTR(d);
        return 0;
}

int log_domain_add(Hashmap **domains, const char *name, int level, LogDomain **ret) {
        _cleanup_(log_domain_freep) LogDomain *d = NULL;
        LogDomain *existing;
        int r;

        assert(domains);
        assert(name);
        assert((level & LOG_PRIMASK) == level);

        existing = hashmap_get(*domains, name);
        if (existing) {
                existing->max_level = level;

                if (ret)
                        *ret = existing;
                return 0;
        }

        r = log_domain_new(name, level, &d);
        if (r < 0)
                return r;

        r = hashmap_ensure_put(domains, &string_hash_ops, d->name, d);
        if (r < 0)
                return r;

        if (ret)
                *ret = d;

        TAKE_PTR(d);
        return 1;
}

int log_domain_add_from_string(Hashmap **domains, const char *str) {
        int k = 0;

        for (const char *p = str;;) {
                _cleanup_free_ char *word = NULL;
                int level, r;
                char *eq;

                r = extract_first_word(&p, &word, ",", 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        return k;

                eq = strchr(word, '=');
                if (!eq) {
                        r = log_set_max_level_from_string(word);
                        if (r < 0)
                                k = log_debug_errno(r, "Failed to set maximum log level from string '%s', ignoring: %m", word);

                        continue;
                }

                if (!domains)
                        continue;

                *eq++ = '\0';

                level = log_level_from_string(eq);
                if (level < 0) {
                        k = log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse log level, ignoring: %s", eq);
                        continue;
                }

                r = log_domain_add(domains, word, level, NULL);
                if (r < 0) {
                        k = log_debug_errno(r, "Failed to add log domain '%s=%s', ignoring: %m", word, eq);
                        continue;
                }
        }
}

int log_domain_get(Hashmap *domains, const char *name, LogDomain **ret) {
        LogDomain *d;

        if (!domains || !name)
                return -ENOENT;

        d = hashmap_get(domains, name);
        if (!d)
                return -ENOENT;

        if (ret)
                *ret = d;

        return 0;
}
