/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dirent.h>
#include <sys/stat.h>

#include "dirent-util.h"
#include "errno-util.h"
#include "glob-util.h"
#include "string-util.h"
#include "strv.h"

typedef union safe_glob_t {
        glob_t glob;
#if HAVE_GLOB_ALTDIRFUNC
        glob_t glob_gnu;
#else
        struct {
                size_t gl_pathc;
                char **gl_pathv;
                size_t gl_offs;
                int gl_flags;

                void (*gl_closedir)(void *);
                struct dirent* (*gl_readdir)(void *);
                void* (*gl_opendir)(const char *);
                int (*gl_lstat)(const char *, struct stat *);
                int (*gl_stat)(const char *, struct stat *);
        } glob_gnu;
#endif
} safe_glob_t;

static void safe_glob_done(safe_glob_t *g) {
        assert(g);

        globfree(&g->glob);
}

static void closedir_wrapper(void *v) {
        (void) closedir(v);
}

#if !HAVE_GLOB_ALTDIRFUNC
static bool safe_glob_verify(const char *p) {
        if (isempty(p))
                return false;

        bool has_dot = false;
        for (const char *e = p;;) {
                if (path_find_first_component(&e, /* accept_dot_dot = */ false, /* ret = */ NULL) < 0)
                        return false;

                if (e - p >= PATH_MAX) /* Already reached the maximum length for a path? (PATH_MAX is counted
                                        * *with* the trailing NUL byte) */
                        return false;
                if (*e == 0)           /* End of string? Yay! */
                        break;

                if (has_dot)
                        return false; /* previous component starts with dot. */

                if (*e == '.')
                        has_dot = true;
        }

        if (streq(p, ".") || startswith(p, "./") || endswith(p, "/.") || strstr(p, "/./"))
                return false;

        if (strstr(p, "//"))
                return false;

        return true;
}
#endif

int safe_glob_full(const char *path, int flags, opendir_t opendir_func, char ***ret) {
        _cleanup_(safe_glob_done) safe_glob_t g = {
                .glob_gnu = {
                        .gl_closedir = closedir_wrapper,
                        .gl_readdir = (struct dirent* (*)(void *)) readdir_no_dot,
                        .gl_opendir = (void* (*)(const char *)) (opendir_func ?: opendir),
                        .gl_lstat = lstat,
                        .gl_stat = stat,
                },
        };
        int r;

        assert(path);

        errno = 0;
        r = glob(path, flags | GLOB_ALTDIRFUNC, NULL, &g.glob);
        if (r == GLOB_NOMATCH)
                return -ENOENT;
        if (r == GLOB_NOSPACE)
                return -ENOMEM;
        if (r != 0)
                return errno_or_else(EIO);

#if !HAVE_GLOB_ALTDIRFUNC
        for (char **p = g.glob.gl_pathv, **q = p; p && *p; p++)
                if (safe_glob_verify(*p))
                        *q++ = TAKE_PTR(*p);
                else {
                        *p = mfree(*p);
                        assert(g.glob.gl_pathc > 0);
                        g.glob.gl_pathc--;
                }
#endif

        if (strv_isempty(g.glob.gl_pathv))
                return -ENOENT;

        if (ret) {
                *ret = TAKE_PTR(g.glob.gl_pathv);
                TAKE_STRUCT(g);
        }

        return 0;
}

int glob_first(const char *path, char **ret) {
        _cleanup_strv_free_ char **v = NULL;
        int r;

        assert(path);

        r = safe_glob(path, GLOB_NOSORT|GLOB_BRACE, &v);
        if (r == -ENOENT) {
                if (ret)
                        *ret = NULL;
                return false;
        }
        if (r < 0)
                return r;

        assert(*v);

        if (ret) {
                STRV_FOREACH(p, strv_skip(v, 1))
                        *p = mfree(*p);

                *ret = TAKE_PTR(*v);
        }

        return true;
}

int glob_extend(char ***strv, const char *path, int flags) {
        _cleanup_strv_free_ char **v = NULL;
        int r;

        assert(path);

        r = safe_glob(path, GLOB_NOSORT|GLOB_BRACE|flags, &v);
        if (r < 0)
                return r;

        return strv_extend_strv(strv, v, /* filter_duplicates = */ false);
}

int glob_non_glob_prefix(const char *path, char **ret) {
        /* Return the path of the path that has no glob characters. */

        size_t n = strcspn(path, GLOB_CHARS);

        if (path[n] != '\0')
                while (n > 0 && path[n-1] != '/')
                        n--;

        if (n == 0)
                return -ENOENT;

        char *ans = strndup(path, n);
        if (!ans)
                return -ENOMEM;
        *ret = ans;
        return 0;
}

bool string_is_glob(const char *p) {
        /* Check if a string contains any glob patterns. */
        return !!strpbrk(p, GLOB_CHARS);
}
