/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fs-util.h"
#include "mkdir.h"
#include "networkctl-varlink.h"
#include "path-util.h"
#include "tmpfile-util.h"
#include "varlink.h"
#include "varlink-io.systemd.NetworkControl.h"

typedef struct PersistentFileInfo {
        const char *path;
        JsonVariant *contents;
} PersistentFileInfo;

static int vl_method_save_persistent_file(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        static const JsonDispatch dispatch_table[] = {
                { "Path",     JSON_VARIANT_STRING, json_dispatch_const_string,  offsetof(PersistentFileInfo, path),     JSON_MANDATORY },
                { "Contents", JSON_VARIANT_OBJECT, json_dispatch_variant_noref, offsetof(PersistentFileInfo, contents), JSON_MANDATORY },
                {}
        };

        PersistentFileInfo info = {};
        int r;

        assert(link);

        r = varlink_dispatch(link, parameters, dispatch_table, &info);
        if (r != 0)
                return r;

        if (!path_is_safe(info.path) || !path_startswith(info.path, "/var/lib/systemd/network/"))
                return varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("Path"));

        if (json_variant_is_blank_object(info.contents)) {
                if (unlink(info.path) < 0 && errno != ENOENT)
                        return log_error_errno(errno, "Failed to remove '%s': %m", info.path);

                return varlink_reply(link, NULL);
        }

        r = mkdir_parents(info.path, 0755);
        if (r < 0)
                return log_error_errno(r, "Failed to create parent directories of '%s': %m", info.path);

        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        r = fopen_temporary(info.path, &f, &temp_path);
        if (r < 0)
                return log_error_errno(r, "Failed to open a temporary file for '%s': %m", info.path);

        (void) fchmod(fileno(f), 0644);

        r = json_variant_dump(info.contents, JSON_FORMAT_NEWLINE | JSON_FORMAT_FLUSH, f, /* prefix = */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to dump json variant to '%s': %m", info.path);

        r = conservative_rename(temp_path, info.path);
        if (r < 0)
                return log_error_errno(r, "Failed to rename temporary file for '%s': %m", info.path);

        temp_path = mfree(temp_path);

        return varlink_reply(link, NULL);
}

int networkctl_varlink(void) {
        int r;

        r = varlink_invocation(VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        if (r == 0)
                return 0;

        /* Invoked as Varlink service. */

        _cleanup_(varlink_server_unrefp) VarlinkServer *varlink_server = NULL;
        r = varlink_server_new(&varlink_server, VARLINK_SERVER_ROOT_ONLY);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_NetworkControl);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = varlink_server_bind_method_many(
                        varlink_server,
                        "io.systemd.NetworkControl.SavePersistentFile", vl_method_save_persistent_file);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        r = varlink_server_loop_auto(varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 1;
}
