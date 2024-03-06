/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.NetworkControl.h"

static VARLINK_DEFINE_METHOD(
                SavePersistentFile,
                VARLINK_DEFINE_INPUT(Path, VARLINK_STRING, 0),
                VARLINK_DEFINE_INPUT(Contents, VARLINK_OBJECT, 0));

VARLINK_DEFINE_INTERFACE(
                io_systemd_NetworkControl,
                "io.systemd.NetworkControl",
                &vl_method_SavePersistentFile);
