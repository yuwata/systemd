/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "coredump-forward.h"

int coredump_worker_main(const CoredumpConfig *config, bool request_mode, int coredump_fd);
