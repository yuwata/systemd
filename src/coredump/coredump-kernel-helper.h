/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "coredump-forward.h"

int coredump_kernel_helper(int argc, char *argv[]);
int coredump_send_or_submit(const CoredumpConfig *config, CoredumpContext *context, int input_fd);
