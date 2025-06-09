/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <features.h>

/* Most glibc headers includes features.h.
 * Let's define assert_cc() here, to make it usable in our glibc header wrappers. */
#define assert_cc(expr) _Static_assert(expr, #expr)

/* For musl. */
#ifndef __THROW
#define __THROW
#endif
