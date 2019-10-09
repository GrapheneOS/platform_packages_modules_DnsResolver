/*	$NetBSD: res_private.h,v 1.1.1.1 2004/05/20 17:18:54 christos Exp $	*/

#ifndef NETD_RES_STATE_EXT_H
#define NETD_RES_STATE_EXT_H

#include "resolv_private.h"

// TODO: consider inlining into res_state
struct res_state_ext {
    sockaddr_union nsaddrs[MAXNS];
};

#endif  // NETD_RES_STATE_EXT_H
