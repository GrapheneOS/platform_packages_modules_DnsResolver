/*	$NetBSD: res_init.c,v 1.8 2006/03/19 03:10:08 christos Exp $	*/

/*
 * Copyright (c) 1985, 1989, 1993
 *    The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 * 	This product includes software developed by the University of
 * 	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Portions Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define LOG_TAG "resolv"

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netinet/in.h>

#include <android-base/logging.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "netd_resolv/resolv.h"
#include "res_state_ext.h"
#include "resolv_private.h"

// Set up Resolver state default settings.
// Note: this is called with statp zero-initialized
void res_init(res_state statp) {
    statp->netid = NETID_UNSET;
    statp->id = arc4random_uniform(65536);
    statp->_mark = MARK_UNSET;

    statp->nscount = 0;
    statp->ndots = 1;
    statp->_vcsock = -1;
    statp->_flags = 0;
    statp->_u._ext.nscount = 0;
    statp->_u._ext.ext = (res_state_ext*) malloc(sizeof(*statp->_u._ext.ext));
    statp->netcontext_flags = 0;
    if (statp->_u._ext.ext != NULL) {
        memset(statp->_u._ext.ext, 0, sizeof(*statp->_u._ext.ext));
    }

    // The following dummy initialization is probably useless because
    // it's overwritten later by _resolv_populate_res_for_net().
    // TODO: check if it's safe to remove.
    const sockaddr_union u{
            .sin.sin_addr.s_addr = INADDR_ANY,
            .sin.sin_family = AF_INET,
            .sin.sin_port = htons(NAMESERVER_PORT),
    };
    memcpy(&statp->_u._ext.ext->nsaddrs[0], &u, sizeof(u));
    statp->nscount = 1;
}

/*
 * This routine is for closing the socket if a virtual circuit is used and
 * the program wants to close it.  This provides support for endhostent()
 * which expects to close the socket.
 *
 * This routine is not expected to be user visible.
 */
void res_nclose(res_state statp) {
    int ns;

    if (statp->_vcsock >= 0) {
        (void) close(statp->_vcsock);
        statp->_vcsock = -1;
        statp->_flags &= ~RES_F_VC;
    }
    for (ns = 0; ns < statp->_u._ext.nscount; ns++) {
        if (statp->_u._ext.nssocks[ns] != -1) {
            (void) close(statp->_u._ext.nssocks[ns]);
            statp->_u._ext.nssocks[ns] = -1;
        }
    }
}

void res_ndestroy(res_state statp) {
    res_nclose(statp);
    if (statp->_u._ext.ext != NULL) free(statp->_u._ext.ext);
    statp->_u._ext.ext = NULL;
}

void res_setnetcontext(res_state statp, const struct android_net_context* netcontext,
                       android::net::NetworkDnsEventReported* _Nonnull event) {
    if (statp != nullptr) {
        statp->netid = netcontext->dns_netid;
        statp->uid = netcontext->uid;
        statp->_mark = netcontext->dns_mark;
        statp->netcontext_flags = netcontext->flags;
        statp->event = event;
    }
}
