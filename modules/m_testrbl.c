/* modules/m_testrbl.c
 *
 *  Copyright (C) 2026 ircd-ratbox development team
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1.Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * 2.Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3.The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include "stdinc.h"
#include "ratbox_lib.h"
#include "struct.h"
#include "client.h"
#include "send.h"
#include "modules.h"
#include "parse.h"
#include "numeric.h"
#include "s_auth.h"
#include "dns.h"

static int mo_testrbl(struct Client *, struct Client *, int, const char **);

struct Message testrbl_msgtab = {
	.cmd = "TESTRBL",
	.handlers[UNREGISTERED_HANDLER] =	{ mm_unreg },
	.handlers[CLIENT_HANDLER] =		{ mm_not_oper },
	.handlers[RCLIENT_HANDLER] =		{ mm_ignore },
	.handlers[SERVER_HANDLER] =		{ mm_ignore },
	.handlers[ENCAP_HANDLER] =		{ mm_ignore },
	.handlers[OPER_HANDLER] =		{ .handler = mo_testrbl, .min_para = 2 },
};

mapi_clist_av1 testrbl_clist[] = { &testrbl_msgtab, NULL };
DECLARE_MODULE_AV1(testrbl, NULL, NULL, testrbl_clist, NULL, NULL, "$Revision$");

struct testrbl_lookup_ctx
{
	struct Client	*source_p;
	char		 hostname[HOSTLEN + 1];
	uint32_t	 xid4;
	uint32_t	 xid6;
	int		 pending;	/* decremented as each lookup completes;
					 * ctx freed when it reaches zero */
};

static void
testrbl_dns_callback(const char *res, int status, int aftype, void *data)
{
	struct testrbl_lookup_ctx *ctx = data;
	struct rb_sockaddr_storage addr;

	if(res == NULL || status == 0)
	{
		/* One of the two lookups failed — not necessarily fatal,
		 * the other family may still succeed. */
		sendto_one_notice(ctx->source_p,
			":TESTRBL: no %s address found for %s",
			aftype == AF_INET6 ? "IPv6" : "IPv4",
			ctx->hostname);
	}
	else
	{
		memset(&addr, 0, sizeof(addr));
		if(rb_inet_pton_sock(res, (struct sockaddr *)&addr) <= 0)
		{
			sendto_one_notice(ctx->source_p,
				":TESTRBL: resolver returned unparseable address %s for %s",
				res, ctx->hostname);
		}
		else
		{
			sendto_one_notice(ctx->source_p,
				":TESTRBL: %s resolved to %s, testing...",
				ctx->hostname, res);
			rbl_run_test(ctx->source_p, (const struct sockaddr *)&addr, res);
		}
	}

	/* Free the context only once both lookups have completed */
	ctx->pending--;
	if(ctx->pending == 0)
		rb_free(ctx);
}

static int
mo_testrbl(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct rb_sockaddr_storage ip;
	const char *target = parv[1];

	memset(&ip, 0, sizeof(ip));

	/* Try to parse as a literal IP address first — no DNS needed */
	if(rb_inet_pton_sock(target, (struct sockaddr *)&ip) > 0)
	{
		rbl_run_test(source_p, (const struct sockaddr *)&ip, target);
		return 0;
	}

	/* Looks like a hostname — validate length then resolve asynchronously */
	if(strlen(target) > HOSTLEN)
	{
		sendto_one_notice(source_p, ":TESTRBL: hostname too long: %s", target);
		return 0;
	}

	struct testrbl_lookup_ctx *ctx = rb_malloc(sizeof(*ctx));
	ctx->source_p = source_p;
	rb_strlcpy(ctx->hostname, target, sizeof(ctx->hostname));

#ifdef RB_IPV6
	/* Fire off both IPv6 and IPv4 lookups in parallel; pending tracks
	 * how many are still outstanding so we know when to free ctx. */
	ctx->pending = 2;
	ctx->xid6 = lookup_hostname(target, AF_INET6, testrbl_dns_callback, ctx);
	ctx->xid4 = lookup_hostname(target, AF_INET,  testrbl_dns_callback, ctx);
#else
	ctx->pending = 1;
	ctx->xid4 = lookup_hostname(target, AF_INET,  testrbl_dns_callback, ctx);
	ctx->xid6 = 0;
#endif

	sendto_one_notice(source_p, ":TESTRBL: looking up hostname %s...", target);
	return 0;
}
