/*
 * Copyright (c) 2003-2011 PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Redistributions in any form must be accompanied by information on
 *    how to obtain complete source code for the pam_gss software and any
 *    accompanying software that uses the pam_gss software. The source code
 *    must either be included in the distribution or be available for no
 *    more than the cost of distribution plus a nominal fee, and must be
 *    freely redistributable under reasonable conditions. For an
 *    executable file, complete source code means the source code for all
 *    modules it contains. It does not include source code for modules or
 *    files that typically accompany the major components of the operating
 *    system on which the executable file runs.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR
 * NON-INFRINGEMENT, ARE DISCLAIMED. IN NO EVENT SHALL PADL SOFTWARE
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * To build:
 *
 * gcc -Wall -g -o pamtest pamtest.c -lpam -ldl
 *
 * Usage:
 *
 * pamtest [user] [service]
 * where:
 *	user is login name if not specified
 *	service is "login" if not specified
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <dlfcn.h>

#include <security/pam_appl.h>

int pamtestConv(int num_msg, struct pam_message **msgv,
	struct pam_response **respv, void *appdata_ptr)
{
	int i;
	char buf[PAM_MAX_MSG_SIZE];

	fprintf(stderr, "%s:%d pamtestConv num_msg=%d\n",
		__FILE__, __LINE__, num_msg);

	*respv = (struct pam_response *)calloc(num_msg, sizeof(struct pam_response));
	if (*respv == NULL) {
		return PAM_BUF_ERR;
	}

	for (i = 0; i < num_msg; i++) {
		const struct pam_message *msg = msgv[i];
		struct pam_response *resp = &((*respv)[i]);

		char *p = NULL;

		switch (msg->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
#if defined(__linux__) || defined(__APPLE__)
			p = getpass(msg->msg);
#else
			p = getpassphrase(msg->msg);
#endif
			break;
		case PAM_PROMPT_ECHO_ON:
			printf("%s", msg->msg);
			p = fgets(buf, sizeof(buf), stdin);
			if (p != NULL) p[strlen(p) - 1] = '\0';
			break;
		case PAM_ERROR_MSG:
			fprintf(stderr, "%s\n", msg->msg);
			break;
		case PAM_TEXT_INFO:
#ifdef PAM_MSG_NOCONF
		case PAM_MSG_NOCONF:
#endif
			printf("%s\n", msg->msg);
			break;
		default:
#ifdef PAM_CONV_INTERRUPT
		case PAM_CONV_INTERRUPT:
#endif
			return PAM_CONV_ERR;
		}

		resp->resp = (p == NULL) ? NULL : strdup(p);
		resp->resp_retcode = 0;
	}

	return PAM_SUCCESS;
}

#define CHECK_STATUS(pamh, fn, rc)	do { \
	char *_err; \
	_err = (rc == PAM_OPEN_ERR || rc == PAM_SYMBOL_ERR) ? dlerror() : NULL; \
	fprintf(stderr, "%s:%d %s: %s[%d]%s%s\n", \
		__FILE__, __LINE__, (fn), pam_strerror((pamh), (rc)), rc, \
		(rc == PAM_OPEN_ERR || rc == PAM_SYMBOL_ERR) ? " - dlerror: " : "", \
		_err ? _err : "(null)"); \
	} while (0)

int main(int argc, char *argv[])
{
	char *user = (argc > 1) ? argv[1] : getlogin();
	char *service = (argc > 2) ? argv[2] : "pamtest";
	struct pam_conv conv;
	int rc;
	pam_handle_t *pamh = NULL;

	conv.conv = pamtestConv;
	conv.appdata_ptr = NULL;

	fprintf(stderr, "%s:%d Starting with user=%s service=%s\n",
		__FILE__, __LINE__, user, service);

	rc = pam_start(service, user, &conv, &pamh);
	CHECK_STATUS(pamh, "pam_start", rc);

	rc = pam_authenticate(pamh, 0);
	CHECK_STATUS(pamh, "pam_authenticate", rc);

	rc = pam_acct_mgmt(pamh, 0);
	CHECK_STATUS(pamh, "pam_acct_mgmt", rc);

	if (rc == PAM_SUCCESS) {
		rc = pam_open_session(pamh, 0);
		CHECK_STATUS(pamh, "pam_open_session", rc);

		rc = pam_close_session(pamh, 0);
		CHECK_STATUS(pamh, "pam_close_session", rc);
	}

	if (rc != PAM_SUCCESS) {
		return rc;
	}

	if (pamh != NULL) {
		rc = pam_end(pamh, PAM_SUCCESS);
		CHECK_STATUS(pamh, "pam_end", rc);
	}

	return rc;
}

