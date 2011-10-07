/*
 * Copyright (c) 2011 PADL Software Pty Ltd.
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
 *    how to obtain complete source code for the NegoEx software and any
 *    accompanying software that uses the NegoEx software. The source code
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

#define PAM_SM_AUTH 
#define PAM_SM_ACCOUNT 

#include <security/pam_modules.h>
#include <security/pam_appl.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

#include <sys/param.h>

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>

#define HAVE_GSS_LOCALNAME      1

#define PASSWORD_PROMPT         "Password:"

#define GSS_MECH_DATA           "GSS-MECH-DATA"
#define GSS_CRED_DATA           "GSS-CRED-DATA"
#define GSS_NAME_DATA           "GSS-NAME-DATA"

static gss_OID_desc gss_spnego_mechanism_oid_desc =
        {6, (void *)"\x2b\x06\x01\x05\x05\x02"};

static void
displayStatusByType(OM_uint32 status, int type)
{
    OM_uint32 major, minor;
    gss_buffer_desc msg;
    OM_uint32 messageCtx;

    messageCtx = 0;

    for (;;) {
        major = gss_display_status(&minor, status,
                                   type, GSS_C_NULL_OID,
                                   &messageCtx, &msg);
        syslog(LOG_DEBUG, "pam_gss: %s\n", (char *)msg.value);

        gss_release_buffer(&minor, &msg);

        if (!messageCtx)
            break;
    }
}

static void
displayStatus(OM_uint32 major, OM_uint32 minor)
{
    displayStatusByType(major, GSS_C_GSS_CODE);
    displayStatusByType(minor, GSS_C_MECH_CODE);
}

static int
gssToPamStatus(OM_uint32 major, OM_uint32 minor)
{
    int status;

    switch (major) {
    case GSS_S_COMPLETE:
        status = PAM_SUCCESS;
        break;
    case GSS_S_BAD_NAME:
        status = PAM_USER_UNKNOWN;
        break;
    case GSS_S_UNAUTHORIZED:
        status = PAM_PERM_DENIED;
        break;
    case GSS_S_DEFECTIVE_CREDENTIAL:
    default:
        status = PAM_AUTH_ERR;
        break;
    }

    return status;
}

static void
cleanupGssMechData(pam_handle_t *pamh, void *data,
                   int error_status)
{
    OM_uint32 minor;
    gss_release_oid(&minor, (gss_OID *)&data);
}

static void
cleanupGssCredData(pam_handle_t *pamh, void *data,
                   int error_status)
{
    OM_uint32 minor;
    gss_release_cred(&minor, (gss_cred_id_t *)&data);
}

static void
cleanupGssNameData(pam_handle_t *pamh, void *data,
                   int error_status)
{
    OM_uint32 minor;
    gss_release_name(&minor, (gss_name_t *)&data);
}

int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int status;
    struct pam_conv *conv;
    struct pam_message msg;
    const struct pam_message *msgp;
    struct pam_response *resp;

    OM_uint32 major = GSS_S_FAILURE, minor;
    gss_buffer_desc userNameBuf = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc hostNameBuf = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc passwordBuf = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc canonUserNameBuf = GSS_C_EMPTY_BUFFER;
    gss_name_t userName = GSS_C_NO_NAME;
    gss_name_t hostName = GSS_C_NO_NAME;
    gss_name_t canonUserName = GSS_C_NO_NAME;
    gss_OID_set_desc mechOids = { 1, &gss_spnego_mechanism_oid_desc };
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc initiatorToken = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc acceptorToken = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t initiatorContext = GSS_C_NO_CONTEXT;
    gss_ctx_id_t acceptorContext = GSS_C_NO_CONTEXT;
    gss_OID canonMech = GSS_C_NO_OID;
    char hostNameBufBuf[5 + MAXHOSTNAMELEN + 1] = "host@";
    int passwordBufAlloced = 0;

    status = pam_get_user(pamh, (void *)&userNameBuf.value, NULL);
    if (status != PAM_SUCCESS) {
        goto cleanup;
    }

    userNameBuf.length = strlen((char *)userNameBuf.value);

    major = gss_import_name(&minor, &userNameBuf, GSS_C_NT_USER_NAME, &userName);
    if (GSS_ERROR(major))
        goto cleanup;

    if (gethostname(&hostNameBufBuf[5], MAXHOSTNAMELEN) != 0) {
        major = GSS_S_FAILURE;
        minor = errno;
        goto cleanup;
    }

    hostNameBuf.length = strlen(hostNameBufBuf);
    hostNameBuf.value = hostNameBufBuf;

    major = gss_import_name(&minor, &hostNameBuf, GSS_C_NT_HOSTBASED_SERVICE, &hostName);
    if (GSS_ERROR(major))
        goto cleanup;

    status = pam_get_item(pamh, PAM_AUTHTOK, (void *)&passwordBuf.value);
    if (status != PAM_SUCCESS) {
        goto cleanup;
    }

    if (passwordBuf.value == NULL) {
        status = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
        if (status != PAM_SUCCESS)
            goto cleanup;

        msg.msg_style = PAM_PROMPT_ECHO_OFF;
        msg.msg = PASSWORD_PROMPT;
        msgp = &msg;
        resp = NULL;

        status = (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr);

        if (resp != NULL) {
            if (status == PAM_SUCCESS) {
                passwordBufAlloced++;
                passwordBuf.value = resp->resp;
            } else
                free(resp->resp);
            free(resp);
        }
    }

    passwordBuf.length = passwordBuf.value ? strlen((char *)passwordBuf.value) : 0;
    if (passwordBuf.length == 0 && (flags & PAM_DISALLOW_NULL_AUTHTOK)) {
        status = PAM_AUTH_ERR;
        goto cleanup;
    }

    major = gss_acquire_cred_with_password(&minor, userName, &passwordBuf,
                                           GSS_C_INDEFINITE, &mechOids,
                                           GSS_C_INITIATE, &cred, NULL, NULL);
    if (GSS_ERROR(major))
        goto cleanup;

    do {
        major = gss_init_sec_context(&minor, cred, &initiatorContext,
                                     hostName, &mechOids.elements[0], GSS_C_MUTUAL_FLAG,
                                     GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS,
                                     &acceptorToken, NULL, &initiatorToken, NULL, NULL);
        if (GSS_ERROR(major))
            break;

        gss_release_buffer(&minor, &acceptorToken);

        major = gss_accept_sec_context(&minor, &acceptorContext, GSS_C_NO_CREDENTIAL,
                                       &initiatorToken, GSS_C_NO_CHANNEL_BINDINGS,
                                       &canonUserName, &canonMech, &acceptorToken,
                                       NULL, NULL, NULL);

        gss_release_buffer(&minor, &initiatorToken);
    } while (major == GSS_S_CONTINUE_NEEDED);

    if (GSS_ERROR(major))
        goto cleanup;

#ifdef HAVE_GSS_LOCALNAME
    major = gss_localname(&minor, canonUserName, GSS_C_NO_OID, &canonUserNameBuf);
    if (major == GSS_S_COMPLETE) {
        status = pam_set_item(pamh, PAM_USER, canonUserNameBuf.value);
        if (status != PAM_SUCCESS)
            goto cleanup;
    }
#endif

    status = pam_set_data(pamh, GSS_CRED_DATA, cred, cleanupGssCredData);
    if (status != PAM_SUCCESS)
        goto cleanup;
    cred = GSS_C_NO_CREDENTIAL;

    status = pam_set_data(pamh, GSS_NAME_DATA, canonUserName, cleanupGssNameData);
    if (status != PAM_SUCCESS)
        goto cleanup;
    canonUserName = GSS_C_NO_NAME;

    status = pam_set_data(pamh, GSS_MECH_DATA, canonMech, cleanupGssMechData);
    if (status != PAM_SUCCESS)
        goto cleanup;
    canonMech = GSS_C_NO_OID;

    status = PAM_SUCCESS;

cleanup:
    if (status == PAM_SUCCESS) {
        status = gssToPamStatus(major, minor);
        displayStatus(major, minor);
    }

    gss_release_name(&minor, &userName);
    gss_release_name(&minor, &canonUserName);
    gss_release_name(&minor, &hostName);
    gss_release_cred(&minor, &cred);
    gss_release_buffer(&minor, &initiatorToken);
    gss_release_buffer(&minor, &acceptorToken);
    gss_release_buffer(&minor, &canonUserNameBuf);
    if (passwordBufAlloced) {
        memset(passwordBuf.value, 0, passwordBuf.length);
        gss_release_buffer(&minor, &passwordBuf);
    }
    gss_delete_sec_context(&minor, &initiatorContext, NULL);
    gss_delete_sec_context(&minor, &acceptorContext, NULL);

    return status;
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int status;
    gss_name_t canonUserName = GSS_C_NO_NAME;
    char *userName = NULL;

    status = pam_get_data(pamh, GSS_NAME_DATA, (const void **)&canonUserName);
    if (status != PAM_SUCCESS) {
        return PAM_USER_UNKNOWN;
    }

    status = pam_get_user(pamh, (void *)&userName, NULL);
    if (status != PAM_SUCCESS) {
        return PAM_USER_UNKNOWN;
    }

    return gss_userok(canonUserName, userName) ? PAM_SUCCESS : PAM_PERM_DENIED;

}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int status;
    OM_uint32 major, minor;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_OID mech = GSS_C_NO_OID;

    if (flags && (flags & PAM_ESTABLISH_CRED) == 0) {
        return PAM_SUCCESS;
    }

    status = pam_get_data(pamh, GSS_CRED_DATA, (const void **)&cred);
    if (status != PAM_SUCCESS) {
        return status;
    }

    status = pam_get_data(pamh, GSS_MECH_DATA, (const void **)&mech);
    if (status != PAM_SUCCESS) {
        return status;
    }

    major = gss_store_cred(&minor, cred, GSS_C_INITIATE, mech,
                           1, 1, NULL, NULL);

    return gssToPamStatus(major, minor);
}
