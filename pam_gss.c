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
 * This is a PAM module that wraps around GSS mechanisms that support
 * gss_acquire_cred_with_password. The default mechanism is SPNEGO, but
 * this can be configured with the mech=OID option in pam.conf.
 */

#define PAM_SM_AUTH 
#define PAM_SM_ACCOUNT 

#include <security/pam_modules.h>
#include <security/pam_appl.h>

#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#include <GSS/GSS.h>
#else
#include <gssapi/gssapi.h>
#ifndef HAVE_HEIMDAL_VERSION
#include <gssapi/gssapi_ext.h>
#endif
#endif

#include <sys/param.h>

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <assert.h>

#define PASSWORD_PROMPT         "Password:"

#define GSS_MECH_DATA           "GSS-MECH-DATA"
#define GSS_CRED_DATA           "GSS-CRED-DATA"
#define GSS_NAME_DATA           "GSS-NAME-DATA"

#ifdef __APPLE__
#define CREDUI_ATTR_DATA        "CREDUI-ATTR-DATA"
#endif

#define BAIL_ON_PAM_ERROR(status)           do {            \
        if ((status) != PAM_SUCCESS)                        \
            goto cleanup;                                   \
    } while (0)

#define BAIL_ON_GSS_ERROR(major, minor)     do {            \
            status = pamGssMapStatus((major), (minor));     \
        if (GSS_ERROR(major)) {                             \
            goto cleanup;                                   \
        }                                                   \
    } while (0)

#define FLAG_USE_FIRST_PASS             0x01
#define FLAG_TRY_FIRST_PASS             0x02
#define FLAG_IGNORE_UNKNOWN_USER        0x04
#define FLAG_IGNORE_AUTHINFO_UNAVAIL    0x08
#define FLAG_NO_WARN                    0x10
#define FLAG_NULLOK                     0x20
#define FLAG_DEBUG                      0x30

#define IGNORE_ERR_P(status, confFlags)                                                     \
    (                                                                                       \
        ((status) == PAM_USER_UNKNOWN && ((confFlags) & FLAG_IGNORE_UNKNOWN_USER)) ||       \
        ((status) == PAM_AUTHINFO_UNAVAIL && ((confFlags) & FLAG_IGNORE_AUTHINFO_UNAVAIL))  \
    )

static gss_OID_desc gss_spnego_mechanism_oid_desc =
        {6, (void *)"\x2b\x06\x01\x05\x05\x02"};

#ifdef __APPLE__
typedef struct heim_oid {
    size_t length;
    unsigned *components;
} heim_oid;

int
der_parse_heim_oid (const char *str, const char *sep, heim_oid *data);

int
der_put_oid (unsigned char *p, size_t len,
             const heim_oid *data, size_t *size);

void
der_free_oid (heim_oid *k);
#endif

static void
displayStatusByType(OM_uint32 status, int type)
{
    OM_uint32 minor;
    gss_buffer_desc msg;
    OM_uint32 messageCtx;

    messageCtx = 0;

    for (;;) {
        gss_display_status(&minor, status,
                           type, GSS_C_NULL_OID,
                           &messageCtx, &msg);
        syslog(LOG_DEBUG, "pam_gss: %s\n", (char *)msg.value);

        gss_release_buffer(&minor, &msg);

        if (!messageCtx)
            break;
    }
}

__attribute__((__unused__))
static void
displayStatus(OM_uint32 major, OM_uint32 minor)
{
    displayStatusByType(major, GSS_C_GSS_CODE);
    displayStatusByType(minor, GSS_C_MECH_CODE);
}

static int
pamGssMapStatus(OM_uint32 major, OM_uint32 minor)
{
    int status;

    switch (major) {
    case GSS_S_COMPLETE:
        status = PAM_SUCCESS;
        break;
    case GSS_S_BAD_MECH:
        status = PAM_USER_UNKNOWN;
        break;
    case GSS_S_UNAUTHORIZED:
        status = PAM_PERM_DENIED;
        break;
    case GSS_S_NO_CRED:
#if 0
    case GSS_S_CRED_UNAVAIL:
#endif
        status = PAM_CRED_UNAVAIL;
        break;
    case GSS_S_DEFECTIVE_CREDENTIAL:
        status = PAM_AUTH_ERR;
        break;
    case GSS_S_CREDENTIALS_EXPIRED:
        status = PAM_CRED_EXPIRED;
        break;
    case GSS_S_UNAVAILABLE:
        status = PAM_IGNORE;
        break;
    case GSS_S_CONTEXT_EXPIRED:
    case GSS_S_BAD_NAME:
    case GSS_S_BAD_NAMETYPE:
    case GSS_S_BAD_BINDINGS:
    case GSS_S_BAD_STATUS:
    case GSS_S_NO_CONTEXT:
    case GSS_S_DEFECTIVE_TOKEN:
    case GSS_S_FAILURE:
    case GSS_S_BAD_QOP:
    default:
        status = PAM_SERVICE_ERR;
        break;
    }

    return status;
}

static void
pamGssCleanupMech(pam_handle_t *pamh, void *data, int error_status)
{
#ifndef HAVE_HEIMDAL_VERSION
    OM_uint32 minor;

    gss_release_oid(&minor, (gss_OID *)&data);
#endif
}

static void
pamGssCleanupCred(pam_handle_t *pamh, void *data, int error_status)
{
    OM_uint32 minor;

    gss_release_cred(&minor, (gss_cred_id_t *)&data);
}

static void
pamGssCleanupName(pam_handle_t *pamh, void *data, int error_status)
{
    OM_uint32 minor;

    gss_release_name(&minor, (gss_name_t *)&data);
}

static int
readConfFlags(int argc, const char **argv)
{
    int i, confFlags = 0;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "use_first_pass") == 0)
            confFlags |= FLAG_USE_FIRST_PASS;
        else if (strcmp(argv[i], "try_first_pass") == 0)
            confFlags |= FLAG_TRY_FIRST_PASS;
        else if (strcmp(argv[i], "ignore_unknown_user") == 0)
            confFlags |= FLAG_IGNORE_UNKNOWN_USER;
        else if (strcmp(argv[i], "ignore_authinfo_unavail") == 0)
            confFlags |= FLAG_IGNORE_AUTHINFO_UNAVAIL;
        else if (strcmp(argv[i], "no_warn") == 0)
            confFlags |= FLAG_NO_WARN;
        else if (strcmp(argv[i], "nullok") == 0)
            confFlags |= FLAG_NULLOK;
        else if (strcmp(argv[i], "debug") == 0)
            confFlags |= FLAG_DEBUG;
    }

    return confFlags;
}

static int
pamGssInitAcceptSecContext(pam_handle_t *pamh,
                           int confFlags,
                           gss_cred_id_t cred,
                           gss_cred_id_t acceptorCred,
                           gss_name_t hostName,
                           gss_OID mech)
{
    int status;
    OM_uint32 major, minor;
    gss_buffer_desc initiatorToken = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc acceptorToken = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t initiatorContext = GSS_C_NO_CONTEXT;
    gss_ctx_id_t acceptorContext = GSS_C_NO_CONTEXT;
    gss_buffer_desc canonUserNameBuf = GSS_C_EMPTY_BUFFER;
    gss_name_t canonUserName = GSS_C_NO_NAME;
    gss_OID canonMech = GSS_C_NO_OID;
    OM_uint32 gssFlags;

    do {
        major = gss_init_sec_context(&minor, cred, &initiatorContext,
                                     hostName, mech, GSS_C_MUTUAL_FLAG,
                                     GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS,
                                     &acceptorToken, NULL, &initiatorToken, &gssFlags, NULL);
        gss_release_buffer(&minor, &acceptorToken);

#ifdef GSS_S_PROMPTING_NEEDED
        if (major == GSS_S_PROMPTING_NEEDED) {
            status = PAM_CRED_INSUFFICIENT;
            goto cleanup;
        }
#endif

        BAIL_ON_GSS_ERROR(major, minor);

        if (initiatorToken.length != 0) {
            major = gss_accept_sec_context(&minor, &acceptorContext, acceptorCred,
                                           &initiatorToken, GSS_C_NO_CHANNEL_BINDINGS,
                                           &canonUserName, &canonMech, &acceptorToken,
                                           NULL, NULL, NULL);
            gss_release_buffer(&minor, &initiatorToken);
        }

        BAIL_ON_GSS_ERROR(major, minor);
    } while (major == GSS_S_CONTINUE_NEEDED);

    BAIL_ON_GSS_ERROR(major, minor);

    if ((gssFlags & GSS_C_MUTUAL_FLAG) == 0) {
        status = PAM_PERM_DENIED;
        goto cleanup;
    }

#ifndef __APPLE__
    major = gss_localname(&minor, canonUserName, GSS_C_NO_OID, &canonUserNameBuf);
    if (major == GSS_S_COMPLETE) {
        status = pam_set_item(pamh, PAM_USER, canonUserNameBuf.value);
        BAIL_ON_PAM_ERROR(status);
    } else if (major != GSS_S_UNAVAILABLE)
        goto cleanup;
#endif

    status = pam_set_data(pamh, GSS_NAME_DATA, canonUserName, pamGssCleanupName);
    BAIL_ON_PAM_ERROR(status);

    canonUserName = GSS_C_NO_NAME;

    status = pam_set_data(pamh, GSS_MECH_DATA, canonMech, pamGssCleanupMech);
    BAIL_ON_PAM_ERROR(status);

    canonMech = GSS_C_NO_OID;

    status = PAM_SUCCESS;

cleanup:
    gss_release_name(&minor, &canonUserName);
    gss_release_buffer(&minor, &initiatorToken);
    gss_release_buffer(&minor, &acceptorToken);
    gss_delete_sec_context(&minor, &initiatorContext, NULL);
    gss_delete_sec_context(&minor, &acceptorContext, NULL);
    gss_release_buffer(&minor, &canonUserNameBuf);

    if (IGNORE_ERR_P(status, confFlags))
        status = PAM_IGNORE;

    return status;
}

#ifdef __APPLE__
static void
pamGssMapAttribute(const void *key, const void *value, void *context)
{       
    CFMutableDictionaryRef mappedAttrs = (CFMutableDictionaryRef)context;
    CFStringRef mappedKey;

    if (CFEqual(key, CFSTR("kCUIAttrCredentialSecIdentity"))) {
        mappedKey = CFRetain(kGSSICCertificate);
    } else {
        mappedKey = CFStringCreateMutableCopy(kCFAllocatorDefault, 0, (CFStringRef)key);
        if (mappedKey == NULL)
            return;

        /* Map CredUI credential to something for gss_aapl_initial_cred */
        CFStringFindAndReplace((CFMutableStringRef)mappedKey,
                               CFSTR("kCUIAttrCredential"),
                               CFSTR("kGSSIC"),
                               CFRangeMake(0, CFStringGetLength(mappedKey)),
                               0);
    }

    CFDictionarySetValue(mappedAttrs, mappedKey, value);
    CFRelease(mappedKey);
}

static int
pamGssAcquireAaplInitialCred(pam_handle_t *pamh,
                             gss_name_t userName,
                             gss_OID mech,
                             CFDictionaryRef attributes,
                             gss_cred_id_t *cred)
{
    CFMutableDictionaryRef mappedAttrs;
    OM_uint32 major;

    mappedAttrs = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                            CFDictionaryGetCount(attributes),
                                            &kCFTypeDictionaryKeyCallBacks,
                                            &kCFTypeDictionaryValueCallBacks);
    if (mappedAttrs == NULL)
        return PAM_BUF_ERR;

    CFDictionaryApplyFunction(attributes, pamGssMapAttribute, (void *)mappedAttrs);

    major = gss_aapl_initial_cred(userName, mech, mappedAttrs, cred, NULL);

    CFRelease(mappedAttrs);

    return pamGssMapStatus(major, 0);
}
#endif /* __APPLE__ */

static int
pamGssAcquireCred(pam_handle_t *pamh,
                  int confFlags,
                  gss_name_t userName,
                  gss_buffer_t passwordBuf,
                  gss_OID mech,
                  gss_cred_id_t *cred)
{
    int status;
    OM_uint32 major, minor;
    gss_OID_set_desc mechOids;
#ifdef __APPLE__
    CFDictionaryRef attributes = NULL;

    status = pam_get_data(pamh, CREDUI_ATTR_DATA, (const void **)&attributes);
    if (status == PAM_SUCCESS)
        return pamGssAcquireAaplInitialCred(pamh, userName, mech, attributes, cred);
#endif /* __APPLE__ */

    mechOids.count = 1;
    mechOids.elements = mech;

    major = gss_acquire_cred_with_password(&minor, userName, passwordBuf,
                                           GSS_C_INDEFINITE, &mechOids,
                                           GSS_C_INITIATE, cred, NULL, NULL);
    BAIL_ON_GSS_ERROR(major, minor);

    status = PAM_SUCCESS;

cleanup:
    return status;
}

static int
pamGssGetAuthTok(pam_handle_t *pamh,
                 int confFlags,
                 gss_buffer_t passwordBuf)
{
    int status;
    struct pam_conv *conv;
    struct pam_message msg;
    const struct pam_message *msgp;
    struct pam_response *resp;

    status = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    BAIL_ON_PAM_ERROR(status);

    if (conv == NULL) {
        status = PAM_CONV_ERR;
        goto cleanup;
    }

    msg.msg_style = PAM_PROMPT_ECHO_OFF;
    msg.msg = PASSWORD_PROMPT;
    msgp = &msg;
    resp = NULL;

    status = (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr);

    if (resp != NULL) {
        if (status == PAM_SUCCESS)
            passwordBuf->value = resp->resp;
        else
            free(resp->resp);
        free(resp);
    }

    passwordBuf->length = passwordBuf->value ? strlen((char *)passwordBuf->value) : 0;
    if (passwordBuf->length == 0 && (confFlags & FLAG_NULLOK) == 0) {
        status = PAM_AUTH_ERR;
        goto cleanup;
    }

cleanup:
    return status;
}

static int
readConfMechOid(int argc,
                const char **argv,
                gss_OID *mech)
{
    int i;
    OM_uint32 major, minor;
    const char *oidstr = NULL;
#ifndef __APPLE__
    size_t oidstrLen;
    gss_buffer_desc oidBuf;
    char *p;
#endif

    for (i = 0; i < argc; i++) {
        if (strncmp(argv[i], "mech=", 5) != 0)
            continue;

        oidstr = &argv[i][5];
        break;
    }

    if (oidstr == NULL)
        return PAM_SUCCESS;

#ifdef __APPLE__
    char mechbuf[64];
    size_t mech_len;
    heim_oid heimOid;
    int ret;
    
    if (der_parse_heim_oid(oidstr, " .", &heimOid))
        return PAM_SERVICE_ERR;
    
    ret = der_put_oid((unsigned char *)mechbuf + sizeof(mechbuf) - 1,
                      sizeof(mechbuf),
                      &heimOid,
                      &mech_len);
    if (ret) {
        der_free_oid(&heimOid);
        return PAM_SERVICE_ERR;
    }

    *mech = (gss_OID)malloc(sizeof(gss_OID_desc));
    if (*mech == NULL) {
        der_free_oid(&heimOid);
        return PAM_BUF_ERR;
    }
    
    (*mech)->elements = malloc(mech_len);
    if ((*mech)->elements == NULL) {
        der_free_oid(&heimOid);
        free(*mech);
        *mech = NULL;
        return PAM_BUF_ERR;
    }

    (*mech)->length = mech_len;
    memcpy((*mech)->elements, mechbuf + sizeof(mechbuf) - mech_len, mech_len);

    der_free_oid(&heimOid);

    major = GSS_S_COMPLETE;
    minor = 0;
#else
    oidstrLen = strlen(oidstr);

    oidBuf.length = 2 + oidstrLen + 2;
    oidBuf.value = malloc(oidBuf.length + 1);
    if (oidBuf.value == NULL)
        return PAM_BUF_ERR;

    p = (char *)oidBuf.value;
    *p++ = '{';
    *p++ = ' ';
    for (i = 0; i < oidstrLen; i++)
        *p++ = oidstr[i] == '.' ? ' ' : oidstr[i];
    *p++ = ' ';
    *p++ = '}';
    *p = '\0';

    assert(oidBuf.length == p - (char *)oidBuf.value);

    major = gss_str_to_oid(&minor, &oidBuf, mech);

    free(oidBuf.value);
#endif

    return pamGssMapStatus(major, minor);
}

int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int status, confFlags = 0;
    char hostNameBufBuf[5 + MAXHOSTNAMELEN + 1] = "host@";
    int isConvPasswordBuf = 0;

    OM_uint32 major, minor;
    gss_buffer_desc userNameBuf = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc hostNameBuf = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc passwordBuf = GSS_C_EMPTY_BUFFER;
    gss_name_t userName = GSS_C_NO_NAME;
    gss_name_t hostName = GSS_C_NO_NAME;
    gss_cred_id_t initiatorCred = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t acceptorCred = GSS_C_NO_CREDENTIAL;
    gss_OID mech = &gss_spnego_mechanism_oid_desc;
    gss_OID_set_desc mechOids;

    confFlags = readConfFlags(argc, argv);

    status = readConfMechOid(argc, argv, &mech);
    BAIL_ON_PAM_ERROR(status);

    if (flags & PAM_DISALLOW_NULL_AUTHTOK)
        confFlags &= ~(FLAG_NULLOK);

    status = pam_get_user(pamh, (void *)&userNameBuf.value, NULL);
    BAIL_ON_PAM_ERROR(status);

    userNameBuf.length = strlen((char *)userNameBuf.value);

    major = gss_import_name(&minor, &userNameBuf, GSS_C_NT_USER_NAME, &userName);
    BAIL_ON_GSS_ERROR(major, minor);

    if (gethostname(&hostNameBufBuf[5], MAXHOSTNAMELEN) != 0) {
        status = PAM_SYSTEM_ERR;
        goto cleanup;
    }

    hostNameBuf.length = strlen(hostNameBufBuf);
    hostNameBuf.value = hostNameBufBuf;

    major = gss_import_name(&minor, &hostNameBuf, GSS_C_NT_HOSTBASED_SERVICE, &hostName);
    BAIL_ON_GSS_ERROR(major, minor);

    mechOids.count = 1;
    mechOids.elements = mech;

    major = gss_acquire_cred(&minor, hostName, GSS_C_INDEFINITE, &mechOids,
                             GSS_C_ACCEPT, &acceptorCred, NULL, NULL);
    BAIL_ON_GSS_ERROR(major, minor);

    status = PAM_AUTHINFO_UNAVAIL;

    if (confFlags & (FLAG_USE_FIRST_PASS | FLAG_TRY_FIRST_PASS)) {
        status = pam_get_item(pamh, PAM_AUTHTOK, (void *)&passwordBuf.value);
        BAIL_ON_PAM_ERROR(status);

        if (passwordBuf.value != NULL)
            passwordBuf.length = strlen((char *)passwordBuf.value);

        status = pamGssAcquireCred(pamh, confFlags, userName, &passwordBuf,
                                   mech, &initiatorCred);
        if (status == PAM_SUCCESS)
            status = pamGssInitAcceptSecContext(pamh, confFlags, initiatorCred,
                                                acceptorCred, hostName, mech);
        if (confFlags & FLAG_USE_FIRST_PASS)
            BAIL_ON_PAM_ERROR(status);
    }

    if (status != PAM_SUCCESS) {
        isConvPasswordBuf = 1;

        if (flags & PAM_SILENT)
            goto cleanup;

        status = pamGssGetAuthTok(pamh, confFlags, &passwordBuf);
        BAIL_ON_PAM_ERROR(status);

        gss_release_cred(&minor, &initiatorCred);

        status = pamGssAcquireCred(pamh, confFlags, userName, &passwordBuf,
                                   mech, &initiatorCred);
        if (status == PAM_SUCCESS)
            status = pamGssInitAcceptSecContext(pamh, confFlags, initiatorCred,
                                                acceptorCred, hostName, mech);
        BAIL_ON_PAM_ERROR(status);
    }

    status = pam_set_data(pamh, GSS_CRED_DATA, initiatorCred, pamGssCleanupCred);
    BAIL_ON_PAM_ERROR(status);

    initiatorCred = GSS_C_NO_CREDENTIAL;

cleanup:
    gss_release_name(&minor, &userName);
    gss_release_name(&minor, &hostName);
    gss_release_cred(&minor, &initiatorCred);
    gss_release_cred(&minor, &acceptorCred);
#ifdef __APPLE__
    if (mech != &gss_spnego_mechanism_oid_desc)
        gss_release_oid(&minor, &mech);
#endif
    if (isConvPasswordBuf) {
        memset((char *)passwordBuf.value, 0, passwordBuf.length);
        free(passwordBuf.value);
    }

    return status;
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int status;
    gss_name_t canonUserName = GSS_C_NO_NAME;
    char *userName = NULL;

    status = pam_get_data(pamh, GSS_NAME_DATA, (const void **)&canonUserName);
    if (status != PAM_SUCCESS)
        return PAM_USER_UNKNOWN;

    status = pam_get_user(pamh, (void *)&userName, NULL);
    if (status != PAM_SUCCESS)
        return PAM_USER_UNKNOWN;

    return gss_userok(canonUserName, userName) ? PAM_SUCCESS : PAM_PERM_DENIED;

}

#ifndef __APPLE__
PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int status;
    OM_uint32 major, minor;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_OID mech = GSS_C_NO_OID;

    if (flags && (flags & PAM_ESTABLISH_CRED) == 0)
        return PAM_SUCCESS;

    status = pam_get_data(pamh, GSS_CRED_DATA, (const void **)&cred);
    BAIL_ON_PAM_ERROR(status);

    status = pam_get_data(pamh, GSS_MECH_DATA, (const void **)&mech);
    BAIL_ON_PAM_ERROR(status);

    major = gss_store_cred(&minor, cred, GSS_C_INITIATE, mech,
                           1, 1, NULL, NULL);
    BAIL_ON_GSS_ERROR(major, minor);

cleanup:
    return status;
}
#endif /* !__APPLE__ */
