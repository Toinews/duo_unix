/*
 * pam_duo.c
 *
 * Copyright (c) 2010 Duo Security
 * All rights reserved, all wrongs reversed.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

/* These #defines must be present according to PAM documentation. */
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

/* NetBSD PAM b0rkage (gnat 39313) */
#ifdef __NetBSD__
#define NO_STATIC_MODULES
#endif

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif
#ifdef HAVE_SECURITY_PAM_EXT_H
#include <security/pam_ext.h>   /* Linux-PAM */
#endif

/* OpenGroup RFC86.0 and XSSO specify no "const" on arguments */
#if defined(__LINUX_PAM__) || defined(OPENPAM)
# define duopam_const   const   /* LinuxPAM, OpenPAM */
#else
# define duopam_const           /* Solaris, HP-UX, AIX */
#endif

#include "util.h"
#include "duo.h"
#include "groupaccess.h"
#include "pam_extra.h"

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#ifndef DUO_PRIVSEP_USER
# define DUO_PRIVSEP_USER   "duo"
#endif
#define DUO_CONF        DUO_CONF_DIR "/pam_duo.conf"

static int
__ini_handler(void *u, const char *section, const char *name, const char *val)
{
    struct duo_config *cfg = (struct duo_config *)u;
    if (!duo_common_ini_handler(cfg, section, name, val)) {
        /* There are no options specific to pam_duo yet */
        duo_syslog(LOG_ERR, "Invalid pam_duo option: '%s'", name);
        return (0);
    }
    return (1);
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int pam_flags,
    int argc, const char *argv[])
{
    struct duo_config cfg;
    struct passwd *pw = NULL;
    struct in_addr addr;
    duo_t *duo = NULL;
    duo_auth_t auth = NULL;

    /*
     * Only variables that will be passed to a pam_* function
     * need to be marked as 'duopam_const char *', anything else
     * should be 'const char *'. This is because there are different
     * PAM implementations, some with the const qualifier, and some
     * without.
     */
    duopam_const char *ip = NULL, *service = NULL, *user = NULL;
    const char *config = NULL, *host = NULL;

    int i, pam_err, matched;

    /*
     * Handle a delimited GECOS field. E.g.
     *
     *     username:x:0:0:code1/code2/code3//textField/usergecosparsed:/username:/bin/bash
     *
     * Parse the username from the appropriate position in the GECOS field.
     */
    const char delimiter = '/';
    const unsigned int delimited_position = 5;

    duo_config_default(&cfg);

    /* Parse configuration */
    config = DUO_CONF;
    for (i = 0; i < argc; i++) {
        if (strncmp("conf=", argv[i], 5) == 0) {
            config = argv[i] + 5;
        } else if (strcmp("debug", argv[i]) == 0) {
            duo_debug = 1;
        } else {
            duo_syslog(LOG_ERR, "Invalid pam_duo option: '%s'",
                argv[i]);
            return (PAM_SERVICE_ERR);
        }
    }
    i = duo_parse_config(config, __ini_handler, &cfg);
    if (i == -2) {
        duo_syslog(LOG_ERR, "%s must be readable only by user 'root'",
            config);
        return (cfg.failmode == DUO_FAIL_SAFE ? PAM_SUCCESS : PAM_NO_MODULE_DATA);
    } else if (i == -1) {
        duo_syslog(LOG_ERR, "Couldn't open %s: %s",
            config, strerror(errno));
        return (cfg.failmode == DUO_FAIL_SAFE ? PAM_SUCCESS : PAM_NO_MODULE_DATA);
    } else if (i > 0) {
        duo_syslog(LOG_ERR, "Parse error in %s, line %d", config, i);
        return (cfg.failmode == DUO_FAIL_SAFE ? PAM_SUCCESS : PAM_NO_MODULE_DATA);
    } else if (!cfg.apihost || !cfg.apihost[0] ||
            !cfg.skey || !cfg.skey[0] || !cfg.ikey || !cfg.ikey[0]) {
        duo_syslog(LOG_ERR, "Missing host, ikey, or skey in %s", config);
        return (cfg.failmode == DUO_FAIL_SAFE ? PAM_SUCCESS : PAM_NO_MODULE_DATA);
    }

    /* Check user */
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS ||
        (pw = getpwnam(user)) == NULL) {
        duo_log(LOG_WARNING, "Unknown user.", user, "", "");
        pam_err = PAM_USER_UNKNOWN;
        goto cleanup;
    }
    /* XXX - Service-specific behavior */
    if (pam_get_item(pamh, PAM_SERVICE, (duopam_const void **)
        (duopam_const void *)&service) != PAM_SUCCESS) {
        duo_syslog(LOG_ERR, "Unknown error");
        pam_err = PAM_SERVICE_ERR;
        goto cleanup;
    }
    if (strcmp(service, "sshd") == 0) {
        /*
         * Disable incremental status reporting for sshd :-(
         * OpenSSH accumulates PAM_TEXT_INFO from modules to send in
         * an SSH_MSG_USERAUTH_BANNER post-auth, not real-time!
         */
        // flags |= DUO_FLAG_SYNC;
    } else if (strcmp(service, "su") == 0 || strcmp(service, "su-l") == 0) {
        /* Check calling user for Duo auth, just like sudo */
        if ((pw = getpwuid(getuid())) == NULL) {
            duo_log(LOG_WARNING, "Unknown user.", user, "", "");
            pam_err = PAM_USER_UNKNOWN;
            goto cleanup;
        }
        user = pw->pw_name;
    }

    /* Check group membership */
    matched = duo_check_groups(pw, cfg.groups, cfg.groups_cnt);
    if (matched == -1) {
        pam_err = PAM_SERVICE_ERR;
        goto cleanup;
    } else if (matched == 0) {
        pam_err = PAM_SUCCESS;
        goto cleanup;        
    }

    /* Use GECOS field if called for */
    if (cfg.send_gecos || cfg.gecos_parsed) {
        if (strlen(pw->pw_gecos) > 0) {
            if (cfg.gecos_parsed) {
                user = duo_split_at(pw->pw_gecos, delimiter, delimited_position);
                if (user == NULL || (strcmp(user, "") == 0)) {
                    duo_log(LOG_DEBUG, "Could not parse GECOS field", pw->pw_name, NULL, NULL);
                    user = pw->pw_name;
                }
            } else {
                user = pw->pw_gecos;
            }
        } else {
            duo_log(LOG_WARNING, "Empty GECOS field", pw->pw_name, NULL, NULL);
        }
    }

    /* Grab the remote host */
    pam_get_item(pamh, PAM_RHOST,
        (duopam_const void **)(duopam_const void *)&ip);
    host = ip;
    /* PAM is weird, check to see if PAM_RHOST is IP or hostname */
    if (ip == NULL) {
        ip = ""; /* XXX inet_addr needs a non-null IP */
    }
    if (!inet_aton(ip, &addr)) {
        /* We have a hostname, don't try to resolve, check fallback */
        if (cfg.local_ip_fallback) {
            host = duo_local_ip();
        }
    }

    /* Try Duo auth. */
    if ((duo = duo_init(cfg.apihost, cfg.ikey, cfg.skey,
                    "login_duo/" PACKAGE_VERSION,
                    cfg.noverify ? "" : cfg.cafile,
                    cfg.http_proxy)) == NULL) {
        duo_log(LOG_ERR, "Couldn't open Duo API handle",
            pw->pw_name, host, NULL);
        pam_err = PAM_SERVICE_ERR;
        goto cleanup;
    }

    auth = duo_auth_check(duo);
    if (auth == NULL || auth->stat != DUO_OK) {
        /* Duo endpoint not available. */
        pam_err = cfg.failmode == DUO_FAIL_SAFE ? PAM_SUCCESS : PAM_SERVICE_ERR;
        goto cleanup;
    }

    auth = duo_auth_free(auth);
    /* Perform preauth check */
    auth = duo_auth_preauth(duo, user);
    if (auth == NULL || auth->stat != DUO_OK) {
        /* Duo endpoint not available. */
        pam_err = cfg.failmode == DUO_FAIL_SAFE ? PAM_SUCCESS : PAM_SERVICE_ERR;
        goto cleanup;
    }

    if (strcmp(auth->ok.preauth.result, "allow") == 0) {
        /* No need to process to auth. User allowed to bypass */
        duo_log(LOG_WARNING, "Skipped Duo login", user, host, auth->ok.preauth.status_msg);
        pam_err = PAM_SUCCESS;
        goto cleanup;
    } else if (strcmp(auth->ok.preauth.result, "auth") == 0) {
        /* Handle auth device and factor here ?*/
        ;
    } else {
        /* enroll or deny, deny access */
        duo_log(LOG_WARNING, "User not allowed to login.", user, host, auth->ok.preauth.status_msg);
        pam_err = PAM_PERM_DENIED;
        goto cleanup;
    }

    pam_err = PAM_PERM_DENIED;

    for (i = 0; i < cfg.prompts; i++) {
        if (auth) {
            auth = duo_auth_free(auth);
        }

        auth = duo_auth_auth(duo, user, "push", NULL, NULL);
        if (auth == NULL || auth->stat != DUO_OK) {
            /* Something went wrong with server and/or request */
            pam_err = PAM_SERVICE_ERR;
            break;
        }
        if (strcmp(auth->ok.auth.result, "allow") == 0) {
            duo_log(LOG_INFO, "Successful Duo login.", user, host, auth->ok.auth.status_msg);
            pam_err = PAM_SUCCESS;
            break;
        }
        else if (strcmp(auth->ok.auth.status, "fraud") == 0) {
                /* Fraud detected. Report and do not continue with login */
                duo_log(LOG_WARNING, "Aborted fraudulent Duo login. Incident reported.",
                    user, host, auth->ok.preauth.status_msg);
                pam_err = PAM_ABORT;
                break;
        } else {
            /* Try again */
            duo_log(LOG_WARNING, "Denied Duo login.", user, host, auth->ok.auth.status_msg);
        }
    }
    if (i == MAX_PROMPTS) {
        pam_err = PAM_MAXTRIES;
    }

cleanup:
    if (auth)
        auth = duo_auth_free(auth);
    if (duo)
        duo = duo_close(duo);
    close_config(&cfg);
    
    return pam_err;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
    return (PAM_SERVICE_ERR);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_duo");
#endif
