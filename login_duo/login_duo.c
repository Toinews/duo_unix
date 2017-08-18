/*
 * login_duo.c
 *
 * Copyright (c) 2010 Duo Security
 * All rights reserved, all wrongs reversed.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "util.h"
#include "duo.h"

/* Which shell should we use by default if there's not one provided by getpwuid(3)? */
#ifndef _DEFAULT_SHELL
#define _DEFAULT_SHELL "/bin/sh"
#endif

#ifndef DUO_PRIVSEP_USER
#define DUO_PRIVSEP_USER    "duo"
#endif
#define DUO_CONF        DUO_CONF_DIR "/login_duo.conf"
#define MOTD_FILE       "/etc/motd"

struct login_ctx {
    const char  *config;
    const char  *duouser;
    const char  *host;
    uid_t        uid;
};

static void
die(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
    exit(EXIT_FAILURE);
}


static int
__ini_handler(void *u, const char *section, const char *name, const char *val)
{
    struct duo_config *cfg = (struct duo_config *)u;
    if (!duo_common_ini_handler(cfg, section, name, val)) {
        /* Extra login_duo options */
        if (strcmp(name, "motd") == 0) {
            cfg->motd = duo_set_boolean_option(val);
        } else {
            fprintf(stderr, "Invalid login_duo option: '%s'\n", name);
            return (0);
        }
    }
    return (1);
}

static int
drop_privs(uid_t uid, gid_t gid)
{
    if (setgid(gid) < 0) {
        return (-1);
    }
    if (setuid(uid) < 0) {
        return (-1);
    }
    if (getgid() != gid || getuid() != uid) {
        return (-1);
    }
    return (0);
}

static int
do_auth(struct login_ctx *ctx, const char *cmd)
{
    struct duo_config cfg;
    struct passwd *pw;
    struct in_addr addr;
    duo_t *duo;
    const char *config, *duouser;
    const char *ip, *host = NULL;
    char buf[64];
    int i, ret, prompts, matched;
    duo_auth_t preauth =NULL, auth = NULL;
    struct duo_factor *f = NULL;
    char *factor = NULL;

    /*
     * Handle a delimited GECOS field. E.g.
     *
     *     username:x:0:0:code1/code2/code3//textField/usergecosparsed:/username:/bin/bash
     *
     * Parse the username from the appropriate position in the GECOS field.
     */
    const char delimiter = '/';
    const unsigned int delimited_position = 5;

    if ((pw = getpwuid(ctx->uid)) == NULL) {
        die("Who are you?");
    }

    duouser = ctx->duouser ? ctx->duouser : pw->pw_name;
    config = ctx->config ? ctx->config : DUO_CONF;

    duo_config_default(&cfg);

    /* Load our private config. */
    if ((i = duo_parse_config(config, __ini_handler, &cfg)) != 0 ||
            (!cfg.apihost || !cfg.apihost[0] || !cfg.skey || !cfg.skey[0] ||
                !cfg.ikey || !cfg.ikey[0])) {
        switch (i) {
        case -2:
            fprintf(stderr, "%s must be readable only by "
                "user '%s'\n", config, pw->pw_name);
            break;
        case -1:
            fprintf(stderr, "Couldn't open %s: %s\n",
                config, strerror(errno));
            break;
        case 0:
            fprintf(stderr, "Missing host, ikey, or skey in %s\n",
                config);
            break;
        default:
            fprintf(stderr, "Parse error in %s, line %d\n",
                config, i);
            break;
        }
        /* Implicit "safe" failmode for local configuration errors */
        if (cfg.failmode == DUO_FAIL_SAFE) {
            return (EXIT_SUCCESS);
        }
        return (EXIT_FAILURE);
    }
    prompts = cfg.prompts;
    /* Check group membership. */
    matched = duo_check_groups(pw, cfg.groups, cfg.groups_cnt);
    if (matched == -1) {
        close_config(&cfg);
        return (EXIT_FAILURE);
    } else if (matched == 0) {
        close_config(&cfg);
        return (EXIT_SUCCESS);
    }

    /* Use GECOS field if called for */
    if ((cfg.send_gecos || cfg.gecos_parsed) && !ctx->duouser) {
        if (strlen(pw->pw_gecos) > 0) {
            if (cfg.gecos_parsed) {
                duouser = duo_split_at(pw->pw_gecos, delimiter, delimited_position);
                if (duouser == NULL || (strcmp(duouser, "") == 0)) {
                    duo_log(LOG_DEBUG, "Could not parse GECOS field", pw->pw_name, NULL, NULL);
                    duouser = pw->pw_name;
                }
            } else {
                duouser = pw->pw_gecos;
            }
        } else {
            duo_log(LOG_WARNING, "Empty GECOS field", pw->pw_name, NULL, NULL);
        }
    }

    /* Check for remote login host */
    if ((host = ip = getenv("SSH_CONNECTION")) != NULL ||
        (host = ip = (char *)ctx->host) != NULL) {
        if (inet_aton(ip, &addr)) {
            strlcpy(buf, ip, sizeof(buf));
            ip = strtok(buf, " ");
            host = ip;
        } else {
            if (cfg.local_ip_fallback) {
                host = duo_local_ip();
            }
        }
    }

    /* Try Duo auth. */
    if ((duo = duo_init(cfg.apihost, cfg.ikey, cfg.skey,
                    "login_duo/" PACKAGE_VERSION,
                    cfg.noverify ? "" : cfg.cafile,
                    cfg.http_proxy)) == NULL) {
        duo_log(LOG_ERR, "Couldn't open Duo API handle",
            pw->pw_name, host, NULL);
        close_config(&cfg);
        return (EXIT_FAILURE);
    }

    auth = duo_auth_check(duo);
    if (auth == NULL || auth->stat != DUO_OK) {
        /* Duo endpoint not available. */
        if (auth)
            auth = duo_auth_free(auth);
        if (cfg.failmode == DUO_FAIL_SAFE) 
            return EXIT_SUCCESS;
        else
            return EXIT_FAILURE;

    }
    auth = duo_auth_free(auth);
    /* Perform preauth check */
    preauth = duo_auth_preauth(duo, duouser);
    if (preauth == NULL || preauth->stat != DUO_OK) {
        /* Duo endpoint not available. */
        duo_log(LOG_ERR, "Cannot Preauth user", duouser, host, preauth->ok.preauth.status_msg);
        ret = cfg.failmode == DUO_FAIL_SAFE ? EXIT_SUCCESS : EXIT_FAILURE;
        goto cleanup;
    }

    if (strcmp(preauth->ok.preauth.result, "allow") == 0) {
        /* No need to process to auth. User allowed to bypass */
        duo_log(LOG_WARNING, "Skipped Duo login", duouser, host, preauth->ok.preauth.status_msg);
        ret = EXIT_SUCCESS;
        goto cleanup;
    } else if (strcmp(preauth->ok.preauth.result, "auth") == 0) {
       ; /* We will handle this case later */
    } else {
        /* enroll or deny, deny access */
        duo_log(LOG_WARNING, "User not allowed to login.", duouser, host, preauth->ok.preauth.status_msg);
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    ret = EXIT_FAILURE;

    /* Perform Duo authentication */
    for (i = 0; i < prompts; i++) {
        if (auth) {
            auth = duo_auth_free(auth);
        }
        if (factor) {
            free(factor);
            factor = NULL;
        }

        if (!cfg.autopush)
        {
            while (factor == NULL) {
                /* Prompt for user input */
                printf("%s", preauth->ok.preauth.prompt.text);
                fflush(stdout);
                if (fgets(buf, sizeof(buf), stdin) == NULL) {
                        exit(1);
                }
                strtok(buf, "\r\n");
                for (i = 0; i < preauth->ok.preauth.prompt.factors_cnt; i++) {
                    f = &preauth->ok.preauth.prompt.factors[i];
                    if (strcmp(buf, f->option) == 0) {
                        factor = strdup(f->label);
                        break;
                    }
                }
                if (factor == NULL)
                    factor = strdup(buf);
            }
        }

        if (cfg.autopush) {
            auth = duo_auth_auth(duo, duouser, "push" , ip, NULL);
        } else {
            auth = duo_auth_auth(duo, duouser, "prompt" , ip, factor);
        }
        if (auth == NULL || auth->stat != DUO_OK) {
            /* Something went wrong with server and/or request */
            ret = EXIT_FAILURE;
            break;
        }
        if (strcmp(auth->ok.auth.result, "allow") == 0) {
            duo_log(LOG_INFO, "Successful Duo login.", duouser, host, auth->ok.auth.status_msg);
            ret = EXIT_FAILURE;
            break;
        }
        else if (strcmp(auth->ok.auth.status, "fraud") == 0) {
                /* Fraud detected. Report and do not continue with login */
                duo_log(LOG_WARNING, "Aborted fraudulent Duo login. Incident reported.",
                    duouser, host, auth->ok.preauth.status_msg);
                ret = EXIT_FAILURE;
                break;
        } else {
            /* Try again */
            duo_log(LOG_WARNING, "Denied Duo login.", duouser, host, auth->ok.auth.status_msg);
        }
    }

cleanup:
    if (factor) {
        free(factor);
        factor = NULL;
    }
    if (auth)
        auth = duo_auth_free(auth);
    if (preauth)
        auth = duo_auth_free(preauth);
    if (duo)
        duo = duo_close(duo);
    close_config(&cfg);
    return ret;
}

static char *
_argv_to_string(int argc, char *argv[])
{
    char *s;
    int i, j, n;

    for (n = i = 0; i < argc; i++) {
        n += strlen(argv[i]) + 1;
    }
    if (n <= 0 || (s = malloc(n)) == NULL) {
        return (NULL);
    }
    for (n = i = 0; i < argc; i++) {
        for (j = 0; argv[i][j] != '\0'; j++) {
            s[n++] = argv[i][j];
        }
        s[n++] = ' ';
    }
    s[--n] = '\0';

    return (s);
}

static void
do_exec(struct login_ctx *ctx, const char *cmd)
{
    struct passwd *pw;
    const char *shell0;
    char argv0[256];
    const char *user_shell;
    int n;

    if ((pw = getpwuid(ctx->uid)) == NULL) {
        die("Who are you?");
    }

    /* Check to see if we have a shell from getpwuid() */
    if (NULL == pw->pw_shell) {
      user_shell = _DEFAULT_SHELL; /* No shell so use the default. */
    } else {
      user_shell = pw->pw_shell; /* Use the shell provided by getpwuid() */
    }
    if ((shell0 = strrchr(user_shell, '/')) != NULL) {
        shell0++;
    } else {
        shell0 = user_shell;
    }
    if (cmd != NULL) {
        execl(user_shell, shell0, "-c", cmd, (char *)NULL);
    } else {
        n = snprintf(argv0, sizeof(argv0), "-%s", shell0);
        if (n == -1 || n >= sizeof(argv0)) {
            die("%s: Invalid argument", user_shell);
        }
        execl(user_shell, argv0, (char *)NULL);
    }
    die("%s: %s", user_shell, strerror(errno));
}

static char *
get_command(int argc, char *argv[])
{
    char *cmd;

    if (argc > 0) {
        if ((cmd = _argv_to_string(argc, argv)) == NULL) {
            die("error converting arguments to command");
        }
    } else {
        cmd = getenv("SSH_ORIGINAL_COMMAND");
    }
    return (cmd);
}

static void
version(void)
{
    die("login_duo " PACKAGE_VERSION);
}

static void
usage(void)
{
    die("Usage: login_duo [-v] [-c config] [-d] [-f duouser] [-h host] [prog [args...]]");
}

int
main(int argc, char *argv[])
{
    struct login_ctx ctx[1];
    struct passwd *pw;
    pid_t pid;
    int c, stat;
    pid_t wait_res;

    memset(ctx, 0, sizeof(ctx));

    while ((c = getopt(argc, argv, "vc:df:h:?")) != -1) {
        switch (c) {
        case 'v':
            version();
            break;
        case 'c':
            ctx->config = optarg;
            break;
        case 'd':
            duo_debug = 1;
            break;
        case 'f':
            ctx->duouser = optarg;
            break;
        case 'h':
            ctx->host = optarg;
            break;
        default:
            usage();
        }
    }
    argc -= optind;
    argv += optind;

    ctx->uid = getuid();

    if (geteuid() != ctx->uid) {
        /* Setuid-root operation protecting private config. */
        if (ctx->config != NULL || ctx->duouser != NULL) {
            die("Only root may specify -c or -f");
        }
        if ((pw = getpwnam(DUO_PRIVSEP_USER)) == NULL) {
            die("User '%s' not found", DUO_PRIVSEP_USER);
        }
        if ((pid = fork()) == 0) {
            /* Unprivileged auth child. */
            if (drop_privs(pw->pw_uid, pw->pw_gid) != 0) {
                die("couldn't drop privileges: %s",
                    strerror(errno));
            }
            exit(do_auth(ctx, get_command(argc, argv)));
        } else {
            /* Parent continues as user. */
            if (drop_privs(getuid(), getgid()) != 0) {
                die("couldn't drop privileges: %s",
                    strerror(errno));
            }
            /* Check auth child status. */
            while ((wait_res = waitpid(pid, &stat, 0)) == -1 &&
                    errno == EINTR) {
                ;
            }
            if (wait_res != pid) {
                die("waitpid: %s", strerror(errno));
            }
            if (WEXITSTATUS(stat) == 0) {
                do_exec(ctx, get_command(argc, argv));
            }
        }
    } else {
        char *cmd = get_command(argc, argv);

        /* Non-setuid root operation or running as root. */
        if (do_auth(ctx, cmd) == EXIT_SUCCESS) {
            do_exec(ctx, cmd);
        }
    }
    exit(EXIT_FAILURE);
}
