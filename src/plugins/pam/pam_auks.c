
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <stdlib.h>

#include "auks/auks_error.h"
#include "auks/auks_api.h"

#define PAM_SM_SESSION

#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#define USE_AUKS_API
#ifdef USE_AUKS_CLI
#ifndef BINDIR 
#define BINDIR "/usr/local/bin"
#endif

#define AUKS BINDIR "/" "auks"
#endif

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
	struct passwd *pw = NULL, pw_s;
	const char *user = NULL;
	char **envp = NULL;
	char buffer[1024];
	int ret, status;
	char *ccache = NULL;
	pid_t pid;
	int fstatus;
	auks_engine_t engine;

	ccache = (char *) pam_getenv(pamh, "KRB5CCNAME");
	if (!ccache) {
		pam_info(pamh, "pam_auks: KRB5CCNAME not found\n");
		return PAM_IGNORE;
	}
	ret = pam_get_user(pamh, &user, NULL);
	if (ret != PAM_SUCCESS || user == NULL) {
		pam_info(pamh, "pam_auks: user not found\n");
		return PAM_IGNORE;
	}

	ret = getpwnam_r(user, &pw_s, buffer, sizeof(buffer), &pw);
	if (ret != 0 || pw == NULL || pw->pw_uid == 0) {
		return PAM_IGNORE;
	}
#ifdef USE_AUKS_CLI
	envp = pam_getenvlist(pamh);
	pam_info(pamh,
		"pam_auks: about to call auks for user %s(%d) with ccache %s\n",
		user, pw->pw_uid, ccache);
	pid = fork();
	if (pid < 0) {
		pam_error(pamh, "pam_auks: fork failed\n");
		return PAM_IGNORE;
	}
	if (pid > 0) {
		waitpid(pid, &status, 0);
		if (envp) free(envp);
	} else {
		char *auks_args[3] = { AUKS, "-a", NULL };

		setuid(pw->pw_uid);
		execve(AUKS, auks_args, envp);
	}
#else	/* AUKS API */
	/* load auks conf */
	seteuid(pw->pw_uid);
	setenv("KRB5CCNAME", ccache, 1);
	fstatus = auks_api_init(&engine, NULL);
	if ( fstatus != AUKS_SUCCESS ) {
		pam_error(pamh, "API init failed : %s", auks_strerror(fstatus));
		return PAM_IGNORE;
	}

	/* send credential to auks daemon */
	fstatus = auks_api_add_cred(&engine, ccache);

	if (fstatus != AUKS_SUCCESS) {
		pam_info(pamh, "cred forwarding failed : %s",
		      auks_strerror(fstatus));
	}
	else {
		pam_info(pamh, "cred forwarding succeed");
	}

	/* unload auks conf */
	auks_api_close(&engine);
	seteuid(getuid());
#endif
	return (PAM_SUCCESS);
}
 
PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv)
{
	return (PAM_SUCCESS);
}


