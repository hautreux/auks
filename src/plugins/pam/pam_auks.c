#include <pwd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/syslog.h>
#include <sys/types.h>
#include <unistd.h>

#define PAM_SM_SESSION
#include <security/_pam_macros.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>

#include "auks/auks_error.h"
#include "auks/auks_api.h"

static inline int
_seteuid (uid_t uid) {
#if defined(SYS_setresuid32)
	return syscall(SYS_setresuid32, -1, uid, -1);
#else
	return syscall(SYS_setresuid, -1, uid, -1);
#endif
}

static inline int
_setegid (gid_t gid) {
#if defined(SYS_setresgid32)
	return syscall(SYS_setresgid32, -1, gid, -1);
#else
	return syscall(SYS_setresgid, -1, gid, -1);
#endif
}

static void
_info (pam_handle_t *pamh, bool syslog, bool quiet, const char *fmt, ...)
{
	va_list args;
	char buf[256];

	if (quiet)
		return;

	va_start(args, fmt);
	if (syslog)
		pam_vsyslog(pamh, LOG_NOTICE, fmt, args);
	else {
		snprintf(buf, sizeof(buf), "pam_auks: %s", fmt);
		pam_vinfo(pamh, buf, args);
	}
	va_end(args);
}

static void
_error (pam_handle_t *pamh, bool syslog, const char *fmt, ...)
{
	va_list args;
	char buf[256];

	va_start(args, fmt);
	if (syslog)
		pam_vsyslog(pamh, LOG_ERR, fmt, args);
	else {
		snprintf(buf, sizeof(buf), "pam_auks: %s", fmt);
		pam_verror(pamh, buf, args);
        }
	va_end(args);
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t *pamh, int flags,
		     int argc, const char **argv)
{
	int rc = PAM_SESSION_ERR;
	bool syslog = false, quiet = false;
	struct passwd *pw;
	const char *username;
	int i, ret, fstatus;
	auks_engine_t engine;
	char *config, *ccache;

	for (i = 0; i < argc; i++) {
		if (strcmp (argv[i], "syslog") == 0)
			syslog = true;
		if (strcmp (argv[i], "quiet") == 0)
			quiet = true;
	}

	ret = pam_get_user(pamh, &username, "auks user");
	if (ret != PAM_SUCCESS)
		return ret;


	pw = pam_modutil_getpwnam(pamh, username);
	if (pw == NULL) {
		_error(pamh, syslog, "unable to look up user \"%s\"\n", username);
		return PAM_USER_UNKNOWN;
	}
	if (pw->pw_uid == 0)
		return PAM_IGNORE;

	if (_setegid (pw->pw_gid) < 0) {
		_error(pamh, syslog, "unable to change GID to %u temporarily\n", pw->pw_gid);
		goto out;
	}
	if (_seteuid (pw->pw_uid) < 0) {
		_error(pamh, syslog, "unable to change UID to %u temporarily\n", pw->pw_uid);
		goto out;
	}

	config = (char *) pam_getenv(pamh, "AUKS_CONF");
	ccache = (char *) pam_getenv(pamh, "KRB5CCNAME");

	fstatus = auks_api_init(&engine, config);
	if ( fstatus != AUKS_SUCCESS ) {
		_error(pamh, syslog, "could not initialize API: %s", auks_strerror(fstatus));
		goto out;
	}
	fstatus = auks_api_add_cred(&engine, ccache);
	if ( fstatus != AUKS_SUCCESS )
		_error(pamh, syslog, "credential forwarding failed: %s", auks_strerror(fstatus));
	else {
		rc = PAM_SUCCESS;
		_info(pamh, syslog, quiet, "credential forwarding succeeded");
	}
	auks_api_close(&engine);

out:
	_seteuid(getuid());
	_setegid(getgid());

	return rc;
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh, int flags,
		      int argc, const char **argv)
{
	return PAM_SUCCESS;
}
