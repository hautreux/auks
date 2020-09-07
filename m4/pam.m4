
AC_DEFUN([AX_PAM],
[

	saved_CPPFLAGS="$CPPFLAGS"
	saved_LDFLAGS="$LDFLAGS"

	ac_have_pam=no

	AC_ARG_WITH(pam,
		AS_HELP_STRING(--with-pam@<:@=PATH@:>@,Specify PAM support and path),
		[ ac_have_pam=yes; PAMDIR="$withval" ]
	)
	AC_ARG_WITH(pam-lib,
		AS_HELP_STRING(--with-pam-lib@<:@=PATH@:>@,Specify PAM libraries path),
		[ PAMLIBDIR="$withval" ]
	)

	if test "x$ac_have_pam" == "xyes" ; then

		PAM_CPPFLAGS=
		PAM_LDFLAGS=

		dnl extend CPPFLAGS and LDFLAGS if required
		if test "x$PAMDIR" != "x" && test "x$PAMDIR" != "xyes" ; then
			PAM_CPPFLAGS="-I$PAMDIR/include"
			CPPFLAGS="${CPPFLAGS} ${PAM_CPPFLAGS}"
			PAM_LDFLAGS="-L$PAMDIR/lib"
                        LDFLAGS="$LDFLAGS $PAM_LDFLAGS"
		fi
		if test "x$PAMLIBDIR" != "x" && test "x$PAMLIBDIR" != "xyes"  ; then
			PAM_LDFLAGS="-L$PAMLIBDIR"
                        LDFLAGS="$LDFLAGS $PAM_LDFLAGS"
                fi
	fi

	CPPFLAGS="$saved_CPPFLAGS"
	LDFLAGS="$saved_LDFLAGS"

	AC_SUBST([PAM_CPPFLAGS])
	AC_SUBST([PAM_LDFLAGS])

	AM_CONDITIONAL(HAVE_PAM, test "x$ac_have_pam" = "xyes")
	AC_SUBST(HAVE_PAM)

])
