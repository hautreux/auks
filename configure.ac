dnl Package initialisation
AC_INIT([auks],[0.5.0],[matthieu.hautreux@cea.fr])

dnl Auxiliary scripts directory
AC_CONFIG_AUX_DIR([build-aux])

dnl In-house m4 macro directory
AC_CONFIG_MACRO_DIR([m4])

dnl This is a GNU aimed project
AC_GNU_SOURCE

dnl Automake options
AM_INIT_AUTOMAKE([-Wall -Werror])

dnl Autoconf header file to generate
AC_CONFIG_HEADERS([config.h])

dnl In order to build lib using Autotools .la format
AC_PROG_LIBTOOL
m4_pattern_allow([AM_PROG_AR])
AM_PROG_AR

dnl This is a C project
AC_PROG_CC
AM_PROG_CC_C_O

dnl This project uses lex an yacc internaly
AC_PROG_LEX
AM_PROG_LEX
AC_PROG_YACC

dnl Look after SLURM resource manager
AX_SLURM

dnl Look for tirpc
AC_ARG_ENABLE(tirpc,
	[AC_HELP_STRING([--enable-tirpc],
			[enable use of TI-RPC @<:@default=yes@:>@])],
	enable_tirpc=$enableval,
	enable_tirpc='')
AC_LIBTIRPC

dnl Files to build during configure
AC_CONFIG_FILES([Makefile
		src/Makefile
		src/api/Makefile
		src/api/confparse/Makefile
		src/api/xternal/Makefile
		src/api/auks/Makefile
		src/auks/Makefile
		src/auksd/Makefile
		src/plugins/Makefile
		src/plugins/slurm/Makefile
		etc/init.d.auksd
		etc/init.d.auksdrenewer
		etc/init.d.aukspriv
		etc/auksd.service
		etc/auksdrenewer.service
		etc/aukspriv.service
		etc/Makefile
		doc/Makefile
		doc/man/Makefile])

dnl 
AC_OUTPUT
