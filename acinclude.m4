AC_DEFUN([AC_PROG_CC_PIE], [
	AC_CACHE_CHECK([whether ${CC-cc} accepts -fPIE], ac_cv_prog_cc_pie, [
		echo 'void f(){}' > conftest.c
		if test -z "`${CC-cc} -fPIE -pie -c conftest.c 2>&1`"; then
			ac_cv_prog_cc_pie=yes
		else
			ac_cv_prog_cc_pie=no
		fi
		rm -rf conftest*
	])
])

AC_DEFUN([COMPILER_FLAGS], [
	if (test "${CFLAGS}" = ""); then
		CFLAGS="-Wall -O2 -D_FORTIFY_SOURCE=2"
	fi
	if (test "$USE_MAINTAINER_MODE" = "yes"); then
		CFLAGS+=" -Werror -Wextra"
		CFLAGS+=" -Wno-unused-parameter"
		CFLAGS+=" -Wno-missing-field-initializers"
		CFLAGS+=" -Wdeclaration-after-statement"
		CFLAGS+=" -Wmissing-declarations"
		CFLAGS+=" -Wredundant-decls"
		CFLAGS+=" -Wcast-align"
	fi
])

AC_DEFUN([SHAVE_ARG_ENABLE],
[
  AC_ARG_ENABLE([shave],
    AS_HELP_STRING(
      [--enable-shave],
      [use shave to make the build pretty [[default=no]]]),,
      [enable_shave=no]
    )
  AC_CONFIG_FILES(shave shave-libtool)
])

AC_DEFUN([SHAVE_INIT],
[
  if test x"$enable_shave" = xyes; then
    dnl where can we find the shave scripts?
    m4_if([$1],,
      [shavedir="$ac_pwd"],
      [shavedir="$ac_pwd/$1"])
    AC_SUBST(shavedir)

    dnl make is now quiet
    AC_SUBST([MAKEFLAGS], [-s])
    AC_SUBST([AM_MAKEFLAGS], ['`test -z $V && echo -s`'])

    dnl we need sed
    AC_CHECK_PROG(SED,sed,sed,false)

    dnl substitute libtool
    SHAVE_SAVED_LIBTOOL=$LIBTOOL
    LIBTOOL="${SHELL} ${shavedir}/shave-libtool '${SHAVE_SAVED_LIBTOOL}'"
    AC_SUBST(LIBTOOL)

    dnl substitute cc/cxx
    SHAVE_SAVED_CC=$CC
    SHAVE_SAVED_CXX=$CXX
    SHAVE_SAVED_FC=$FC
    SHAVE_SAVED_F77=$F77
    CC="${SHELL} ${shavedir}/shave cc ${SHAVE_SAVED_CC}"
    CXX="${SHELL} ${shavedir}/shave cxx ${SHAVE_SAVED_CXX}"
    FC="${SHELL} ${shavedir}/shave fc ${SHAVE_SAVED_FC}"
    F77="${SHELL} ${shavedir}/shave f77 ${SHAVE_SAVED_F77}"
    AC_SUBST(CC)
    AC_SUBST(CXX)
    AC_SUBST(FC)
    AC_SUBST(F77)

    V=@
  else
    V=1
  fi
  Q='$(V:1=)'
  AC_SUBST(V)
  AC_SUBST(Q)
])

AC_DEFUN([GTK_DOC_CHECK],
[
  AC_BEFORE([AC_PROG_LIBTOOL],[$0])dnl setup libtool first
  AC_BEFORE([AM_PROG_LIBTOOL],[$0])dnl setup libtool first
  dnl for overriding the documentation installation directory
  AC_ARG_WITH([html-dir],
    AS_HELP_STRING([--with-html-dir=PATH], [path to installed docs]),,
    [with_html_dir='${datadir}/gtk-doc/html'])
  HTML_DIR="$with_html_dir"
  AC_SUBST([HTML_DIR])

  dnl enable/disable documentation building
  AC_ARG_ENABLE([gtk-doc],
    AS_HELP_STRING([--enable-gtk-doc],
                   [use gtk-doc to build documentation [[default=no]]]),,
    [enable_gtk_doc=no])

  if test x$enable_gtk_doc = xyes; then
    ifelse([$1],[],
      [PKG_CHECK_EXISTS([gtk-doc],,
                        AC_MSG_ERROR([gtk-doc not installed and --enable-gtk-doc requested]))],
      [PKG_CHECK_EXISTS([gtk-doc >= $1],,
                        AC_MSG_ERROR([You need to have gtk-doc >= $1 installed to build gtk-doc]))])
  fi

  AC_MSG_CHECKING([whether to build gtk-doc documentation])
  AC_MSG_RESULT($enable_gtk_doc)

  AC_PATH_PROGS(GTKDOC_CHECK,gtkdoc-check,)

  AM_CONDITIONAL([ENABLE_GTK_DOC], [test x$enable_gtk_doc = xyes])
  AM_CONDITIONAL([GTK_DOC_USE_LIBTOOL], [test -n "$LIBTOOL"])
])
