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
