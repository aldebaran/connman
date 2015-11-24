# configmake.m4 serial 2
dnl Copyright (C) 2010-2015 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

# gl_CONFIGMAKE_PREP
# ------------------
AC_DEFUN([gl_CONFIGMAKE_PREP],
[
  dnl Added in autoconf 2.70
  if test "x$runstatedir" = x; then
    AC_SUBST([runstatedir], ['${localstatedir}/run'])
  fi
])
