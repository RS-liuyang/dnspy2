dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(dnspy2, 1.0)


AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE()

AC_PROG_CC

dnl Checks for libpcap
AC_MSG_CHECKING(for libpcap)
AC_ARG_WITH(libpcap,
[  --with-libpcap=DIR      use libpcap in DIR],
[ case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     AC_MSG_RESULT($withval)
     if test -f $withval/pcap.h -a -f $withval/libpcap.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
	PCAPINC="-I$withval -I$withval/bpf"
	PCAPLIB="-L$withval -lpcap"
     elif test -f $withval/include/pcap.h -a \
	       -f $withval/include/net/bpf.h -a \
	       -f $withval/lib/libpcap.a; then
	owd=`pwd`
	if cd $withval; then withval=`pwd`; cd $owd; fi
	PCAPINC="-I$withval/include"
	PCAPLIB="-L$withval/lib -lpcap"
     else
        AC_ERROR(pcap.h, net/bpf.h, or libpcap.a not found in $withval)
     fi
     ;;
  esac ],
[ if test -f ${prefix}/include/pcap.h; then
     PCAPINC="-I${prefix}/include"
     PCAPLIB="-L${prefix}/lib -lpcap"
  elif test -f /usr/include/pcap/pcap.h; then
     PCAPINC="-I/usr/include/pcap"
     PCAPLIB="-lpcap"
  elif test -f /usr/include/pcap.h; then
     PCAPLIB="-lpcap"
  else
     AC_MSG_RESULT(no)
     AC_ERROR(libpcap not found)
  fi
  AC_MSG_RESULT(yes) ]
)
AC_SUBST(PCAPINC)
AC_SUBST(PCAPLIB)

dnl Checks for libunbound
AC_MSG_CHECKING(for libunbound)
AC_ARG_WITH(libunbound,
[  --with-libunbound=DIR      use libunbound in DIR],
[ case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     AC_MSG_RESULT($withval)
     if test -f $withval/unbound.h -a -f $withval/libunbound.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
	UNBOUNDINC="-I$withval"
	UNBOUNDLIB="-L$withval -lunbound"
     elif test -f $withval/include/unbound.h -a \
	       -f $withval/lib/libunbound.a; then
	owd=`pwd`
	if cd $withval; then withval=`pwd`; cd $owd; fi
	UNBOUNDINC="-I$withval/include"
	UNBOUNDLIB="-L$withval/lib -lunbound"
     else
        AC_ERROR(unbound.h, or libunbound.a not found in $withval)
     fi
     ;;
  esac ],
[ if test -f ${prefix}/include/unbound.h; then
     UNBOUNDINC="-I${prefix}/include"
     UNBOUNDLIB="-L${prefix}/lib -lunbound"
  elif test -f /usr/include/unbound.h; then
     UNBOUNDLIB="-lunbound"
  else
     AC_MSG_RESULT(no)
     AC_ERROR(libunbound not found)
  fi
  AC_MSG_RESULT(yes) ]
)
AC_SUBST(UNBOUNDINC)
AC_SUBST(UNBOUNDLIB)

dnl Checks for libnet
AC_MSG_CHECKING(for libnet)
AC_ARG_WITH(libnet,
[  --with-libnet=DIR       use libnet in DIR],
[ case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     AC_MSG_RESULT($withval)
     if test -f $withval/include/libnet.h -a -f $withval/lib/libnet.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
	if test -f $withval/bin/libnet-config; then
	   CFLAGS="$CFLAGS `$withval/bin/libnet-config --defines`"
	elif test -f $withval/libnet-config; then
	   CFLAGS="$CFLAGS `$withval/libnet-config --defines`"
	else
	   CFLAGS="$CFLAGS `libnet-config --defines`"
	fi
	LNETINC="-I$withval/include"
	LNETLIB="-L$withval/lib -lnet"
     else
        AC_ERROR(libnet.h or libnet.a not found in $withval)
     fi
     ;;
  esac ],
[ if test -f ${prefix}/include/libnet.h; then
     CFLAGS="$CFLAGS `${prefix}/bin/libnet-config --defines`"
     LNETINC="-I${prefix}/include"
     LNETLIB="-L${prefix}/lib -lnet"
  elif test -f /usr/include/libnet.h; then
     CFLAGS="$CFLAGS `libnet-config --defines`"
     LNETLIB="-lnet"
  else
     AC_MSG_RESULT(no)
     AC_ERROR(libnet not found)
  fi
  AC_MSG_RESULT(yes) ]
)
AC_SUBST(LNETINC)
AC_SUBST(LNETLIB)

AC_CHECK_FUNCS(sigignore)

dnl Check whether the user's system supports pthread
AC_SEARCH_LIBS(pthread_create, pthread)
if test "x$ac_cv_search_pthread_create" = "xno"; then
  AC_MSG_ERROR([Can't enable threads without the POSIX thread library.])
fi

AC_CHECK_LIB(resolv, dn_expand)

AC_CONFIG_FILES(Makefile src/Makefile)
AC_OUTPUT
