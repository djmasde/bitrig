# $Id: Makefile.am,v 1.1 2013/06/17 19:11:45 robert Exp $

include $(top_srcdir)/Makefile.am.common

noinst_DATA = krb5.conf

check_SCRIPTS = $(SCRIPT_TESTS) 

SCRIPT_TESTS = check-kinit

TESTS = $(SCRIPT_TESTS)

port = 49188

do_subst = sed -e 's,[@]srcdir[@],$(srcdir),g' \
	-e 's,[@]port[@],$(port),g' \
	-e 's,[@]objdir[@],$(top_builddir)/tests/java,g'

LDADD = ../../lib/krb5/libkrb5.la $(LIB_roken)

check-kinit: check-kinit.in Makefile
	$(do_subst) < $(srcdir)/check-kinit.in > check-kinit.tmp
	chmod +x check-kinit.tmp
	mv check-kinit.tmp check-kinit

krb5.conf: krb5.conf.in Makefile
	$(do_subst) < $(srcdir)/krb5.conf.in > krb5.conf.tmp
	mv krb5.conf.tmp krb5.conf

CLEANFILES= \
	$(TESTS) \
	*.tmp \
	*.class \
	current-db* \
	krb5.conf \
	messages.log


EXTRA_DIST = \
	NTMakefile \
	KerberosInit.java \
	jaas.conf \
	check-kinit.in \
	have-java.sh \
	krb5.conf.in
