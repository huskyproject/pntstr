# PntStr make file
#
# $Id$
#

include ../huskymak.cfg

install:
	$(INSTALL) $(IBOPT) pntstr.pl $(BINDIR)

uninstall:
	-$(RM) $(RMOPT) $(BINDIR)$(DIRSEP)pntstr.pl
