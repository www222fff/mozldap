# Generated automatically from Makefile.in by configure.
#! gmake
# 
# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
# 
# The contents of this file are subject to the Mozilla Public License Version 
# 1.1 (the "License"); you may not use this file except in compliance with 
# the License. You may obtain a copy of the License at 
# http://www.mozilla.org/MPL/
# 
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
# 
# The Original Code is the Netscape Portable Runtime (NSPR).
# 
# The Initial Developer of the Original Code is
# Netscape Communications Corporation.
# Portions created by the Initial Developer are Copyright (C) 1998-2000
# the Initial Developer. All Rights Reserved.
# 
# Contributor(s):
# 
# Alternatively, the contents of this file may be used under the terms of
# either of the GNU General Public License Version 2 or later (the "GPL"),
# or the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
# 
# ***** END LICENSE BLOCK ***** 

MOD_DEPTH	= ..
topsrcdir	= ..
srcdir		= .

include $(MOD_DEPTH)/config/autoconf.mk

# Indicate that this directory builds build tools.
INTERNAL_TOOLS	= 1

# autoconf.mk must be deleted last (from the top-level directory)
# because it is included by every makefile.
DIST_GARBAGE	= 

include $(topsrcdir)/config/config.mk

ifndef MOZILLA_CLIENT
CSRCS	= nsinstall.c 
endif

CSRCS	+= now.c

PLSRCS	= nfspwd.pl

ifeq (,$(CROSS_COMPILE)$(filter-out WINNT OS2,$(OS_ARCH)))
PROG_SUFFIX = .exe
else
PROG_SUFFIX =
endif

# Temporary workaround to disable the generation of
# library build time because now.c uses the 'long long'
# data type that's not available on some platforms.
ifeq (,$(filter-out NEC NEXTSTEP QNX SCOOS UNIXWARE,$(OS_ARCH)))
DEFINES += -DOMIT_LIB_BUILD_TIME
endif

ifeq ($(OS_ARCH), IRIX)
    ifeq ($(basename $(OS_RELEASE)),6)
	    ifeq ($(USE_N32),1)
		    XLDOPTS += -n32 -Wl,-woff,85
		    ifeq ($(OS_RELEASE), 6_2)
			    XLDOPTS += -Wl,-woff,85
		    endif
	    else
		    ifeq ($(USE_64),1)
			    XLDOPTS += -64
		    else
			    XLDOPTS += -32
		    endif
	    endif
    endif
endif

ifeq ($(OS_ARCH), HP-UX)
    ifeq ($(OS_RELEASE), B.11.23)
       ifeq ($(USE_64),1)
           XLDOPTS += +DD64
       else
           XLDOPTS += +DD32
       endif
    else
       ifeq ($(USE_64),1)
           XLDOPTS += +DA2.0W
       endif
	endif
endif

ifeq ($(OS_ARCH), OpenVMS)
    XLDOPTS += $(LDFLAGS)
endif

ifeq ($(MOZ_OS2_TOOLS),EMX)
XCFLAGS = $(OS_EXE_CFLAGS)
XLDOPTS = -Zomf -Zlinker -PM:VIO
endif

ifeq ($(MOZ_OS2_TOOLS),VACPP)
OS_CFLAGS = $(OS_EXE_CFLAGS)
endif

include $(topsrcdir)/config/rules.mk

PROGS	= $(OBJDIR)/now$(PROG_SUFFIX)

ifeq (,$(CROSS_COMPILE)$(filter-out WINNT OS2,$(OS_ARCH)))
TARGETS = $(PROGS)
else
PROGS	+= $(OBJDIR)/nsinstall$(PROG_SUFFIX)
TARGETS = $(PROGS) $(PLSRCS:.pl=)
endif

OUTOPTION = -o # end of the line
ifeq (,$(filter-out WINNT OS2,$(OS_ARCH)))
ifndef NS_USE_GCC
OUTOPTION = -Fe
endif
endif

# Redefine MAKE_OBJDIR for just this directory
define MAKE_OBJDIR
if test ! -d $(@D); then rm -rf $(@D); mkdir $(@D); else true; fi
endef

export:: $(TARGETS)

$(OBJDIR)/%$(PROG_SUFFIX): $(OBJDIR)/%.$(OBJ_SUFFIX)
	@$(MAKE_OBJDIR)
ifeq ($(MOZ_OS2_TOOLS),VACPP)
	$(LD) $(EXEFLAGS) $<
else
	$(CC) $(XCFLAGS) $< $(XLDOPTS) $(OUTOPTION)$@
endif
