# Generated automatically from Makefile.in by configure.
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
# The Original Code is Mozilla Communicator client code, released
# March 31, 1998.
# 
# The Initial Developer of the Original Code is
# Netscape Communications Corporation.
# Portions created by the Initial Developer are Copyright (C) 1998-1999
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

MOD_DEPTH = ../../..
srcdir = .
topsrcdir = ../../..

include $(MOD_DEPTH)/config/autoconf.mk
include $(topsrcdir)/build.mk

SRCS		= line64.c

RELEASE_LIBS    = $(SHARED_LIBRARY) $(DLLLDIF)

REALOBJS	= $(SRCS:.c=.$(OBJ_SUFFIX))
OBJS		= $(addprefix $(OBJDIR_NAME)/, $(REALOBJS))

HDIR		= $(topsrcdir)/ldap/include

LIBLDIF		= $(addprefix $(OBJDIR_NAME)/, $(LIB_PREFIX)$(LDIF_LIBNAME).$(LIB_SUFFIX))
DLLLDIF         = $(addprefix $(OBJDIR_NAME)/, $(LIB_PREFIX)$(LDIF_LIBNAME).$(DLL_SUFFIX))

INSTALLDIR      = $(DIST)/$(OBJDIR_NAME)

include $(topsrcdir)/config/rules.mk

GARBAGE 	+= $(LIBLDIF) $(DLLLDIF)

LOCAL_INCLUDES  = -I$(PUBLIC)/nspr
INCLUDES	+= -I$(HDIR) -I$(INSTALLDIR)/include -I$(DIST)/include
DEFINES		+= $(DEFS)

PLATFORMCFLAGS	= -DUSE_WAITPID -DNEEDPROTOS
PLATFORMLIBS	=
THREADS		=
THREADSLIB	=

ifeq ($(OS_ARCH), AIX)
PLATFORMLIBS	+= -ldl -brtl -lpthreads -lc_r -lm
endif

#
# shared library symbol export definitions
#
ifeq ($(USE_DLL_EXPORTS_FILE), 1)
ifeq ($(OS_ARCH), WINNT)
GENEXPORTS=cmd /c  $(PERL) $(topsrcdir)/ldap/build/genexports.pl
else
GENEXPORTS=$(PERL) $(topsrcdir)/ldap/build/genexports.pl
endif

# variable definitions for exported symbols
ifeq ($(OS_ARCH), WINNT)
        LDIF_EXPORT_DEFS= $(WIN_TOP_SRC)/ldap/libraries/msdos/winsock/nsldif32.def
else
ifeq ($(OS_ARCH), OS2)
        LDIF_EXPORT_DEFS= $(OBJDIR_NAME)/libldif.def
else
        LDIF_EXPORT_DEFS= $(OBJDIR_NAME)/libldif.exp
endif
GARBAGE += $(LDIF_EXPORT_DEFS)
endif

LDIF_EXPORT_FLAGS=$(addprefix $(DLLEXPORTS_PREFIX), $(LDIF_EXPORT_DEFS))

GENEXPARGS=$(BUILD_DEBUG) $(LDIFVERS_SUFFIX) $(LDIFVERS)
endif # USE_DLL_EXPORTS_FILE


###########################################################################

ifeq ($(USE_DLL_EXPORTS_FILE), 1)
# recursive gmake rule to create exported symbols file
$(LDIF_EXPORT_DEFS):: $(srcdir)/../libldif.ex
ifeq ($(OS_ARCH), WINNT)
	$(GENEXPORTS) Win32 $(srcdir)/../msdos/winsock/nsldif32.tdf $< $(GENEXPARGS) > $@
else
ifeq ($(OS_ARCH), OS2)
	echo LIBRARY $(LDIF_LIBNAME) INITINSTANCE TERMINSTANCE > $@
	echo PROTMODE >> $@
	echo CODE    LOADONCALL MOVEABLE DISCARDABLE >> $@
	echo DATA    PRELOAD MOVEABLE MULTIPLE NONSHARED >> $@
	echo EXPORTS >> $@
	$(GENEXPORTS) $(OS_ARCH) Standard $< $(GENEXPARGS) >> $@
else
	$(GENEXPORTS) $(OS_ARCH) Standard $< $(GENEXPARGS) > $@
endif
endif
endif # USE_DLL_EXPORTS_FILE

versiont.c:	Makefile.client Version.c
	@$(RM) $@
	@(u="$${USER-root}" v="$(shell cat ../../build/version)" d="$(shell pwd)" \
	h="$(shell hostname)" t="$(shell date)"; $(SED) -e "s|%WHEN%|$${t}|" \
	-e "s|%WHOANDWHERE%|$${u}@$${h}:$${d}|" \
	-e "s|%VERSION%|$${v}|" \
	< Version.c > $@)

export::    $(OBJDEST) $(LIBDIR) $(OBJS) $(LIBLDIF)

$(LIBDIR):
	$(MKDIR) $(LIBDIR)

$(LIBLDIF): $(OBJS) $(LIBDIR)
	@echo ======= making $(LIBLDIF)

	$(LINK_LIB)

$(DLLLDIF): $(OBJS) $(LIBDIR) $(LDIF_EXPORT_DEFS)
	@echo ======= making $(DLLLDIF)

ifdef SO_FILES_TO_REMOVE
	-$(RM) $(SO_FILES_TO_REMOVE)
endif

	$(LINK_DLL) $(LDIF_EXPORT_FLAGS) $(PLATFORMLIBS) $(EXTRA_LIBS)


veryclean:: clean

$(OBJDEST):
	$(MKDIR) $(OBJDEST)

export::	$(DLLLDIF) $(LIBLDIF)
	$(INSTALL) -m 444 $(LIBLDIF) $(dist_libdir)

ifdef MKSHLIB
	$(INSTALL) -m 444 $(LIBLDIF) $(dist_libdir)
	$(INSTALL) -m 444 $(DLLLDIF) $(dist_libdir)
	$(INSTALL) -m 444 $(DLLLDIF) $(dist_bindir)
endif
