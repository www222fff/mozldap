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

MOD_DEPTH 	= ../../..
srcdir		= .
topsrcdir	= ../../..
SASL_CFLAGS     = 
SASL_LIBS       =  
HAVE_SASL	= 

include $(MOD_DEPTH)/config/autoconf.mk
include $(topsrcdir)/build.mk

SRCS		= abandon.c \
		  add.c \
		  authzidctrl.c \
		  bind.c \
		  cache.c \
		  charray.c \
		  charset.c \
		  compare.c \
		  compat.c \
		  control.c \
		  countvalues.c \
		  delete.c \
		  disptmpl.c \
		  dsparse.c \
		  error.c \
		  extendop.c \
		  free.c \
		  freevalues.c \
		  friendly.c \
		  getattr.c \
		  getdn.c \
		  getdxbyname.c \
		  geteffectiverightsctrl.c \
		  getentry.c \
		  getfilter.c \
		  getoption.c \
		  getvalues.c \
		  memcache.c \
		  message.c \
		  modify.c \
		  open.c \
		  os-ip.c \
		  proxyauthctrl.c \
		  psearch.c \
		  pwmodext.c \
		  pwpctrl.c \
		  referral.c \
		  regex.c \
		  rename.c \
		  request.c \
		  reslist.c \
		  result.c \
		  saslbind.c \
		  sbind.c \
		  search.c \
		  setoption.c \
		  sort.c \
		  sortctrl.c \
		  srchpref.c \
		  tmplout.c \
		  ufn.c \
		  unbind.c \
		  unescape.c \
		  url.c \
		  userstatusctrl.c \
		  utf8.c \
		  vlistctrl.c \
		  whoami.c

ifeq ($(HAVE_SASL), 1)
SRCS		+= saslio.c
endif

ifeq ($(OS_ARCH),WINNT)
SRCS		+= dllmain.c \
                   mozock.c
endif
RELEASE_LIBS	= $(SHARED_LIBRARY) $(DLLLDAP)

REALOBJS	= $(SRCS:.c=.$(OBJ_SUFFIX))
OBJS		= $(addprefix $(OBJDIR_NAME)/, $(REALOBJS))

DISTHDIR	= $(DIST)/public/ldap
HDIR		= $(topsrcdir)/ldap/include

LIBLDAP		= $(addprefix $(OBJDIR_NAME)/, $(LIB_PREFIX)$(LDAP_LIBNAME).$(LIB_SUFFIX))
DLLLDAP		= $(addprefix $(OBJDIR_NAME)/, $(LIB_PREFIX)$(LDAP_LIBNAME).$(DLL_SUFFIX))

INSTALLDIR	= $(DIST)/$(OBJDIR_NAME)

include $(topsrcdir)/config/rules.mk

GARBAGE 	+= $(LIBLDAP) $(DLLLDAP)

LOCAL_INCLUDES  = -I$(PUBLIC)/nspr
INCLUDES	+= -I$(DISTHDIR) -I$(HDIR) -I$(INSTALLDIR)/public

ifeq ($(HAVE_SASL), 1)
INCLUDES        += $(SASL_CFLAGS)
endif

DEFINES		+= $(DEFS) -UMOZILLA_CLIENT

ifdef USE_PTHREADS
DEFINES   += -DUSE_PTHREADS
endif

ifeq ($(OS_ARCH),WINNT)
PLATFORMCFLAGS	= -DNEEDPROTOS
else
PLATFORMCFLAGS	= -DUSE_WAITPID -DNEEDPROTOS
endif
THREADS		=
THREADSLIB	=

ETCFILENAMES	= ldapfilter.conf \
		  ldapfriendly \
		  ldapsearchprefs.conf \
		  ldaptemplates.conf \
		  $(NULL)

ETCDIR		= $(INSTALLDIR)/etc
ETCFILES	= $(addprefix $(srcdir)/, $(ETCFILENAMES))

#
# if you want things to run in a different directory from where they
# are installed, set this accordingly (this path gets compiled into a
# few binaries). otherwise, leave it alone.
#
RUNTIMEETCDIR	= $(ETCDIR)

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
        LDAP_EXPORT_DEFS= $(WIN_TOP_SRC)/ldap/libraries/msdos/winsock/nsldap32.def
else
ifeq ($(OS_ARCH), OS2)
        LDAP_EXPORT_DEFS= $(OBJDIR_NAME)/libldap.def
else
        LDAP_EXPORT_DEFS= $(OBJDIR_NAME)/libldap.exp
endif
GARBAGE += $(LDAP_EXPORT_DEFS)
endif

LDAP_EXPORT_FLAGS=$(addprefix $(DLLEXPORTS_PREFIX), $(LDAP_EXPORT_DEFS))

GENEXPARGS=$(BUILD_DEBUG) $(LDAPVERS_SUFFIX) $(LDAPVERS)
endif # USE_DLL_EXPORTS_FILE

ifeq ($(OS_ARCH), SunOS)
EXTRA_LIBS = -L$(dist_libdir) -l$(LBER_LIBNAME)
endif

ifeq ($(OS_ARCH), IRIX)
EXTRA_LIBS = -L$(dist_libdir) -l$(LBER_LIBNAME) $(OS_LIBS) -lc
endif

ifeq ($(OS_ARCH), Linux)
EXTRA_LIBS = -L$(dist_libdir) -l$(LBER_LIBNAME)
endif

ifeq ($(OS_ARCH), WINNT)
ifdef NS_USE_GCC
EXTRA_DLL_LIBS=-L$(dist_libdir) -l$(LBER_LIBNAME)
else
EXTRA_LIBS =wsock32.lib kernel32.lib user32.lib gdi32.lib winspool.lib \
            comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib \
            rpcrt4.lib uuid.lib winmm.lib
EXTRA_LIBS += $(dist_libdir)/$(LDIF_LIBNAME).lib
EXTRA_LIBS += $(dist_libdir)/$(LBER_LIBNAME).lib
endif
endif

ifeq ($(MOZ_OS2_TOOLS),VACPP)
EXTRA_LIBS = $(dist_libdir)/$(LDIF_LIBNAME).lib
EXTRA_LIBS += $(dist_libdir)/$(LBER_LIBNAME).lib
EXTRA_LIBS += $(OS_LIBS)
endif
ifeq ($(MOZ_OS2_TOOLS),EMX)
EXTRA_LIBS = -L$(dist_libdir) -l$(LBER_LIBNAME) $(OS_LIBS)
endif

ifeq ($(OS_ARCH), OSF1)
EXTRA_LIBS = -L$(dist_libdir) -l$(LBER_LIBNAME)
EXTRA_LIBS += -L/usr/lib -lcxx -lpthread -lrt -lmach -lexc
endif

ifeq ($(OS_ARCH), AIX)
EXTRA_LIBS = -L$(dist_libdir) -l$(LBER_LIBNAME)
EXTRA_LIBS += -ldl -brtl -lpthreads -lc_r -lm
endif

ifeq ($(OS_ARCH), HP-UX)
EXTRA_LIBS = -L$(dist_libdir) -l$(LBER_LIBNAME)
ifdef USE_PTHREADS
EXTRA_LIBS += -ldld -lm -lpthread
else
EXTRA_LIBS += -ldld -lm
endif
endif

ifeq ($(OS_ARCH), Darwin)
EXTRA_LIBS = -L$(dist_libdir) -l$(LBER_LIBNAME)
endif

ifeq ($(OS_ARCH), OpenVMS)
EXTRA_LIBS = -L$(dist_libdir) -l$(LBER_LIBNAME) $(OS_LIBS)
SHARED_LIBRARY_LIBS = $(dist_libdir)/lib$(LBER_LIBNAME).a
endif

ifeq ($(OS_ARCH), BeOS)
EXTRA_LIBS = -L$(dist_libdir) -l$(LBER_LIBNAME) -lbe
endif

ifeq ($(OS_ARCH), NetBSD)
EXTRA_LIBS = -L$(dist_libdir) -l$(LBER_LIBNAME)
endif

ifeq ($(OS_ARCH), OpenBSD)
EXTRA_LIBS = -L$(dist_libdir) -l$(LBER_LIBNAME) -pthread
endif

ifeq ($(HAVE_SASL), 1)
EXTRA_LIBS += $(SASL_LINK)
endif

###########################################################################

ifeq ($(USE_DLL_EXPORTS_FILE), 1)
# recursive gmake rule to create exported symbols file
$(LDAP_EXPORT_DEFS):: $(srcdir)/../libldap.ex
ifeq ($(OS_ARCH), WINNT)
	$(GENEXPORTS) Win32 $(srcdir)/../msdos/winsock/nsldap32.tdf $< $(GENEXPARGS) > $@
else
ifeq ($(OS_ARCH), OS2)
	echo LIBRARY $(LDAP_LIBNAME) INITINSTANCE TERMINSTANCE > $@
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

# Set the default sources for the export target
EXPDEPS = $(OBJDIR_NAME) $(LIBDIR) $(OBJS) $(LIBLDAP) $(DLLLDAP)
# Remove the LIB source if on win32 and using MSVC
# This avoids problems with -jX builds where 'link' will make both the
# .dll and .lib files in one pass
ifeq ($(OS_ARCH), WINNT)
ifeq ($(LD),link)
EXPDEPS = $(OBJDIR_NAME) $(LIBDIR) $(OBJS) $(DLLLDAP)
endif
endif

export::	$(EXPDEPS)

ltest::	$(LIBLDAP) test.o
		$(LINK_EXE) test.o

$(LIBDIR):
	$(MKDIR) $(LIBDIR)

$(LIBLDAP): $(OBJS) $(LIBDIR) $(LDAP_EXPORT_DEFS)
	@echo ======= making $(LIBLDAP)
ifdef SO_FILES_TO_REMOVE
	-$(RM) $(SO_FILES_TO_REMOVE)
endif
ifneq (,$(filter AIX Linux HP-UX Darwin BeOS QNX NetBSD OSF1 OpenBSD, $(OS_ARCH)))
	$(LINK_LIB)
else
ifeq ($(OS_ARCH),OS2)
# create import library for OS/2
	rm -f $@
	$(IMPLIB) $@ $(LDAP_EXPORT_DEFS)
else
	$(LINK_LIB)
endif
endif

$(DLLLDAP): $(OBJS) $(LIBDIR) $(LDAP_EXPORT_DEFS)
	@echo ======= making $(DLLLDAP)
ifdef SO_FILES_TO_REMOVE
	-$(RM) $(SO_FILES_TO_REMOVE)
endif
	$(LINK_DLL) $(LDAP_EXPORT_FLAGS) $(EXTRA_LIBS)

veryclean:: clean

# the $(dist_bindir) line is for the mozilla client, which for reasons
# unknown wants shared libraries in /bin also
#
# Set the default sources for the export target
EXPDEPS2 = $(LIBLDAP) $(DLLLDAP)
# Remove the LIB source if on win32 and using MSVC
# This avoids problems with -jX builds where 'link' will make both the
# .dll and .lib files in one pass
ifeq ($(OS_ARCH), WINNT)
ifeq ($(LD),link)
EXPDEPS2 = $(DLLLDAP)
endif
endif

export::	$(EXPDEPS2)
ifdef MKSHLIB
	$(INSTALL) -m 444 $(LIBLDAP) $(dist_libdir)
	$(INSTALL) -m 444 $(DLLLDAP) $(dist_libdir)
	$(INSTALL) -m 444 $(DLLLDAP) $(dist_bindir)
endif
ifeq ($(OS_ARCH), WINNT)
	$(INSTALL) -m 444 $(LIBLDAP) $(dist_libdir)
	$(INSTALL) -m 444 $(DLLLDAP) $(dist_libdir)
endif
	$(INSTALL) -m 444 $(ETCFILES) $(ETCDIR)
