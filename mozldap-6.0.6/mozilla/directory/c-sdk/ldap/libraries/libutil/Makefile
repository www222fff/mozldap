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
# The Original Code is mozilla.org code.
# 
# The Initial Developer of the Original Code is
#   Rich Megginson <richm@stanfordalumni.org>
# Portions created by the Initial Developer are Copyright (C) 2006
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



MOD_DEPTH	= ../../..
srcdir		= .
topsrcdir 	= ../../..

include $(MOD_DEPTH)/config/autoconf.mk
include $(topsrcdir)/build.mk

SRCS = getopt.c

REALOBJS        = $(SRCS:.c=.$(OBJ_SUFFIX))

UTILOBJDEST	= $(OBJDIR_NAME)
OBJS		= $(addprefix $(UTILOBJDEST)/, $(REALOBJS))

DISTHDIR	= $(DIST)/public/ldap
HDIR		= $(topsrcdir)/ldap/include

LIBUTIL	= $(addprefix $(UTILOBJDEST)/, \
		  $(LIB_PREFIX)$(UTIL_LIBNAME).$(LIB_SUFFIX))

INSTALLDIR      = $(DIST)/$(OBJDIR_NAME)

include $(topsrcdir)/config/rules.mk

DEFINES		+= $(DEFS)


export::    $(OBJDEST) $(LIBDIR) $(OBJS) $(LIBUTIL)

$(LIBDIR):
	$(MKDIR) $(LIBDIR)

$(LIBUTIL): $(OBJS) $(LIBDIR)
	@echo ======= making $(LIBUTIL)
ifdef SO_FILES_TO_REMOVE
	-$(RM) $(SO_FILES_TO_REMOVE)
endif
	$(LINK_LIB)

veryclean:: clean

$(OBJDEST):
	$(MKDIR) $(OBJDEST)

export::	$(LIBUTIL)
	$(INSTALL) -m 444 $(LIBUTIL) $(dist_libdir)
