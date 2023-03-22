# contrib/bytea_toaster/Makefile

MODULE_big = bytea_toaster
OBJS = \
	$(WIN32RES) \
	bytea_toaster.o \
	toast_extended.o

EXTENSION = bytea_toaster
DATA = bytea_toaster--1.0.sql
PGFILEDESC = "bytea_toaster - appendable bytea toaster"

REGRESS = bytea_toaster bytea_toaster_syntax
EXTRA_INSTALL = contrib/toastapi

ifdef USE_PGXS
PG_CPPFLAGS = -I$(top_srcdir)/contrib/toastapi
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
PG_CPPFLAGS = -I$(top_srcdir)/contrib/toastapi
subdir = contrib/bytea_toaster
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
