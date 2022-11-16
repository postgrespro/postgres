# contrib/bytea_toaster/Makefile

MODULE_big = bytea_toaster
OBJS = \
	$(WIN32RES) \
	bytea_toaster.o

EXTENSION = bytea_toaster
DATA = bytea_toaster--1.0.sql
PGFILEDESC = "bytea_toaster - appendable bytea toaster"

REGRESS = bytea_toaster

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/bytea_toaster
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
