# contrib/dummy_toaster/Makefile

MODULE_big = dummy_toaster
OBJS = \
	$(WIN32RES) \
	dummy_toaster.o

EXTENSION = dummy_toaster
DATA = dummy_toaster--1.0.sql
PGFILEDESC = "dummy_toaster - toaster example"

REGRESS = dummy_toaster

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/dummy_toaster
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
