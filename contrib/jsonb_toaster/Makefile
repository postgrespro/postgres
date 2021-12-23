# contrib/jsonb_toaster/Makefile

MODULE_big = jsonb_toaster
OBJS = \
	$(WIN32RES) \
	jsonb_toaster.o

EXTENSION = jsonb_toaster
DATA = jsonb_toaster--1.0.sql
PGFILEDESC = "jsonb_toaster - updatable jsonb toaster"

REGRESS = jsonb_toaster

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/jsonb_toaster
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
