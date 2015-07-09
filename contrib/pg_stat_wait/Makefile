# contrib/pg_stat_wait/Makefile

MODULE_big = pg_stat_wait
OBJS = pg_stat_wait.o collector.o

EXTENSION = pg_stat_wait
DATA = pg_stat_wait--1.0.sql
PG_CPPFLAGS = -DPG_STAT_WAIT_TESTS
EXTRA_CLEAN = $(pg_regress_clean_files) ./regression_output ./isolation_output
EXTRA_INSTALL=contrib/pg_stat_wait

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/pg_stat_wait
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif

check: regresscheck isolationcheck

submake-regress:
	$(MAKE) -C $(top_builddir)/src/test/regress all

submake-isolation:
	$(MAKE) -C $(top_builddir)/src/test/isolation all

submake-pg_stat_wait:
	$(MAKE) -C $(top_builddir)/contrib/pg_stat_wait

REGRESSCHECKS=file_trace descriptions

regresscheck: all | submake-regress submake-pg_stat_wait
	$(MKDIR_P) regression_output
	$(pg_regress_check) \
	    --temp-instance=./tmp_check \
	    --load-extension=pg_stat_wait \
	    --outputdir=./regression_output \
	    $(REGRESSCHECKS)

ISOLATIONCHECKS=history

isolationcheck: all | submake-isolation submake-pg_stat_wait
	$(MKDIR_P) isolation_output
	$(pg_isolation_regress_check) \
	    --temp-instance=./tmp_check \
		--temp-config=./waits.conf \
		--load-extension=pg_stat_wait \
	    --outputdir=./isolation_output \
	    $(ISOLATIONCHECKS)

