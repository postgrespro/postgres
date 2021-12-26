/*-------------------------------------------------------------------------
 *
 * toast_table.h
 *	  Table definitions for the TOAST system.
 *
 * Copyright (c) 2000-2021, PostgreSQL Global Development Group
 *
 * src/include/access/toast_table.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef TOAST_TABLE_H
#define TOAST_TABLE_H

#include "access/toast_compression.h"
#include "storage/lockdefs.h"
#include "utils/relcache.h"
#include "utils/snapshot.h"
#include "utils/rel.h"
#include "access/detoast.h"
#include "access/table.h"
#include "access/tableam.h"
#include "common/int.h"
#include "common/pg_lzcompress.h"
#include "utils/expandeddatum.h"

extern Oid	toast_get_valid_index(Oid toastoid, LOCKMODE lock);
extern int	toast_open_indexes(Relation toastrel,
							   LOCKMODE lock,
							   Relation **toastidxs,
							   int *num_indexes);
extern void toast_close_indexes(Relation *toastidxs, int num_indexes,
								LOCKMODE lock);
extern void init_toast_snapshot(Snapshot toast_snapshot);

#endif							/* TOAST_TABLE_H */