/*-------------------------------------------------------------------------
 *
 * pg_toaster.c
 *		PG_Toaster functions
 *
 * Portions Copyright (c) 1996-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *		src/backend/catalog/pg_toaster.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "access/htup_details.h"
#include "access/toasterapi.h"
#include "access/xact.h"
#include "catalog/indexing.h"
#include "catalog/pg_toaster.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "storage/lmgr.h"
#include "utils/array.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"
#include "utils/pg_lsn.h"
#include "utils/rel.h"
#include "utils/syscache.h"

Datum
default_toaster_handler(PG_FUNCTION_ARGS)
{
	TsrRoutine	*tsr = makeNode(TsrRoutine);

	PG_RETURN_POINTER(tsr);
}

