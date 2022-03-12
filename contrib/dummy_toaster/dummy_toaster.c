/*-------------------------------------------------------------------------
 *
 * dummy_toaster.c
 *		Bloom index utilities.
 *
 * Portions Copyright (c) 2016-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 1990-1993, Regents of the University of California
 *
 * IDENTIFICATION
 *	  contrib/bloom/blutils.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"
#include "fmgr.h"

PG_MODULE_MAGIC;
PG_FUNCTION_INFO_V1(dummy_toaster_handler);

Datum
dummy_toaster_handler(PG_FUNCTION_ARGS)
{
	/*
	IndexAmRoutine *amroutine = makeNode(IndexAmRoutine);

	amroutine->amstrategies = BLOOM_NSTRATEGIES;
	*/

	elog(ERROR, "dummy_toaster_handler is uninimplemented yet");
	PG_RETURN_POINTER(NULL);
}

