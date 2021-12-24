/*-------------------------------------------------------------------------
 *
 * toasterapi.h
 *	  API for Postgres custom TOAST methods.
 *
 * Copyright (c) 2015-2021, PostgreSQL Global Development Group
 *
 * src/include/access/toasterapi.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef TOASTERAPI_H
#define TOASTERAPI_H

#include "access/genam.h"

/*
 * We don't wish to include planner header files here, since most of an toaster
 * implementation isn't concerned with those data structures.  To allow
 * declaring functions here, use forward struct references.
 */
struct PlannerInfo;
struct IndexPath;

/* Likewise, this file shouldn't depend on execnodes.h. */
struct IndexInfo;


/*
 * Properties for tsrproperty API.  This list covers properties known to the
 * core code
 */
typedef enum IndexTsrProperty
{
	TSRPROP_UNKNOWN = 0,			/* anything not known to core code */
	TSRPROP_VERSION,				/* toaster version */
	TSRPROP_COMPRESSED,				/* is compressed */
	TSRPROP_RESERVED,
} IndexTsrProperty;

/*
 * Callback function signatures --- see indexam.sgml for more info.
 */

/* Toast function */
typedef Datum (*toast_function) (Relation toast_rel,
								Datum value, Datum oldvalue,
								int max_inline_size);

/* Detoast function */
typedef Datum (*detoast_function) (Relation toast_rel,
								Datum toast_ptr,
								int offset, int length);

/* Delete toast function */
typedef Datum (*del_toast_function) (Relation toast_rel,
								Datum value);

/* Return virtual table of functions */
typedef Size (*get_rawsize_function) (Datum toast_ptr);

/* Return virtual table of functions, optional */
typedef void * (*get_vtable_function) (Datum toast_ptr);

/* validate definition of a toaster Oid */
typedef bool (*toastervalidate_function) (Oid typeoid,
										  Oid amoid, bool false_ok);

/*
 * API struct for Toaster.  Note this must be stored in a single palloc'd
 * chunk of memory.
 */
typedef struct TsrRoutine
{
	NodeTag		type;

	/* interface functions */
	toast_function toast;
	detoast_function detoast;
	del_toast_function deltoast;
	get_vtable_function get_vtable;
	toastervalidate_function toastervalidate;
} TsrRoutine;


/* Functions in access/index/toasterapi.c */
extern TsrRoutine *GetTsrRoutine(Oid tsrhandler);
extern TsrRoutine *GetTsrRoutineByOid(Oid tsroid, bool noerror);
extern bool	validateToaster(Oid toasteroid, Oid typeoid, Oid amoid, bool
							false_ok);
#endif							/* TOASTERAPI_H */
