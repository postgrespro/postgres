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
#include "catalog/pg_toaster.h"

/*
 * Callback function signatures --- see indexam.sgml for more info.
 */

/* Create toast storage */
typedef void (*toast_init)(Relation rel, Datum reloptions, LOCKMODE lockmode,
						   bool check, Oid OIDOldToast);

/* Toast function */
typedef Datum (*toast_function) (Relation toast_rel,
										   Oid toasterid,
										   Datum value,
										   Datum oldvalue,
										   int max_inline_size,
										   int options);

/* Update toast function, optional */
typedef Datum (*update_toast_function) (Relation toast_rel,
												  Oid toasterid,
												  Datum newvalue,
												  Datum oldvalue,
												  int options);

/* Copy toast function, optional */
typedef Datum (*copy_toast_function) (Relation toast_rel,
												Oid toasterid,
												Datum newvalue,
												int options);

/* Detoast function */
typedef Datum (*detoast_function) (Relation toast_rel,
											 Datum toast_ptr,
											 int offset, int length);

/* Delete toast function */
typedef void (*del_toast_function) (Datum value, bool is_speculative);



/* Return virtual table of functions, optional */
typedef void * (*get_vtable_function) (Datum toast_ptr);

/* validate definition of a toaster Oid */
typedef bool (*toastervalidate_function) (Oid typeoid,
										  char storage, char compression,
										  Oid amoid, bool false_ok);

/*
 * API struct for Toaster.  Note this must be stored in a single palloc'd
 * chunk of memory.
 */
typedef struct TsrRoutine
{
	NodeTag		type;

	/* interface functions */
	toast_init init;
	toast_function toast;
	update_toast_function update_toast;
	copy_toast_function copy_toast;
	detoast_function detoast;
	del_toast_function deltoast;
	get_vtable_function get_vtable;
	toastervalidate_function toastervalidate;
} TsrRoutine;

/* Functions in access/index/toasterapi.c */
extern TsrRoutine *GetTsrRoutine(Oid tsrhandler);
extern TsrRoutine *GetTsrRoutineByOid(Oid tsroid, bool noerror);
extern TsrRoutine *SearchTsrCache(Oid tsroid);
extern bool	validateToaster(Oid toasteroid, Oid typeoid, char storage,
							char compression, Oid amoid, bool false_ok);
extern Datum default_toaster_handler(PG_FUNCTION_ARGS);
#endif							/* TOASTERAPI_H */
