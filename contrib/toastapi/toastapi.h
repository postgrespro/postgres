/*-------------------------------------------------------------------------
 *
 * toastapi.h
 *		Pluggable TOAST API
 *
 * Portions Copyright (c) 2016-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 1990-1993, Regents of the University of California
 *
 * IDENTIFICATION
 *	  contrib/toastapi/toastapi.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef TOASTAPI_H
#define TOASTAPI_H

#include "postgres.h"
#include "varatt.h"
#include "varatt_custom.h"
#include "fmgr.h"
#include "access/heaptoast.h"
#include "access/htup_details.h"
#include "commands/defrem.h"
#include "utils/builtins.h"
#include "utils/syscache.h"
#include "access/toast_compression.h"
#include "access/attoptions.h"
#include "access/xact.h"
#include "catalog/binary_upgrade.h"
#include "catalog/catalog.h"
#include "catalog/dependency.h"
#include "catalog/heap.h"
#include "catalog/index.h"
#include "catalog/namespace.h"
#include "catalog/pg_am.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_opclass.h"
#include "catalog/pg_type.h"
#include "catalog/toasting.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "access/relation.h"
#include "access/genam.h"

#define TOASTER_HANDLEROID 8888

#define PG_TOASTER_NAME "pg_toaster"
#define PG_TOASTREL_NAME "pg_toastrel"

#define REL_TOASTER_NAME "pgpro_toasteroid"
#define REL_BASEREL_NAME "pgpro_basereloid"

#define ATT_TOASTER_NAME "pgpro_toasteroid"
#define ATT_HANDLER_NAME "pgpro_toasthandler"
#define ATT_TOASTREL_NAME "pgpro_toastreloid"
#define ATT_NTOASTERS_NAME "pgpro_ntoasters"
/*
static Oid pg_toaster_idx_oid = InvalidOid;
static Oid pg_toastrel_idx_oid = InvalidOid;
*/

/*
 * Macro to fetch the possibly-unaligned contents of an EXTERNAL datum
 * into a local "struct varatt_external" toast pointer.  This should be
 * just a memcpy, but some versions of gcc seem to produce broken code
 * that assumes the datum contents are aligned.  Introducing an explicit
 * intermediate "varattrib_1b_e *" variable seems to fix it.
 */
#define VARATT_EXTERNAL_GET_POINTER(toast_pointer, attr) \
do { \
	varattrib_1b_e *attre = (varattrib_1b_e *) (attr); \
	Assert(VARATT_IS_EXTERNAL(attre)); \
	Assert(VARSIZE_EXTERNAL(attre) == sizeof(toast_pointer) + VARHDRSZ_EXTERNAL); \
	memcpy(&(toast_pointer), VARDATA_EXTERNAL(attre), sizeof(toast_pointer)); \
} while (0)

/* Size of an EXTERNAL datum that contains a standard TOAST pointer */
#define TOAST_POINTER_SIZE (VARHDRSZ_EXTERNAL + sizeof(varatt_external))

/* Size of an EXTERNAL datum that contains an indirection pointer */
#define INDIRECT_POINTER_SIZE (VARHDRSZ_EXTERNAL + sizeof(varatt_indirect))

#define VARATT_TOASTER_GET_POINTER(toast_pointer, attr) \
do { \
	varattrib_1b_e *attre = (varattrib_1b_e *) (attr); \
	Assert(VARATT_IS_TOASTER(attre)); \
	Assert(VARSIZE_TOASTER(attre) == sizeof(toast_pointer) + VARHDRSZ_EXTERNAL); \
	memcpy(&(toast_pointer), VARDATA_TOASTER(attre), sizeof(toast_pointer)); \
} while (0)

/* Size of an EXTERNAL datum that contains a custom TOAST pointer */
#define TOASTER_POINTER_SIZE (VARHDRSZ_EXTERNAL + sizeof(varatt_custom))

#define BYTEA_TOASTER_MAGIC    0xb17ea757
typedef struct ByteaToastRoutine
{
	int32	magic;
	Datum	(*append)(Datum val1, Datum val2);
} ByteaToastRoutine;

typedef struct ToastAttributesData
{
	Oid toasteroid;
	Oid toasthandleroid;
	Oid toastreloid;
	int attnum;
	int ntoasters;
	int options;
	void *toaster;
	bool create_table_ind;
} ToastAttributesData;

typedef ToastAttributesData *ToastAttributes;

/*
 * Callback function signatures --- see indexam.sgml for more info.
 */

/* Toast function */
typedef Datum (*toast_function) (Relation toast_rel,
										   Datum value,
										   Datum oldvalue,
										   int max_inline_size,
										   int options,
											ToastAttributes tattrs);

/* Update toast function, optional */
typedef Datum (*update_toast_function) (Relation toast_rel,
												  Datum newvalue,
												  Datum oldvalue,
												  int options,
												  ToastAttributes tattrs);

/* Copy toast function, optional */
typedef Datum (*copy_toast_function) (Relation toast_rel,
												Datum newvalue,
												int options,
												ToastAttributes tattrs);

/* Detoast function */
typedef Datum (*detoast_function) (Datum toast_ptr,
											 int offset, int length, ToastAttributes tattrs);

/* Delete toast function */
typedef void (*del_toast_function) (Relation rel,Datum value, bool is_speculative, ToastAttributes tattrs);

/* Return virtual table of functions, optional */
typedef void * (*get_vtable_function) (Datum toast_ptr);

/* validate definition of a toaster Oid */
typedef bool (*toastervalidate_function) (Oid toasteroid, Oid typeoid,
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
	toast_function toast;
	update_toast_function update_toast;
	copy_toast_function copy_toast;
	detoast_function detoast;
	del_toast_function deltoast;
	get_vtable_function get_vtable;
	toastervalidate_function toastervalidate;
} TsrRoutine;

#define T_TsrRoutine 999
#define makeTsrNode()		((TsrRoutine *) newNode(sizeof(TsrRoutine),T_TsrRoutine))

/* Functions in toastapi.c */
extern TsrRoutine *GetTsrRoutine(Oid tsrhandler);
extern TsrRoutine *GetTsrRoutineByOid(Oid tsroid, bool noerror);
extern TsrRoutine *SearchTsrCache(Oid tsroid);
extern bool	validateToaster(Oid toasteroid, Oid typeoid, char storage,
							char compression, Oid amoid, bool false_ok);

#endif							/* TOASTAPI_H */
