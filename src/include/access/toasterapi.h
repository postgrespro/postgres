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

#include "access/detoast.h"
#include "access/genam.h"
#include "catalog/pg_toaster.h"

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
       int32           magic;
       Datum     (*append)(Datum val1, Datum val2);
} ByteaToastRoutine;

/*
 * Callback function signatures --- see indexam.sgml for more info.
 */

/* Create toast storage */
typedef Datum (*toast_init)(Relation rel, Oid toasteroid, Oid toastoid, Oid toastindexoid, Datum reloptions, int attnum, LOCKMODE lockmode,
						   bool check, Oid OIDOldToast);

/* Toast function */
typedef Datum (*toast_function) (Relation toast_rel,
										   Oid toasterid,
										   Datum value,
										   Datum oldvalue,
											int attnum,
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
												int options,
												int attnum);

/* Detoast function */
typedef Datum (*detoast_function) (Datum toast_ptr,
											 int offset, int length);

/* Delete toast function */
typedef void (*del_toast_function) (Datum value, bool is_speculative);



/* Return virtual table of functions, optional */
typedef void * (*get_vtable_function) (Datum toast_ptr);

/* validate definition of a toaster Oid */
typedef bool (*toastervalidate_function) (Oid typeoid,
										  char storage, char compression,
										  Oid amoid, bool false_ok);

#define TOASTREL_VACUUM_FULL_DISABLED 0x01
typedef int (*toast_rel_info_function)(Relation toast_rel);

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
	toast_rel_info_function relinfo;
} TsrRoutine;

typedef struct ToastrelData {
	Oid			oid;			   /* oid */
   Oid			toasteroid;		/* oid */
   Oid			relid;		   /* oid */
   Oid			toastentid;		/* oid */
   int16			attnum;		   /* oid */
   int16       version;
   NameData	   relname;		   /* original table name */
   NameData	   toastentname;	/* toast storage entity name */
   char		   description;	/* Description */
	char		   toastoptions;	/* Toast options */
} ToastrelData;

typedef struct ToastrelData *Toastrel;

typedef struct ToastrelKey {
   Oid			toastentid;		/* oid */
	Oid			toasterid;		/* oid */
   int16			attnum;		   /* oid */
	int16			version;		   /* oid */
} ToastrelKey;

typedef struct ToastrelKey *Toastkey;

/* Functions in access/index/toasterapi.c */
extern TsrRoutine *GetTsrRoutine(Oid tsrhandler);
extern TsrRoutine *GetTsrRoutineByOid(Oid tsroid, bool noerror);
extern TsrRoutine *SearchTsrCache(Oid tsroid);
extern bool	validateToaster(Oid toasteroid, Oid typeoid, char storage,
							char compression, Oid amoid, bool false_ok);
extern Datum default_toaster_handler(PG_FUNCTION_ARGS);

extern Datum GetFullToastrel(Oid relid, int16 attnum, LOCKMODE lockmode);
extern Datum GetActualToastrel(Oid toasterid, Oid relid, int16 attnum, LOCKMODE lockmode);
extern Datum GetAttVersionToastrel(Oid toasterid, Oid relid, int16 attnum, LOCKMODE lockmode);
extern Datum GetLastToaster(Oid relid, int16 attnum, LOCKMODE lockmode);

extern bool InsertToastRelation(Oid toasteroid, Oid relid, Oid toastentid, int16 attnum,
	int version, NameData relname, NameData toastentname, char toastoptions, LOCKMODE lockmode);
extern bool UpdateToastRelationFlag(Oid treloid, Oid toasteroid, Oid relid, Oid toastentid, int16 attnum,
	int version, char flag, LOCKMODE lockmode);
extern bool
DeleteToastRelation(Oid treloid, Oid toasteroid, Oid relid, Oid toastentid, int16 attnum,
	int version, LOCKMODE lockmode);


extern Datum SearchToastrelCache(Oid	relid, int16 attnum, bool search_ind);
extern Datum InsertToastrelCache(Oid treloid, Oid toasteroid, Oid relid, Oid toastentid, int16 attnum,
	int16 version, char toastoptions);
extern Datum DeleteToastrelCache(Oid toasterid, Oid	relid, int16 attnum);
extern Datum InsertOrReplaceToastrelCache(Oid treloid, Oid toasteroid, Oid relid, Oid toastentid, int16 attnum,
	char toastoptions);
extern Datum
GetToastrelList(List *trel_list, Oid relid, int16 attnum, LOCKMODE lockmode);
extern bool
HasToastrel(Oid toasterid, Oid relid, int16 attnum, LOCKMODE lockmode);
extern Datum
GetFullToastrelList(List *trel_list, Oid relid, int16 attnum, LOCKMODE lockmode);

extern Datum
GetInheritedToaster(List *schema, List *supers, char relpersistence,
				bool is_partition, List **supconstr,
				Oid accessMethodId, NameData attname, Oid typid);

Datum relopts_get_toaster_opts(Datum reloptions, Oid *relid, Oid *toasterid);
Datum relopts_set_toaster_opts(Datum reloptions, Oid relid, Oid toasterid);

#endif							/* TOASTERAPI_H */
