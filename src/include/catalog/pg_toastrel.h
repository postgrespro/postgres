/*-------------------------------------------------------------------------
 *
 * pg_toastrel.h
 *	  toasters and TOAST relations system catalog (pg_toastrel)
 *
 *
 * Portions Copyright (c) 1996-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/catalog/pg_toastrel.h
 *
 * NOTES
 *	  The Catalog.pm module reads this file and derives schema
 *	  information.
 *
 *-------------------------------------------------------------------------
 */
#ifndef PG_TOASTREL_H
#define PG_TOASTREL_H

#include "catalog/genbki.h"
#include "catalog/pg_toastrel_d.h"
#include "utils/relcache.h"

/* ----------------
 *		pg_toastrel definition.  cpp turns this into
 *		typedef struct FormData_pg_toastrel
 * ----------------
 */
CATALOG(pg_toastrel,9881,ToastrelRelationId)
{
	Oid			oid;			   /* oid */
   Oid			toasterrelid;	/* pg_toaster_rel record id */
   Oid			toastentid;		/* oid */
   int16			toastentnum;	/* toast entity index */
   NameData	   toastentname;	/* toast storage entity name */
#ifdef CATALOG_VARLEN			/* variable-length fields start here */
	timestamptz sys_creation_date;	/* password expiration time, if any */
#endif
} FormData_pg_toastrel;

/* ----------------
 *		Form_pg_toastrel corresponds to a pointer to a tuple with
 *		the format of pg_toastrel relation.
 * ----------------
 */
typedef FormData_pg_toastrel *Form_pg_toastrel;

DECLARE_UNIQUE_INDEX_PKEY(pg_toastrel_oid_index, 9882, ToastrelOidIndexId, on pg_toastrel using btree(oid oid_ops));
DECLARE_UNIQUE_INDEX(pg_toastrel_name_index, 9883, ToastrelKeyIndexId, on pg_toastrel using btree(toasterrelid oid_ops, toastentid oid_ops));
// DECLARE_INDEX(pg_toastrel_tsr_index, 9884, ToastrelTsrIndexId, on pg_toastrel using btree(relid oid_ops, toastentid oid_ops, attnum int2_ops));

#endif							/* PG_TOASTREL_H */
