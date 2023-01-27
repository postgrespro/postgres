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

#include "postgres.h"
#include "utils/relcache.h"

#define ToastrelRelationId 9881
#define ToastrelOidIndexId 9882
#define ToastrelKeyIndexId 9883
#define ToastrelRelIndexId 9884
#define ToastrelTsrIndexId 9885

#define Anum_pg_toastrel_oid 1
#define Anum_pg_toastrel_toasteroid 2
#define Anum_pg_toastrel_relid 3
#define Anum_pg_toastrel_toastentid 4
#define Anum_pg_toastrel_attnum 5
#define Anum_pg_toastrel_version 6
#define Anum_pg_toastrel_flag 7
#define Anum_pg_toastrel_toastoptions 8

#define Natts_pg_toastrel 8

/* ----------------
 *		pg_toastrel definition.  cpp turns this into
 *		typedef struct FormData_pg_toastrel
 * ----------------
 */
typedef struct FormData_pg_toastrel
{
	Oid			oid;			   /* oid */
   Oid			toasteroid;		/* oid */
   Oid			relid;		   /* oid */
   Oid			toastentid;		/* oid */
   int16			attnum;		   /* oid */
   int16       version;
   char		   flag;	         /* Cleanup flag */
	char		   toastoptions;	/* Toast options */
} FormData_pg_toastrel;

/* ----------------
 *		Form_pg_toastrel corresponds to a pointer to a tuple with
 *		the format of pg_toastrel relation.
 * ----------------
 */
typedef FormData_pg_toastrel *Form_pg_toastrel;
/*
DECLARE_UNIQUE_INDEX_PKEY(pg_toastrel_oid_index, 9882, ToastrelOidIndexId, on pg_toastrel using btree(oid oid_ops));
DECLARE_UNIQUE_INDEX(pg_toastrel_name_index, 9883, ToastrelKeyIndexId, on pg_toastrel using btree(toasteroid oid_ops, relid oid_ops, version int2_ops, attnum int2_ops));
DECLARE_INDEX(pg_toastrel_rel_index, 9884, ToastrelRelIndexId, on pg_toastrel using btree(relid oid_ops, attnum int2_ops));
DECLARE_INDEX(pg_toastrel_tsr_index, 9885, ToastrelTsrIndexId, on pg_toastrel using btree(toasteroid oid_ops));
*/
#endif							/* PG_TOASTREL_H */
