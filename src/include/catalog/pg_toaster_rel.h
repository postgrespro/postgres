/*-------------------------------------------------------------------------
 *
 * pg_toaster_rel.h
 *	  toasters and TOAST relations system catalog (pg_toastrel)
 *
 *
 * Portions Copyright (c) 1996-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/catalog/pg_toaster_rel.h
 *
 * NOTES
 *	  The Catalog.pm module reads this file and derives schema
 *	  information.
 *
 *-------------------------------------------------------------------------
 */
#ifndef PG_TOASTER_REL_H
#define PG_TOASTER_REL_H

#include "catalog/genbki.h"
#include "catalog/pg_toaster_rel_d.h"
#include "utils/relcache.h"

/* ----------------
 *		pg_toaster_rel definition.  cpp turns this into
 *		typedef struct FormData_pg_toaster_rel
 * ----------------
 */
CATALOG(pg_toaster_rel,9891,ToasterRelRelationId)
{
	Oid			oid;			   /* oid */
   Oid			toasteroid;		/* oid */
   Oid			relid;		   /* oid */
   int16			attnum;		   /* oid */
   int16       version;
	char		   toastoptions;	/* Toast options */
} FormData_pg_toaster_rel;

/* ----------------
 *		Form_pg_toaster_rel corresponds to a pointer to a tuple with
 *		the format of pg_toaster_rel relation.
 * ----------------
 */
typedef FormData_pg_toaster_rel *Form_pg_toaster_rel;

DECLARE_UNIQUE_INDEX_PKEY(pg_toaster_rel_oid_index, 9892, ToasterRelOidIndexId, on pg_toaster_rel using btree(oid oid_ops));
DECLARE_UNIQUE_INDEX(pg_toaster_rel_name_index, 9893, ToasterRelKeyIndexId, on pg_toaster_rel using btree(toasteroid oid_ops, relid oid_ops, attnum int2_ops, version int2_ops));

#endif							/* PG_TOASTER_REL_H */
