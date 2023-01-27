/*-------------------------------------------------------------------------
 *
 * pg_toaster.h
 *	  definition of the "generalized toaster" system catalog (pg_toaster)
 *
 *
 * Portions Copyright (c) 1996-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/catalog/pg_toaster.h
 *
 * NOTES
 *	  The Catalog.pm module reads this file and derives schema
 *	  information.
 *
 *-------------------------------------------------------------------------
 */
#ifndef PG_TOASTER_H
#define PG_TOASTER_H

#include "postgres.h"
#include "utils/relcache.h"

#define Anum_pg_toaster_oid 1
#define Anum_pg_toaster_tsrname 2
#define Anum_pg_toaster_tsrhandler 3

#define Natts_pg_toaster 3

#define DEFAULT_TOASTER_OID 9864

typedef struct FormData_pg_toaster
{
	Oid			oid;			/* oid */

	/* toaster name */
	NameData	tsrname;

	/* handler function */
	regproc		tsrhandler;
} FormData_pg_toaster;

typedef FormData_pg_toaster *Form_pg_toaster;

/* DECLARE_UNIQUE_INDEX(pg_toaster_name_index, 9862, ToasterNameIndexId, on pg_toaster using btree(tsrname name_ops));
DECLARE_UNIQUE_INDEX_PKEY(pg_toaster_oid_index, 9863, ToasterOidIndexId, on pg_toaster using btree(oid oid_ops)); */

#endif							/* PG_TOASTER_H */
