/*-------------------------------------------------------------------------
 *
 * toasting.h
 *	  This file provides some definitions to support creation of toast tables
 *	  and access to
 *
 * Portions Copyright (c) 1996-2023, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/catalog/toasting.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef TOASTING_H
#define TOASTING_H

#include "storage/lock.h"
#include "utils/snapmgr.h"

/*
 * toasting.c prototypes
 */
extern void NewRelationCreateToastTable(Oid relOid, Datum reloptions);
extern void NewHeapCreateToastTable(Oid relOid, Datum reloptions,
									LOCKMODE lockmode, Relation old_heap);
extern void AlterTableCreateToastTable(Oid relOid, Datum reloptions,
									   LOCKMODE lockmode);
extern void BootstrapToastTable(char *relName,
								Oid toastOid, Oid toastIndexOid);

extern int ExtractRelToastInfo(TupleDesc pg_class_desc,
	HeapTuple pg_class_tuple,
	Datum **toasterids, Datum **toastrelids);

/* generic toaster access */
extern bool create_toast_table(Relation rel, Oid toasterid, Oid toastOid, Oid toastIndexOid,
							   Datum reloptions, LOCKMODE lockmode, bool check,
							   Oid OIDOldToast);

extern void register_toast_table(Oid relid, Oid toasterid, Oid toastrelid);
extern Oid toast_find_relation_for_toaster(Relation rel, Oid toasterid,
	Oid *real_toastrelid);
extern HeapTuple toast_modify_pg_class_tuple(Relation classrel,
	HeapTuple tuple,
	Datum reltoasterids,
	Datum reltoastrelids);

extern Oid	toast_get_valid_index(Oid toastoid, LOCKMODE lock);
extern int	toast_open_indexes(Relation toastrel,
							   LOCKMODE lock,
							   Relation **toastidxs,
							   int *num_indexes);
extern void toast_close_indexes(Relation *toastidxs, int num_indexes,
								LOCKMODE lock);
extern void init_toast_snapshot(Snapshot toast_snapshot);

#endif							/* TOASTING_H */
