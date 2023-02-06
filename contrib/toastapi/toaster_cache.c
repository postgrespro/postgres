#ifndef TOASTERCACHE_H
#define TOASTERCACHE_H

#include "toastapi.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"
#include "access/heapam.h"
#include "access/xact.h"
#include "storage/lock.h"
#include "utils/builtins.h"
#include "utils/rel.h"
#include "utils/memutils.h"
#include "utils/fmgroids.h"
#include "utils/regproc.h"
#include "nodes/nodes.h"
#include "pg_toaster.h"
#include "pg_toastrel.h"
#include "toastapi_internals.h"

typedef struct ToasterCacheEntry
{
	Oid			toasterOid;
	TsrRoutine *routine;
} ToasterCacheEntry;

static List	*ToasterCache = NIL;

typedef struct ToastrelCacheEntry
{
	Oid 		relid;
	int16 	attnum;
} ToastrelCacheEntry;

static List	*ToastrelCache = NIL;

/* Cache pg_toaster and pg_toastrel */
Oid cache_pg_toaster()
{
   Oid coid = InvalidOid;
   text *relname = cstring_to_text("pg_toaster");
   Relation rel;
   rel = get_rel_from_relname(relname, AccessShareLock, ACL_SELECT);

   coid = RelationGetRelid(rel);
   return coid;
}

/*
 * SearchTsrCache - get cached toaster routine, emits an error if toaster
 * doesn't exist
 */
TsrRoutine*
SearchTsrCache(Oid	toasterOid)
{
	ListCell		   *lc;
	ToasterCacheEntry  *entry;
	MemoryContext		ctx;

	if (list_length(ToasterCache) > 0)
	{
		/* fast path */
		entry = (ToasterCacheEntry*)linitial(ToasterCache);
		if (entry->toasterOid == toasterOid)
			return entry->routine;
	}

	/* didn't find in first position */
	ctx = MemoryContextSwitchTo(CacheMemoryContext);

	for_each_from(lc, ToasterCache, 0)
	{
		entry = (ToasterCacheEntry*)lfirst(lc);

		if (entry->toasterOid == toasterOid)
		{
			/* XXX NMalakhov: */
			/* Questionable approach - should we re-arrange TOASTer cache 		*/
			/* on cache hit for non-first entry or not. We suggest that there 	*/
			/* won't be a lot of Toasters, and most used still will be the 		*/
			/* default (generic) one. Re-arranging is commented until final		*/
			/* decision is to be made */
			/* remove entry from list, it will be added in a head of list below */
			/*
			foreach_delete_current(ToasterCache, lc);
			*/
			goto out;
		}
	}

	/* did not find entry, make a new one */
	entry = palloc(sizeof(*entry));

	entry->toasterOid = toasterOid;
	entry->routine = GetTsrRoutineByOid(toasterOid, false);

/* XXX NMalakhov: label moved further wi re-arranging commented. Insertion into */
/* ToasterCache changed from prepend to append, fot the first used Toaster 		*/
/* (almost always the default one) to be the first one. Also appending does not */
/* move all the entries around */
/* out: */
	/*
	ToasterCache = lcons(entry, ToasterCache);
	*/
	ToasterCache = lappend(ToasterCache, entry);

out:
	MemoryContextSwitchTo(ctx);

	return entry->routine;
}

/*я
 * GetRoutine - call the specified toaster handler routine to get
 * its TsrRoutine struct, which will be palloc'd in the caller's context.
 *
 */
TsrRoutine *
GetTsrRoutine(Oid tsrhandler)
{
	Datum		datum;
	TsrRoutine *routine;

	datum = OidFunctionCall0(tsrhandler);
	routine = (TsrRoutine *) DatumGetPointer(datum);

	if (routine == NULL) // || !IsA(routine, TsrRoutine))
		elog(ERROR, "toaster handler function %u did not return an TsrRoutine struct",
			 tsrhandler);

	return routine;
}

/*
 * GetTsrRoutineByOid - look up the handler of the toaster
 * with the given OID, and get its TsrRoutine struct.
 *
 * If the given OID isn't a valid toaster, returns NULL if
 * noerror is true, else throws error.
 */
TsrRoutine *
GetTsrRoutineByOid(Oid tsroid, bool noerror)
{
	HeapTuple	tuple;
	Form_pg_toaster	tsrform;
	regproc		tsrhandler = InvalidOid;

	Relation	toastrel;
	Relation	rel;
	Relation   *toastidxs;
	Relation   relindx;
	Oid			idx_oid;
	int			num_indexes;
	int			validIndex;
	int options = 0;
   Oid relid = InvalidOid;
   Oid tshndloid = InvalidOid;
	char *tsrname;
	bool		found = false;
	List	   *indexlist;
	List *namelist;
	ListCell   *lc;
	ScanKeyData key[2];
	SysScanDesc scan;
	HeapTuple	tup;
	uint32      total_entries = 0;
	int keys = 0;

	rel = get_rel_from_relname(cstring_to_text(PG_TOASTER_NAME), RowExclusiveLock, ACL_INSERT);

	if(!rel)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_TABLE),
				 errmsg("Cannot open pg_toaster table")));

	indexlist = RelationGetIndexList(rel);
	
	Assert(indexlist != NIL);

	num_indexes = list_length(indexlist);

	foreach(lc, indexlist)
	{
		relindx = index_open(lfirst_oid(lc), AccessShareLock);
		idx_oid = RelationGetRelid(relindx);
		index_close(relindx, AccessShareLock);
		found = true;
		break;
	}

	list_free(indexlist);

	if (!found)
	{
		table_close(rel, RowExclusiveLock);
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_FUNCTION),
				 errmsg("no valid index found for toast relation with Oid %u", relid)));
	}

	ScanKeyInit(&key[keys],
			Anum_pg_toaster_oid,
			BTEqualStrategyNumber, F_INT4EQ,
			tsroid);
	keys++;

	scan = systable_beginscan(rel, idx_oid, false,
							  NULL, keys, key);
	keys = 0;
	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		total_entries++;
		if(tsroid == ((Form_pg_toaster) GETSTRUCT(tup))->oid)
		{
      	tsrhandler = ((Form_pg_toaster) GETSTRUCT(tup))->tsrhandler;
			break;
		}
	}
	systable_endscan(scan);
	table_close(rel, RowExclusiveLock);

/*	namelist = stringToQualifiedNameList(tsrhandler, NULL); */
	/*
	 * Get the handler function oid, verifying the toaster type while at it.
	 */
/*	tshndloid = lookup_toaster_handler_func(namelist); */
	if (!RegProcedureIsValid(tsrhandler))
	{
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("toaster \"%u\" does not have a handler",
						tsroid)));
	}
//NameStr(tsrform->tsrname)
	/* And finally, call the handler function to get the API struct. */
	return GetTsrRoutine(tsrhandler);
}

/*
 * could toaster operates with given type and access method?
 * If it can't then validate method should emit an error if false_ok = false
 */
bool
validateToaster(Oid toasteroid, Oid typeoid,
				char storage, char compression, Oid amoid, bool false_ok)
{
	TsrRoutine *tsrroutine;
	bool	result = true;

	if (!TypeIsToastable(typeoid))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("data type %s can not be toasted",
						format_type_be(typeoid))));

	tsrroutine = GetTsrRoutineByOid(toasteroid, false_ok);

	/* if false_ok == false then GetTsrRoutineByOid emits an error */
	if (tsrroutine == NULL)
		return false;

#if 0 /* XXX teodor: commented out while there is no actual toaster */
	/* should not happen */
	if (tsrroutine->toastervalidate == NULL)
		elog(ERROR, "function toastervalidate is not defined for toaster %s",
			 get_toaster_name(toasteroid));

	result = tsrroutine->toastervalidate(typeoid, storage, compression,
										 amoid, false_ok);
#endif

	pfree(tsrroutine);

	return result;
}



#endif							/* TOASTERCACHE_H */