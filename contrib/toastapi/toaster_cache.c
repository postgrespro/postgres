#include "postgres.h"

#include "access/genam.h"
#include "access/htup_details.h"
#include "access/table.h"
#include "catalog/pg_type.h"
#include "utils/builtins.h"
#include "utils/catcache.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"

#include "toastapi.h"
#include "toaster_cache.h"
#include "toastapi_internals.h"
#include "pg_toaster.h"

static List	*ToasterCache = NIL;

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

/*
 * SearchTsrCache - get cached toaster routine, emits an error if toaster
 * doesn't exist
 */
TsrRoutine*
SearchTsrHandlerCache(Oid	toastHandlerOid)
{
	ListCell		   *lc;
	ToasterCacheEntry  *entry;
	MemoryContext		ctx;

	if (list_length(ToasterCache) > 0)
	{
		/* fast path */
		entry = (ToasterCacheEntry*)linitial(ToasterCache);
		if (entry->toasterOid == toastHandlerOid)
			return entry->routine;
	}

	/* didn't find in first position */
	ctx = MemoryContextSwitchTo(CacheMemoryContext);

	for_each_from(lc, ToasterCache, 0)
	{
		entry = (ToasterCacheEntry*)lfirst(lc);

		if (entry->toasterOid == toastHandlerOid)
		{
			goto out;
		}
	}

	/* did not find entry, make a new one */
	entry = palloc(sizeof(*entry));

	entry->toasterOid = toastHandlerOid;
	entry->routine = GetTsrRoutine(toastHandlerOid);

	ToasterCache = lappend(ToasterCache, entry);

out:
	MemoryContextSwitchTo(ctx);

	return entry->routine;
}

static void
reportMissingToastMethod(const char *method_name, Oid tsrhandler)
{
	ereport(ERROR,
			(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
			 errmsg("mandatory function %s is not present in toaster routine returned by toast handler function %u",
					"toast()", tsrhandler))); /* get_toaster_name(tsroid) */
}

/*
 * GetRoutine - call the specified toaster handler routine to get
 * its TsrRoutine struct, which will be palloc'd in the caller's context.
 */
TsrRoutine *
GetTsrRoutine(Oid tsrhandler)
{
	TsrRoutine *routine = (TsrRoutine *)
		DatumGetPointer(OidFunctionCall0(tsrhandler));

	if (routine == NULL) /* || !IsA(routine, TsrRoutine)) */
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("toaster handler function %u did not return a %s",
						tsrhandler, "struct TsrRoutine")));

	if (!routine->toast)
		reportMissingToastMethod("toast()", tsrhandler);

	if (!routine->detoast)
		reportMissingToastMethod("detoast()", tsrhandler);

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
	regproc		tsrhandler = InvalidOid;

	Relation	rel;
	Relation   relindx;
	Oid			idx_oid;
	int			num_indexes = 0;
   Oid relid = InvalidOid;
	bool		found = false;
	List	   *indexlist;
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
				 errmsg("cannot open \"%s\" table", "PG_TOASTER")));

	indexlist = RelationGetIndexList(rel);

	Assert(indexlist != NIL);

	num_indexes = list_length(indexlist);
	if (num_indexes <= 0)
	{
		table_close(rel, RowExclusiveLock);
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_FUNCTION),
				 errmsg("no valid indexes for toast relation with Oid %u", relid)));
	}


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

	/*
	 * Get the handler function oid, verifying the toaster type while at it.
	 */
	if (!RegProcedureIsValid(tsrhandler))
	{
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("toaster \"%u\" does not have a handler",
						tsroid)));
	}
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

	/* should not happen */
	if (tsrroutine->toastervalidate == NULL)
		elog(ERROR, "function toastervalidate is not defined for toaster %s",
			 get_toaster_name(toasteroid));

	result = tsrroutine->toastervalidate(toasteroid, typeoid,
										 storage, compression,
										 amoid, false_ok);

	pfree(tsrroutine);

	Assert(result || false_ok);

	return result;
}
