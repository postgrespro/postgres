#include "postgres.h"
#include "varatt.h"
#include "fmgr.h"
#include "toastapi_internals.h"
#include "access/heaptoast.h"
#include "access/htup_details.h"
#include "commands/defrem.h"
#include "utils/builtins.h"
#include "utils/syscache.h"
#include "access/toast_compression.h"
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
#include "catalog/pg_collation.h"
#include "catalog/pg_type.h"
#include "catalog/toasting.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "access/relation.h"
#include "access/genam.h"
#include "access/table.h"
#include "access/reloptions.h"
#include "access/attoptions.h"
#include "utils/rel.h"
#include "utils/relcache.h"
#include "utils/lsyscache.h"
#include "utils/varlena.h"
#include "utils/guc.h"
#include "parser/parse_func.h"
#include "toaster_cache.h"

Relation
get_rel_from_relname(text *relname_text, LOCKMODE lockmode, AclMode aclmode)
{
	RangeVar   *relvar;
	Relation	rel;
	AclResult	aclresult;

	relvar = makeRangeVarFromNameList(textToQualifiedNameList(relname_text));
	rel = table_openrv(relvar, lockmode);

	aclresult = pg_class_aclcheck(RelationGetRelid(rel), GetUserId(),
								  aclmode);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, get_relkind_objtype(rel->rd_rel->relkind),
					   RelationGetRelationName(rel));

	return rel;
}

/*
 * Convert a handler function name to an Oid.  If the return type of the
 * function doesn't match the given toaster type, an error is raised.
 *
 * This function either return valid function Oid or throw an error.
 */
Oid
lookup_toaster_handler_func(List *handler_name)
{
	Oid			handlerOid;
	Oid			funcargtypes[1] = {INTERNALOID};

	if (handler_name == NIL)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_FUNCTION),
				 errmsg("handler function is not specified")));

	/* handlers have one argument of type internal */
	handlerOid = LookupFuncName(handler_name, 1, funcargtypes, false);
/*
	if (get_func_rettype(handlerOid) != TOASTER_HANDLEROID)
		ereport(ERROR,
				(errcode(ERRCODE_WRONG_OBJECT_TYPE),
				 errmsg("function %s must return type %s",
						get_func_name(handlerOid),
						format_type_extended(TOASTER_HANDLEROID, -1, 0))));
*/
	return handlerOid;
}

Datum
attopts_get_toaster_opts(Oid relOid, char *attname, int attnum, char *optname)
{
	List *o_list = NIL;
	ListCell   *cell;
	Datum o_datum;
	int l_idx = 0;
	char *str = NULL;

	o_datum = get_attoptions(relOid, attnum);
   if(o_datum == (Datum) 0) return (Datum) 0;

   o_list =  untransformRelOptions(o_datum);

	foreach(cell, o_list)
	{
		DefElem    *def = (DefElem *) lfirst(cell);
		if (strcmp(def->defname, optname) == 0)
		{
			str = palloc(strlen(defGetString(def))+1);
			memcpy(str, defGetString(def), strlen(defGetString(def))+1);
			break;
		}
		l_idx++;
	}

	if(str == NULL)
		return (Datum) 0;
	return CStringGetDatum(str);
}

Datum
attopts_set_toaster_opts(Oid relOid, char *attname, char *optname, char *optval, int order)
{
	Relation	attrelation;
	HeapTuple	tuple,
				newtuple;
	Form_pg_attribute attrtuple;
	AttrNumber	attnum;
	bool		isnull;
	Datum		repl_val[Natts_pg_attribute];
	bool		repl_null[Natts_pg_attribute];
	bool		repl_repl[Natts_pg_attribute];
	Datum opts, o_datum;
	List *o_list;
	ListCell *cell;
	int l_idx = 0;
	Datum res = (Datum) 0;

	attrelation = table_open(AttributeRelationId, RowExclusiveLock);
	tuple = SearchSysCacheAttName(relOid, attname);

	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("column \"%s\" of relation \"%s\" does not exist",
						attname, RelationGetRelationName(attrelation))));

	attrtuple = (Form_pg_attribute) GETSTRUCT(tuple);

	attnum = attrtuple->attnum;
	if (attnum <= 0)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("cannot alter system column \"%s\"",
						attname)));
	o_datum = SysCacheGetAttr(ATTNAME, tuple, Anum_pg_attribute_attoptions,
							&isnull);

	o_list = untransformRelOptions(o_datum);

	memset(repl_null, false, sizeof(repl_null));
	memset(repl_repl, false, sizeof(repl_repl));

	l_idx = 0;

	foreach(cell, o_list)
	{
		DefElem    *def = (DefElem *) lfirst(cell);
		if (strcmp(def->defname, optname) == 0)
		{
			o_list = list_delete_nth_cell(o_list, l_idx);
			break;
		}
		else l_idx++;
	}

	if (order < 0)
		o_list = lcons(makeDefElem(optname, (Node *) makeString(optval), -1), o_list);
	else if (order == 0 && l_idx > 0)
		o_list = list_insert_nth(o_list, 1, makeDefElem(optname, (Node *) makeString(optval), -1));
	else
		o_list = lappend(o_list, makeDefElem(optname, (Node *) makeString(optval), -1));

	opts = transformRelOptions(isnull ? (Datum) 0 : o_datum,
									 o_list, NULL, NULL, false,
									 false);

	if (opts != (Datum) 0)
		repl_val[Anum_pg_attribute_attoptions - 1] = opts;
	else
		repl_null[Anum_pg_attribute_attoptions - 1] = true;
	repl_repl[Anum_pg_attribute_attoptions - 1] = true;
	newtuple = heap_modify_tuple(tuple, RelationGetDescr(attrelation),
								 repl_val, repl_null, repl_repl);
	CatalogTupleUpdate(attrelation, &newtuple->t_self, newtuple);

	heap_freetuple(newtuple);

	ReleaseSysCache(tuple);

	table_close(attrelation, RowExclusiveLock);
	CommandCounterIncrement();
	return res;

}

Datum
attopts_clear_toaster_opts(Oid relOid, char *attname, char *optname)
{
	Relation	attrelation;
	HeapTuple	tuple,
				newtuple;
	Form_pg_attribute attrtuple;
	AttrNumber	attnum;
	bool		isnull;
	Datum		repl_val[Natts_pg_attribute];
	bool		repl_null[Natts_pg_attribute];
	bool		repl_repl[Natts_pg_attribute];
	Datum opts, o_datum;
	List *o_list;
	ListCell *cell;
	int l_idx = 0;
	Datum res = (Datum) 0;

	attrelation = table_open(AttributeRelationId, RowExclusiveLock);
	tuple = SearchSysCacheAttName(relOid, attname);

	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("column \"%s\" of relation \"%s\" does not exist",
						attname, RelationGetRelationName(attrelation))));

	attrtuple = (Form_pg_attribute) GETSTRUCT(tuple);

	attnum = attrtuple->attnum;
	if (attnum <= 0)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("cannot alter system column \"%s\"",
						attname)));
	o_datum = SysCacheGetAttr(ATTNAME, tuple, Anum_pg_attribute_attoptions,
							&isnull);

	o_list = untransformRelOptions(o_datum);

	memset(repl_null, false, sizeof(repl_null));
	memset(repl_repl, false, sizeof(repl_repl));

	l_idx = 0;

	foreach(cell, o_list)
	{
		DefElem    *def = (DefElem *) lfirst(cell);
		if (strcmp(def->defname, optname) == 0)
		{
			o_list = list_delete_nth_cell(o_list, l_idx);
			break;
		}
		else l_idx++;
	}

	opts = transformRelOptions(isnull ? (Datum) 0 : o_datum,
									 o_list, NULL, NULL, false,
									 false);

	if (opts != (Datum) 0)
		repl_val[Anum_pg_attribute_attoptions - 1] = opts;
	else
		repl_null[Anum_pg_attribute_attoptions - 1] = true;
	repl_repl[Anum_pg_attribute_attoptions - 1] = true;
	newtuple = heap_modify_tuple(tuple, RelationGetDescr(attrelation),
								 repl_val, repl_null, repl_repl);
	CatalogTupleUpdate(attrelation, &newtuple->t_self, newtuple);

	heap_freetuple(newtuple);

	ReleaseSysCache(tuple);

	table_close(attrelation, RowExclusiveLock);
	CommandCounterIncrement();
	return res;
}

void create_pg_toaster(void)
{
	Datum reloptions = (Datum) 0;
	Oid ownerId;
	TupleDesc	tupdesc;
	bool		shared_relation;
	bool		mapped_relation;
	Relation	toast_rel;
	Oid			pgtoaster_relid = InvalidOid;
	Oid			namespaceid;
	char		toast_relname[NAMEDATALEN];
	char		toast_idxname[NAMEDATALEN];
	IndexInfo  *indexInfo;
	Oid			collationObjectId[1];
	Oid			classObjectId[1];
	int16		coloptions[1];
	RangeVar   *relvar;
	Relation	rel;

	snprintf(toast_relname, sizeof(toast_relname),
			 "pg_toaster");
	snprintf(toast_idxname, sizeof(toast_idxname),
			 "pg_toaster_index");

	PG_TRY();
	{
		relvar = makeRangeVarFromNameList(textToQualifiedNameList(cstring_to_text(toast_relname)));
		rel = table_openrv(relvar, AccessShareLock);
		if(rel)
		{
			pgtoaster_relid = RelationGetRelid(rel);
			table_close(rel, AccessShareLock);
		}
	}
	PG_CATCH();
	{
		pgtoaster_relid = InvalidOid;
		rel = NULL;
	}
	PG_END_TRY();

	if(OidIsValid(pgtoaster_relid))
	{
		return;
	}

	tupdesc = CreateTemplateTupleDesc(3);
	TupleDescInitEntry(tupdesc, (AttrNumber) 1,
					   "tsroid",
					   OIDOID,
					   -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 2,
					   "tsrname",
					   NAMEOID,
					   -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 3,
					   "tsrhandler",
					   REGPROCOID,
					   -1, 0);

	TupleDescAttr(tupdesc, 0)->attstorage = TYPSTORAGE_PLAIN;
	TupleDescAttr(tupdesc, 1)->attstorage = TYPSTORAGE_PLAIN;
	TupleDescAttr(tupdesc, 2)->attstorage = TYPSTORAGE_PLAIN;

	TupleDescAttr(tupdesc, 0)->attcompression = InvalidCompressionMethod;
	TupleDescAttr(tupdesc, 1)->attcompression = InvalidCompressionMethod;
	TupleDescAttr(tupdesc, 2)->attcompression = InvalidCompressionMethod;

	/* create pg_toaster in pg_toast namespace */
	namespaceid = PG_PUBLIC_NAMESPACE;

	/* Toast table is shared if and only if its parent is. */
	shared_relation = false;

	/* It's mapped if and only if its parent is, too */
	mapped_relation = false;

	ownerId = GetUserId();

	pgtoaster_relid = heap_create_with_catalog(toast_relname,
										   namespaceid,
										   InvalidOid,
										   InvalidOid,
										   InvalidOid,
										   InvalidOid,
										   ownerId,
										   HEAP_TABLE_AM_OID,
										   tupdesc,
										   NIL,
										   RELKIND_RELATION,
										   RELPERSISTENCE_PERMANENT,
										   shared_relation,
										   mapped_relation,
										   ONCOMMIT_NOOP,
										   reloptions,
										   false,
										   true,
										   true,
										   InvalidOid,
										   NULL);
	Assert(pgtoaster_relid != InvalidOid);
	/* make the toast relation visible, else table_open will fail */
	CommandCounterIncrement();

	/* ShareLock is not really needed here, but take it anyway */
	toast_rel = table_open(pgtoaster_relid, ShareLock);

	indexInfo = makeNode(IndexInfo);
	indexInfo->ii_NumIndexAttrs = 1;
	indexInfo->ii_NumIndexKeyAttrs = 1;
	indexInfo->ii_IndexAttrNumbers[0] = 1;
//	indexInfo->ii_IndexAttrNumbers[1] = 1;
	indexInfo->ii_Expressions = NIL;
	indexInfo->ii_ExpressionsState = NIL;
	indexInfo->ii_Predicate = NIL;
	indexInfo->ii_PredicateState = NULL;
	indexInfo->ii_ExclusionOps = NULL;
	indexInfo->ii_ExclusionProcs = NULL;
	indexInfo->ii_ExclusionStrats = NULL;
	indexInfo->ii_OpclassOptions = NULL;
	indexInfo->ii_Unique = true;
	indexInfo->ii_NullsNotDistinct = false;
	indexInfo->ii_ReadyForInserts = true;
	indexInfo->ii_CheckedUnchanged = false;
	indexInfo->ii_IndexUnchanged = false;
	indexInfo->ii_Concurrent = false;
	indexInfo->ii_BrokenHotChain = false;
	indexInfo->ii_ParallelWorkers = 0;
	indexInfo->ii_Am = BTREE_AM_OID;
	indexInfo->ii_AmCache = NULL;
	indexInfo->ii_Context = CurrentMemoryContext;

	collationObjectId[0] = InvalidOid;
//	collationObjectId[1] = DEFAULT_COLLATION_OID;

	classObjectId[0] = OID_BTREE_OPS_OID;
//	classObjectId[1] = TEXT_BTREE_OPS_OID;

	coloptions[0] = 0;
//	coloptions[1] = 0;

	index_create(toast_rel, toast_idxname, InvalidOid, InvalidOid,
				 InvalidOid, InvalidOid,
				 indexInfo,
				 list_make1("tsroid"), // ,"tsrname"),
				 BTREE_AM_OID,
				 InvalidOid,
				 collationObjectId, classObjectId, coloptions, (Datum) 0,
				 INDEX_CREATE_IS_PRIMARY, 0, true, true, NULL);
	table_close(toast_rel, ShareLock);

	CommandCounterIncrement();
	// return pgtoaster_relid;
}
