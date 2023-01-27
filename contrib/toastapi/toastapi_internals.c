#include "postgres.h"
#include "varatt.h"
#include "fmgr.h"
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
#include "catalog/pg_type.h"
#include "catalog/toasting.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "access/relation.h"
#include "access/genam.h"
#include "access/table.h"
#include "access/reloptions.h"
#include "utils/rel.h"
#include "utils/relcache.h"
#include "utils/lsyscache.h"
#include "utils/varlena.h"
#include "utils/guc.h"
#include "parser/parse_func.h"
#include "toastapi_internals.h"

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

void load_toaster_cache(void)
{
	return;
}

void load_toastrel_cache(void)
{
	return;
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

	if (get_func_rettype(handlerOid) != TOASTER_HANDLEROID)
		ereport(ERROR,
				(errcode(ERRCODE_WRONG_OBJECT_TYPE),
				 errmsg("function %s must return type %s",
						get_func_name(handlerOid),
						format_type_extended(TOASTER_HANDLEROID, -1, 0))));

	return handlerOid;
}


Datum
relopts_get_toaster_opts(Datum reloptions, Oid *relid, Oid *toasterid)
{
	List	   *options_list = untransformRelOptions(reloptions);
	ListCell   *cell;

	foreach(cell, options_list)
	{
		DefElem    *def = (DefElem *) lfirst(cell);

		if (strcmp(def->defname, "relationoid") == 0
			|| strcmp(def->defname, "toasteroid") == 0)
		{
			char	   *value;
			int			int_val;
			bool		is_parsed;

			value = defGetString(def);
			is_parsed = parse_int(value, &int_val, 0, NULL);

			if (!is_parsed)
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						 errmsg("invalid value for integer option \"%s\": %s",
								def->defname, value)));

			if (int_val <= 0)
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						 errmsg("\"%s\" must be an integer value greater than zero",
								def->defname)));
			if(strcmp(def->defname, "relationoid") == 0)
				*relid = int_val;
			if(strcmp(def->defname, "toasteroid") == 0)
				*toasterid = int_val;
		}
	}
	return ObjectIdGetDatum(*relid);
}

Datum
relopts_set_toaster_opts(Datum reloptions, Oid relid, Oid toasterid)
{
	Datum toast_options;
	List    *defList = NIL;
	static char *validnsps[] = HEAP_RELOPT_NAMESPACES;

	defList = lappend(defList, makeDefElem("toasteroid", (Node *) makeInteger(toasterid), -1));
	defList = lappend(defList, makeDefElem("toastrelid", (Node *) makeInteger(relid), -1));

	toast_options = transformRelOptions(reloptions,
									 defList, NULL, validnsps, false,
									 false);

	(void) heap_reloptions(RELKIND_TOASTVALUE, toast_options, false);
	return toast_options;
}

void create_pg_toaster(void)
{
	Relation rel;
	Oid toastOid;
	Oid toastIndexOid;
	Oid toasteroid;
	Datum reloptions = (Datum) 0;
	int attnum;
	LOCKMODE lockmode;
	bool check;
	Oid OIDOldToast;
	Oid ownerId;
	HeapTuple	reltup;
	TupleDesc	tupdesc;
	bool		shared_relation;
	bool		mapped_relation;
	Relation	toast_rel;
	Relation	class_rel;
	Oid			pgtoaster_relid;
	Oid			namespaceid;
	char		toast_relname[NAMEDATALEN];
	char		toast_idxname[NAMEDATALEN];
	IndexInfo  *indexInfo;
	Oid			collationObjectId[2];
	Oid			classObjectId[2];
	int16		coloptions[2];
	ObjectAddress baseobject,
				toastobject;
	bool toastrel_insert_ind = false;
	int16 version = 0;
	NameData relname;
	NameData toastentname;
	char toastoptions = (char) 0;
	int tblnum = 0;

	snprintf(toast_relname, sizeof(toast_relname),
			 "pg_toaster");
	snprintf(toast_idxname, sizeof(toast_idxname),
			 "pg_toaster_index");

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
	namespaceid = PG_TOAST_NAMESPACE;

	/* Toast table is shared if and only if its parent is. */
	shared_relation = true;

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
	indexInfo->ii_NumIndexAttrs = 2;
	indexInfo->ii_NumIndexKeyAttrs = 2;
	indexInfo->ii_IndexAttrNumbers[0] = 1;
	indexInfo->ii_IndexAttrNumbers[1] = 1;
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
	collationObjectId[1] = InvalidOid;

	classObjectId[0] = OID_BTREE_OPS_OID;
	classObjectId[1] = TEXT_BTREE_OPS_OID;

	coloptions[0] = 0;
	coloptions[1] = 0;

	index_create(toast_rel, toast_idxname, InvalidOid, InvalidOid,
				 InvalidOid, InvalidOid,
				 indexInfo,
				 list_make2("tsroid","tsrname"),
				 BTREE_AM_OID,
				 InvalidOid,
				 collationObjectId, classObjectId, coloptions, (Datum) 0,
				 INDEX_CREATE_IS_PRIMARY, 0, true, true, NULL);
	table_close(toast_rel, NoLock);

	CommandCounterIncrement();
	// return pgtoaster_relid;
}

void create_pg_toastrel(void)
{
	bool check;
	Oid ownerId;
	HeapTuple	reltup;
	TupleDesc	tupdesc;
	bool		shared_relation;
	bool		mapped_relation;
	Relation	toast_rel;
	Relation	class_rel;
	Oid			pgtoastrel_relid;
	Oid			namespaceid;
	char		toast_relname[NAMEDATALEN];
	char		toast_idxname[NAMEDATALEN];
	IndexInfo  *indexInfo;
	Oid			collationObjectId[4];
	Oid			classObjectId[4];
	int16		coloptions[4];
	ObjectAddress baseobject,
				toastobject;
	bool toastrel_insert_ind = false;
	int16 version = 0;
	NameData relname;
	char toastoptions = (char) 0;
	int tblnum = 0;

	snprintf(toast_relname, sizeof(toast_relname),
			 "pg_toastrel");
	snprintf(toast_idxname, sizeof(toast_idxname),
			 "pg_toastrel_index");

	tupdesc = CreateTemplateTupleDesc(8);
	TupleDescInitEntry(tupdesc, (AttrNumber) 1,
					   "tsrecoid",
					   OIDOID,
					   -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 2,
					   "tsroid",
					   OIDOID,
					   -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 3,
					   "relid",
					   OIDOID,
					   -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 4,
					   "treloid",
					   OIDOID,
					   -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 5,
					   "attnum",
					   INT4OID,
					   -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 6,
					   "version",
					   INT4OID,
					   -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 7,
					   "a_flag",
					   INT2OID,
					   -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 8,
					   "toastoptions",
					   CHAROID,
					   -1, 0);

	TupleDescAttr(tupdesc, 0)->attstorage = TYPSTORAGE_PLAIN;
	TupleDescAttr(tupdesc, 1)->attstorage = TYPSTORAGE_PLAIN;
	TupleDescAttr(tupdesc, 2)->attstorage = TYPSTORAGE_PLAIN;
	TupleDescAttr(tupdesc, 3)->attstorage = TYPSTORAGE_PLAIN;
	TupleDescAttr(tupdesc, 4)->attstorage = TYPSTORAGE_PLAIN;
	TupleDescAttr(tupdesc, 5)->attstorage = TYPSTORAGE_PLAIN;
	TupleDescAttr(tupdesc, 6)->attstorage = TYPSTORAGE_PLAIN;
	TupleDescAttr(tupdesc, 7)->attstorage = TYPSTORAGE_PLAIN;

	TupleDescAttr(tupdesc, 0)->attcompression = InvalidCompressionMethod;
	TupleDescAttr(tupdesc, 1)->attcompression = InvalidCompressionMethod;
	TupleDescAttr(tupdesc, 2)->attcompression = InvalidCompressionMethod;
	TupleDescAttr(tupdesc, 3)->attcompression = InvalidCompressionMethod;
	TupleDescAttr(tupdesc, 4)->attcompression = InvalidCompressionMethod;
	TupleDescAttr(tupdesc, 5)->attcompression = InvalidCompressionMethod;
	TupleDescAttr(tupdesc, 6)->attcompression = InvalidCompressionMethod;
	TupleDescAttr(tupdesc, 7)->attcompression = InvalidCompressionMethod;

	/* create pg_toastrel in pg_toast namespace */
	namespaceid = PG_TOAST_NAMESPACE;

	shared_relation = true;

	mapped_relation = false;
	
	ownerId = GetUserId();

	pgtoastrel_relid = heap_create_with_catalog(toast_relname,
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
										   (Datum) 0,
										   false,
										   true,
										   true,
										   InvalidOid,
										   NULL);
	Assert(pgtoastrel_relid != InvalidOid);
	/* make the toast relation visible, else table_open will fail */
	CommandCounterIncrement();

	/* ShareLock is not really needed here, but take it anyway */
	toast_rel = table_open(pgtoastrel_relid, ShareLock);

	indexInfo = makeNode(IndexInfo);
	indexInfo->ii_NumIndexAttrs = 4;
	indexInfo->ii_NumIndexKeyAttrs = 4;
	indexInfo->ii_IndexAttrNumbers[0] = 1;
	indexInfo->ii_IndexAttrNumbers[1] = 1;
	indexInfo->ii_IndexAttrNumbers[3] = 1;
	indexInfo->ii_IndexAttrNumbers[4] = 1;
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
	collationObjectId[1] = InvalidOid;
	collationObjectId[2] = InvalidOid;
	collationObjectId[3] = InvalidOid;

	classObjectId[0] = OID_BTREE_OPS_OID;
	classObjectId[1] = OID_BTREE_OPS_OID;
	classObjectId[2] = INT4_BTREE_OPS_OID;
	classObjectId[3] = INT4_BTREE_OPS_OID;

	coloptions[0] = 0;
	coloptions[1] = 0;
	coloptions[2] = 0;
	coloptions[3] = 0;

	index_create(toast_rel, toast_idxname, InvalidOid, InvalidOid,
				 InvalidOid, InvalidOid,
				 indexInfo,
				 list_make4("tsroid","relid", "attnum", "version"),
				 BTREE_AM_OID,
				 InvalidOid,
				 collationObjectId, classObjectId, coloptions, (Datum) 0,
				 INDEX_CREATE_IS_PRIMARY, 0, true, true, NULL);
	table_close(toast_rel, NoLock);

	CommandCounterIncrement();
	// return pgtoastrel_relid;
}
