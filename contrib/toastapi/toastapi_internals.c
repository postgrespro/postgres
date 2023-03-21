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

	if (attrtuple->attnum <= 0)
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

	opts = transformRelOptions((Datum) 0, o_list, NULL, NULL, false, false);

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
	bool		isnull;
	Datum		repl_val[Natts_pg_attribute];
	bool		repl_null[Natts_pg_attribute];
	bool		repl_repl[Natts_pg_attribute];
	Datum opts, o_datum;
	List *o_list;
	Datum res = (Datum) 0;

	attrelation = table_open(AttributeRelationId, RowExclusiveLock);
	tuple = SearchSysCacheAttName(relOid, attname);

	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("column \"%s\" of relation \"%s\" does not exist",
						attname, RelationGetRelationName(attrelation))));

	attrtuple = (Form_pg_attribute) GETSTRUCT(tuple);

	if (attrtuple->attnum <= 0)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("cannot alter system column \"%s\"",
						attname)));
	o_datum = SysCacheGetAttr(ATTNAME, tuple, Anum_pg_attribute_attoptions,
							&isnull);

	o_list = list_make1(makeDefElem(optname, NULL, -1));

	opts = transformRelOptions(isnull ? (Datum) 0 : o_datum,
							   o_list, NULL, NULL, false, true);

	memset(repl_null, false, sizeof(repl_null));
	memset(repl_repl, false, sizeof(repl_repl));

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

Oid
get_toaster_by_name(Relation pg_toaster_rel, const char *tsrname, Oid *tsrhandler)
{
	SysScanDesc scan;
	HeapTuple	tup;
	Oid			tsroid = InvalidOid;

	scan = systable_beginscan(pg_toaster_rel, InvalidOid, false, NULL, 0, NULL);

	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		Form_pg_toaster tsr = (Form_pg_toaster) GETSTRUCT(tup);

		if (!namestrcmp(&tsr->tsrname, tsrname))
		{
			tsroid = tsr->oid;

			if (tsrhandler)
				*tsrhandler = tsr->tsrhandler;

			break;
		}
	}

	systable_endscan(scan);

	return tsroid;
}

char *
get_toaster_name(Oid tsroid)
{
	SysScanDesc scan;
	HeapTuple	tup;
	char	   *tsrname = NULL;
	Relation	pg_toaster_rel =
		get_rel_from_relname(cstring_to_text(PG_TOASTER_NAME), AccessShareLock, ACL_SELECT);

	scan = systable_beginscan(pg_toaster_rel, InvalidOid, false, NULL, 0, NULL);

	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		Form_pg_toaster tsr = (Form_pg_toaster) GETSTRUCT(tup);

		if (tsr->oid == tsroid)
		{
			tsrname = pstrdup(NameStr(tsr->tsrname));
			break;
		}
	}

	systable_endscan(scan);
	table_close(pg_toaster_rel, AccessShareLock);

	return tsrname;
}
