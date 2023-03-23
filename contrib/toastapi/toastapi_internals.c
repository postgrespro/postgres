#include "postgres.h"

#include "access/reloptions.h"
#include "access/table.h"
#include "access/xact.h"
#include "catalog/indexing.h"
#include "catalog/namespace.h"
#include "catalog/pg_type.h"
#include "commands/defrem.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "parser/parse_func.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/syscache.h"
#include "utils/varlena.h"

#include "toastapi.h"
#include "toastapi_internals.h"
#include "pg_toaster.h"

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

static void
toaster_attopts_init_ext(ToastAttrContext *cxt, Relation rel,
						 const char *attname, int attnum, bool for_update, Oid toasterid)
{
	Form_pg_attribute att;
	HeapTuple	tuple;
	bool		isnull;
	Oid			relid = RelationGetRelid(rel);

	cxt->attrel_lockmode = for_update ? RowExclusiveLock : RowShareLock;
	cxt->attrel = table_open(AttributeRelationId, cxt->attrel_lockmode);

	tuple = attname ? SearchSysCacheAttName(relid, attname) : SearchSysCacheAttNum(relid, attnum);

	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("column \"%s\" of relation \"%s\" does not exist",
						attname, RelationGetRelationName(rel))));

	cxt->atttup = tuple;
	att = (Form_pg_attribute) GETSTRUCT(tuple);

	if (att->attnum <= 0 && for_update)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("cannot alter system column \"%s\"",
						attname)));

	/* validate toaster, if needed */
	if (OidIsValid(toasterid))
		validateToaster(toasterid, att->atttypid, att->attstorage,
						att->attcompression, rel->rd_rel->relam, false);

	cxt->attnum = att->attnum;

	cxt->attoptions =
		SysCacheGetAttr(ATTNAME, tuple, Anum_pg_attribute_attoptions,
						&isnull);

	if (isnull)
		cxt->attoptions = (Datum) 0;
}

void
toaster_attopts_init(ToastAttrContext *cxt, Relation rel,
					 const char *attname, bool for_update, Oid toasterid)
{
	toaster_attopts_init_ext(cxt, rel, attname, -1, for_update, toasterid);
}

void
toaster_attopts_free(ToastAttrContext *cxt)
{
	ReleaseSysCache(cxt->atttup);
	table_close(cxt->attrel, cxt->attrel_lockmode);
}

char *
toaster_attopts_get(ToastAttrContext *cxt, char *optname)
{
	List	   *o_list = untransformRelOptions(cxt->attoptions);
	ListCell   *cell;

	foreach(cell, o_list)
	{
		DefElem    *def = lfirst(cell);

		if (!strcmp(def->defname, optname))
			return pstrdup(defGetString(def));
	}

	return NULL;
}

void
toaster_attopts_set(ToastAttrContext *cxt, char *optname, char *optval, int order)
{
	List	   *o_list = untransformRelOptions(cxt->attoptions);
	ListCell   *cell;
	int			l_idx = 0;

	foreach(cell, o_list)
	{
		DefElem    *def = lfirst(cell);

		if (!strcmp(def->defname, optname))
		{
			o_list = list_delete_nth_cell(o_list, l_idx);
			break;
		}

		l_idx++;
	}

	if (order < 0)
		o_list = lcons(makeDefElem(optname, (Node *) makeString(optval), -1), o_list);
	else if (order == 0 && l_idx > 0)
		o_list = list_insert_nth(o_list, 1, makeDefElem(optname, (Node *) makeString(optval), -1));
	else
		o_list = lappend(o_list, makeDefElem(optname, (Node *) makeString(optval), -1));

	cxt->attoptions = transformRelOptions((Datum) 0, o_list, NULL, NULL, false, false);
}

void
toaster_attopts_clear(ToastAttrContext *cxt, char *optname)
{
	List	   *o_list = list_make1(makeDefElem(optname, NULL, -1));

	cxt->attoptions = transformRelOptions(cxt->attoptions, o_list, NULL, NULL, false, true);
}

void
toaster_attopts_update(ToastAttrContext *cxt)
{
	HeapTuple	newtuple;
	Datum		repl_val[Natts_pg_attribute];
	bool		repl_null[Natts_pg_attribute];
	bool		repl_repl[Natts_pg_attribute];
	Datum		opts = cxt->attoptions;

	memset(repl_null, false, sizeof(repl_null));
	memset(repl_repl, false, sizeof(repl_repl));

	if (opts != (Datum) 0)
		repl_val[Anum_pg_attribute_attoptions - 1] = opts;
	else
		repl_null[Anum_pg_attribute_attoptions - 1] = true;
	repl_repl[Anum_pg_attribute_attoptions - 1] = true;

	newtuple = heap_modify_tuple(cxt->atttup, RelationGetDescr(cxt->attrel),
								 repl_val, repl_null, repl_repl);
	CatalogTupleUpdate(cxt->attrel, &newtuple->t_self, newtuple);

	heap_freetuple(newtuple);

	CommandCounterIncrement();
}

char *
attopts_get_toaster_opts(Relation rel, int attnum, char *optname)
{
	ToastAttrContext cxt;
	char	   *res;

	toaster_attopts_init_ext(&cxt, rel, NULL, attnum, false, InvalidOid);
	res = toaster_attopts_get(&cxt, optname);
	toaster_attopts_free(&cxt);

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
