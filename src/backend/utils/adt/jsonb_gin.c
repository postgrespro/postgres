/*-------------------------------------------------------------------------
 *
 * jsonb_gin.c
 *	 GIN support functions for jsonb
 *
 * Copyright (c) 2014-2020, PostgreSQL Global Development Group
 *
 * We provide two opclasses for jsonb indexing: jsonb_ops and jsonb_path_ops.
 * For their description see json.sgml and comments in jsonb.h.
 *
 * The operators support, among the others, "jsonb @? jsonpath" and
 * "jsonb @@ jsonpath".  Expressions containing these operators are easily
 * expressed through each other.
 *
 *	jb @? 'path' <=> jb @@ 'EXISTS(path)'
 *	jb @@ 'expr' <=> jb @? '$ ? (expr)'
 *
 * Thus, we're going to consider only @@ operator, while regarding @? operator
 * the same is true for jb @@ 'EXISTS(path)'.
 *
 * Result of jsonpath query extraction is a tree, which leaf nodes are index
 * entries and non-leaf nodes are AND/OR logical expressions.  Basically we
 * extract following statements out of jsonpath:
 *
 *	1) "accessors_chain = const",
 *	2) "EXISTS(accessors_chain)".
 *
 * Accessors chain may consist of .key, [*] and [index] accessors.  jsonb_ops
 * additionally supports .* and .**.
 *
 * For now, both jsonb_ops and jsonb_path_ops supports only statements of
 * the 1st find.  jsonb_ops might also support statements of the 2nd kind,
 * but given we have no statistics keys extracted from accessors chain
 * are likely non-selective.  Therefore, we choose to not confuse optimizer
 * and skip statements of the 2nd kind altogether.  In future versions that
 * might be changed.
 *
 * In jsonb_ops statement of the 1st kind is split into expression of AND'ed
 * keys and const.  Sometimes const might be interpreted as both value or key
 * in jsonb_ops.  Then statement of 1st kind is decomposed into the expression
 * below.
 *
 *	key1 AND key2 AND ... AND keyN AND (const_as_value OR const_as_key)
 *
 * jsonb_path_ops transforms each statement of the 1st kind into single hash
 * entry below.
 *
 *	HASH(key1, key2, ... , keyN, const)
 *
 * Despite statements of the 2nd kind are not supported by both jsonb_ops and
 * jsonb_path_ops, EXISTS(path) expressions might be still supported,
 * when statements of 1st kind could be extracted out of their filters.
 *
 * IDENTIFICATION
 *	  src/backend/utils/adt/jsonb_gin.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/gin.h"
#include "access/hash.h"
#include "access/reloptions.h"
#include "access/stratnum.h"
#include "catalog/pg_collation.h"
#include "catalog/pg_type.h"
#include "common/hashfn.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "utils/json.h"
#include "utils/jsonb.h"
#include "utils/jsonpath.h"
#include "utils/varlena.h"

#define GIN_JSONB_PROJECTION_PARAM "projection"

/* jsonb_ops and json_path_ops options */
typedef struct GinJsonOptions
{
	int32		vl_len_;		/* varlena header (do not touch directly!) */
	int			pathsOffset;	/* offset of list of indexed json paths */
} GinJsonOptions;

#define GIN_GET_JSONPATHS(options) \
	((options) && VARSIZE(GET_STRING_RELOPTION((options), pathsOffset)) ? \
		(JsonPath *) GET_STRING_RELOPTION((options), pathsOffset) : NULL)

typedef struct PathHashStack
{
	uint32		hash;
	struct PathHashStack *parent;
} PathHashStack;

/* Buffer for GIN entries */
typedef struct GinEntries
{
	Datum	   *buf;
	int			count;
	int			allocated;
} GinEntries;

typedef enum JsonPathGinNodeType
{
	JSP_GIN_OR,
	JSP_GIN_AND,
	JSP_GIN_ENTRY
} JsonPathGinNodeType;

typedef struct JsonPathGinNode JsonPathGinNode;

/* Node in jsonpath expression tree */
struct JsonPathGinNode
{
	JsonPathGinNodeType type;
	union
	{
		int			nargs;		/* valid for OR and AND nodes */
		int			entryIndex; /* index in GinEntries array, valid for ENTRY
								 * nodes after entries output */
		Datum		entryDatum; /* path hash or key name/scalar, valid for
								 * ENTRY nodes before entries output */
	}			val;
	JsonPathGinNode *args[FLEXIBLE_ARRAY_MEMBER];	/* valid for OR and AND
													 * nodes */
};

/*
 * jsonb_ops entry extracted from jsonpath item.  Corresponding path item
 * may be: '.key', '.*', '.**', '[index]' or '[*]'.
 * Entry type is stored in 'type' field.
 */
typedef struct JsonPathGinPathItem
{
	struct JsonPathGinPathItem *parent;
	Datum		keyName;		/* key name (for '.key' path item) or NULL */
	JsonPathItemType type;		/* type of jsonpath item */
} JsonPathGinPathItem;

typedef List *JsonPathItemList;

/* GIN representation of the extracted json path */
typedef struct JsonPathGinPath
{
	JsonPathItemList path;			/* original sequence of JsonPathItems */
	union
	{
		JsonPathGinPathItem *items; /* list of path items (jsonb_ops) */
		uint32		hash;			/* hash of the path (jsonb_path_ops) */
	};
} JsonPathGinPath;

typedef struct JsonPathGinContext JsonPathGinContext;

/* Callback, which stores information about path item into JsonPathGinPath */
typedef bool (*JsonPathGinAddPathItemFunc) (JsonPathGinPath *path,
											JsonPathItem *jsp);

/*
 * Callback, which extracts set of nodes from statement of 1st kind
 * (scalar != NULL) or statement of 2nd kind (scalar == NULL).
 */
typedef List *(*JsonPathGinExtractNodesFunc) (JsonPathGinContext *cxt,
											  JsonPathGinPath path,
											  JsonbValue *scalar,
											  List *nodes);

/* Callback, which extract GIN "entries" for "jbv" placed at "path" */
typedef void (*JsonPathGinExtractEntriesFunc) (GinEntries *entries,
											   JsonbValue *jbv,
											   JsonPathGinPath path);


/* Common context for value/query extraction */
typedef struct JsonbGinContext
{
	GinJsonOptions *options;
	JsonPath   *indexed_paths;
	bool		lax_indexed_paths;
	JsonPathGinAddPathItemFunc add_path_item;
} JsonbGinContext;

/* Context for jsonpath query entries extraction */
struct JsonPathGinContext
{
	JsonbGinContext common;
	JsonPathGinExtractNodesFunc extract_nodes;
	bool		lax_query;
};

/* Context for jsonb value entries extraction */
typedef struct GinJsonExtractionContext
{
	JsonbGinContext common;
	GinEntries *entries;
	JsonbValue *root;
	JsonPathGinExtractEntriesFunc extract_entries;
} GinJsonExtractionContext;

/* Context for iteration through indexed paths */
typedef struct GinForEachPathContext
{
	void	   *cxt;
	bool		lax;
} GinForEachPathContext;


static Datum make_text_key(char flag, const char *str, int len);
static Datum make_scalar_key(const JsonbValue *scalarVal, bool is_key);

static JsonPathGinNode *extract_jsp_bool_expr(JsonPathGinContext *cxt,
											  JsonPathGinPath path,
											  JsonPathItem *jsp, bool not);

static Datum *gin_extract_jsonb_internal(Jsonb *jb, GinJsonOptions *options,
										 bool path_ops, int32 *nentries);

static void extract_jsonb_by_path(GinJsonExtractionContext *cxt,
								  JsonbValue *jbv, JsonPathItem *jsp,
								  JsonPathGinPath path);

static void init_gin_jsonb_context(JsonbGinContext *cxt,
								   GinJsonOptions *options, bool path_ops);

static bool jsonpath_match(JsonPathItem *index, List *query,
						   ListCell *querylc, bool lax, bool unwrap);

static void jsonb_path_ops__extract_entries(GinEntries *entries,
											JsonbValue *jbv,
											JsonPathGinPath path);

static void validate_indexed_json_paths(JsonPath *jspath);


/* Initialize GinEntries struct */
static void
init_gin_entries(GinEntries *entries, int preallocated)
{
	entries->allocated = preallocated;
	entries->buf = preallocated ? palloc(sizeof(Datum) * preallocated) : NULL;
	entries->count = 0;
}

/* Add new entry to GinEntries */
static int
add_gin_entry(GinEntries *entries, Datum entry)
{
	int			id = entries->count;

	if (entries->count >= entries->allocated)
	{
		if (entries->allocated)
		{
			entries->allocated *= 2;
			entries->buf = repalloc(entries->buf,
									sizeof(Datum) * entries->allocated);
		}
		else
		{
			entries->allocated = 8;
			entries->buf = palloc(sizeof(Datum) * entries->allocated);
		}
	}

	entries->buf[entries->count++] = entry;

	return id;
}

/*
 *
 * jsonb_ops GIN opclass support functions
 *
 */

Datum
gin_compare_jsonb(PG_FUNCTION_ARGS)
{
	text	   *arg1 = PG_GETARG_TEXT_PP(0);
	text	   *arg2 = PG_GETARG_TEXT_PP(1);
	int32		result;
	char	   *a1p,
			   *a2p;
	int			len1,
				len2;

	a1p = VARDATA_ANY(arg1);
	a2p = VARDATA_ANY(arg2);

	len1 = VARSIZE_ANY_EXHDR(arg1);
	len2 = VARSIZE_ANY_EXHDR(arg2);

	/* Compare text as bttextcmp does, but always using C collation */
	result = varstr_cmp(a1p, len1, a2p, len2, C_COLLATION_OID);

	PG_FREE_IF_COPY(arg1, 0);
	PG_FREE_IF_COPY(arg2, 1);

	PG_RETURN_INT32(result);
}

Datum
gin_extract_jsonb(PG_FUNCTION_ARGS)
{
	Jsonb	   *jb = (Jsonb *) PG_GETARG_JSONB_P(0);
	int32	   *nentries = (int32 *) PG_GETARG_POINTER(1);
	GinJsonOptions *options = (GinJsonOptions *) PG_GET_OPCLASS_OPTIONS();

	PG_RETURN_POINTER(gin_extract_jsonb_internal(jb, options, false, nentries));
}

/* Extract entries from container */
static void
jsonb_ops__extract_container(GinEntries *entries, JsonbContainer *jbc)
{
	JsonbIterator *it;
	JsonbValue	v;
	JsonbIteratorToken r;

	it = JsonbIteratorInit(jbc);

	while ((r = JsonbIteratorNext(&it, &v, false)) != WJB_DONE)
	{
		switch (r)
		{
			case WJB_KEY:
				add_gin_entry(entries, make_scalar_key(&v, true));
				break;
			case WJB_ELEM:
				/* Pretend string array elements are keys, see jsonb.h */
				add_gin_entry(entries, make_scalar_key(&v, v.type == jbvString));
				break;
			case WJB_VALUE:
				add_gin_entry(entries, make_scalar_key(&v, false));
				break;
			default:
				/* we can ignore structural items */
				break;
		}
	}
}

/* jsonb_ops: Extract entries from container placed at "path" */
static void
jsonb_ops__extract_entries(GinEntries *entries, JsonbValue *jbv,
						   JsonPathGinPath path)
{
	JsonPathGinPathItem *item;
	bool		is_array_elem = true;	/* raw scalars */

	/* Add all entries from the preceding path */
	for (item = path.items; item; item = item->parent)
	{
		is_array_elem = !DatumGetPointer(item->keyName);

		if (!is_array_elem)		/* XXX optimize duplicate entries */
			add_gin_entry(entries, item->keyName);
	}

	/* Add all entries from the jsonb value itself */
	if (jbv->type == jbvBinary)
		jsonb_ops__extract_container(entries, jbv->val.binary.data);
	else
		add_gin_entry(entries,
					  make_scalar_key(jbv,
					  /* Pretend string array elements are keys, see jsonb.h */
									  is_array_elem && jbv->type == jbvString));
}

/* Functions for extraction jsonb by jsonpath */

static int32
jsonpath_get_array_index(JsonPathItem *idx)
{
	if (idx->type != jpiNumeric || jspHasNext(idx))
		elog(ERROR, "invalid array subscript in GIN json path");

	return DatumGetInt32(
		DirectFunctionCall1(numeric_int4,
			DirectFunctionCall2(numeric_trunc,
								NumericGetDatum(jspGetNumeric(idx)),
								Int32GetDatum(0))));
}

static void
extract_jsonb_any_path(GinJsonExtractionContext *cxt, JsonbValue *jbv,
					   JsonPathItem *next, JsonPathGinPath path,
					   uint32 level, uint32 first, uint32 last)
{
	JsonbIterator *it;
	JsonbValue	v;
	JsonbIteratorToken r;
	JsonPathGinPath childpath = path;
	JsonPathItem jsp;

	check_stack_depth();

	if (level > last)
		return;

	if (level >= first)
		extract_jsonb_by_path(cxt, jbv, next, path);

	if (level >= last)
		return;

	if (jbv->type != jbvBinary)
		return;

	if (JsonContainerIsArray(jbv->val.binary.data))
	{
		jsp.type = jpiAnyArray;
		cxt->common.add_path_item(&childpath, &jsp);
	}

	it = JsonbIteratorInit(jbv->val.binary.data);

	while ((r = JsonbIteratorNext(&it, &v, true)) != WJB_DONE)
	{
		if (r == WJB_KEY)
		{
			jsp.type = jpiKey;
			jsp.content.value.data = v.val.string.val;
			jsp.content.value.datalen = v.val.string.len;

			childpath = path;
			cxt->common.add_path_item(&childpath, &jsp);
		}
		else if (r == WJB_VALUE || r == WJB_ELEM)
			extract_jsonb_any_path(cxt, &v, next, childpath, level + 1,
								   first, last);
	}
}

static void
extract_jsonb_by_path(GinJsonExtractionContext *cxt, JsonbValue *jbv,
					  JsonPathItem *jsp, JsonPathGinPath path)
{
	JsonPathItem nextbuf;
	JsonPathItem *next;

	check_stack_depth();

	if (!jsp)
	{
		cxt->extract_entries(cxt->entries, jbv, path);
		return;
	}

	next = jspGetNext(jsp, &nextbuf) ? &nextbuf : NULL;

	switch (jsp->type)
	{
		case jpiKey:
			{
				JsonbValue	key;
				JsonbValue *val;

				if (jbv->type != jbvBinary ||
					!JsonContainerIsObject(jbv->val.binary.data))
					return;

				key.type = jbvString;
				key.val.string.val = jspGetString(jsp, &key.val.string.len);

				val = findJsonbValueFromContainer(jbv->val.binary.data,
												  JB_FOBJECT, &key);
				if (!val)
					return;

				cxt->common.add_path_item(&path, jsp);
				extract_jsonb_by_path(cxt, val, next, path);
				break;
			}

		case jpiIndexArray:
			{
				int			i;
				JsonbContainer *jbc = jbv->val.binary.data;

				if (jbv->type != jbvBinary || !JsonContainerIsArray(jbc))
					return;

				cxt->common.add_path_item(&path, jsp);

				for (i = 0; i < jsp->content.array.nelems; i++)
				{
					JsonPathItem from;
					JsonPathItem to;
					bool		range;
					int32		fromIdx;

					range = jspGetArraySubscript(jsp, &from, &to, i);

					fromIdx = jsonpath_get_array_index(&from);

					if (range)
					{
						JsonbIterator *it;
						JsonbValue	elem;
						JsonbIteratorToken tok;
						int32		toIdx =  jsonpath_get_array_index(&to);
						int32		idx = 0;

						if (toIdx > fromIdx)
							return;

						if (fromIdx >= JsonContainerSize(jbc))
							return;

						it = JsonbIteratorInit(jbc);

						while ((tok = JsonbIteratorNext(&it, &elem, true)) != WJB_DONE)
						{
							if (tok != WJB_ELEM)
								continue;

							if (idx >= fromIdx)
								extract_jsonb_by_path(cxt, &elem, next, path);

							idx++;

							if (idx > toIdx)
								break;
						}
					}
					else
					{
						JsonbValue *elem =
							getIthJsonbValueFromContainer(jbc, fromIdx);

						extract_jsonb_by_path(cxt, elem, next, path);
					}
				}

				break;
			}

		case jpiAnyKey:
			if (jbv->type != jbvBinary ||
				!JsonContainerIsObject(jbv->val.binary.data))
				return;

			extract_jsonb_any_path(cxt, jbv, next, path, 0, 1, 1);
			break;

		case jpiAnyArray:
			if (jbv->type != jbvBinary ||
				!JsonContainerIsArray(jbv->val.binary.data))
				return;

			extract_jsonb_any_path(cxt, jbv, next, path, 0, 1, 1);
			break;

		case jpiAny:
			extract_jsonb_any_path(cxt, jbv, next, path, 0,
								   jsp->content.anybounds.first,
								   jsp->content.anybounds.last);
			break;

		default:
			elog(ERROR, "invalid item type in GIN jsonpath: %d", jsp->type);
	}
}

static GinTernaryValue
foreach_jsonpath(JsonPath *paths,
				 GinTernaryValue (*callback)(GinForEachPathContext *context,
											 JsonPathItem *jsp),
				 void *cxt)
{
	GinForEachPathContext context;
	JsonPathItem jsp;

	context.lax = (paths->header & JSONPATH_LAX) != 0;
	context.cxt = cxt;

	jspInit(&jsp, paths);

	if (jsp.type == jpiSequence)
	{
		GinTernaryValue res = GIN_FALSE;

		for (int i = 0; i < jsp.content.sequence.nelems; i++)
		{
			JsonPathItem elem;
			GinTernaryValue r;

			jspGetSequenceElement(&jsp, i, &elem);

			r = callback(&context, &elem);

			if (r == GIN_TRUE)
				return GIN_TRUE;	/* path is found */

			if (r == GIN_MAYBE)
				res = GIN_MAYBE;
		}

		return res;
	}
	else
	{
		return callback(&context, &jsp);
	}
}

static GinTernaryValue
gin_extract_jsonb_paths_cb(GinForEachPathContext *context, JsonPathItem *root)
{
	GinJsonExtractionContext *cxt = context->cxt;

	cxt->common.lax_indexed_paths = context->lax;

	if (root->type == jpiRoot)
	{
		JsonPathGinPath path = { 0 };
		JsonPathItem next;

		extract_jsonb_by_path(cxt, cxt->root,
							  jspGetNext(root, &next) ? &next : NULL, path);
	}

	return GIN_FALSE;
}

static Datum *
gin_extract_jsonb_internal(Jsonb *jb, GinJsonOptions *options, bool path_ops,
						   int32 *nentries)
{
	GinJsonExtractionContext cxt;
	GinEntries	entries;
	JsonbValue	root;
	int			size = JB_ROOT_COUNT(jb);

	/* If the root level is empty, we certainly have no keys */
	if (!size)
	{
		*nentries = 0;
		return NULL;
	}

	/* Otherwise, use 2 * root count as initial estimate of result size */
	init_gin_entries(&entries, 2 * size);

	init_gin_jsonb_context(&cxt.common, options, path_ops);

	cxt.root = &root;
	cxt.entries = &entries;
	cxt.extract_entries =
		path_ops ? jsonb_path_ops__extract_entries : jsonb_ops__extract_entries;

	if (!JsonbExtractScalar(&jb->root, &root))
	{
		root.type = jbvBinary;
		root.val.binary.data = &jb->root;
		root.val.binary.len = VARSIZE_ANY_EXHDR(jb);
	}

	if (cxt.common.indexed_paths)
	{
		/* Extract only indexed paths from the container */
		foreach_jsonpath(cxt.common.indexed_paths,
						 gin_extract_jsonb_paths_cb, &cxt);
	}
	else
	{
		/* Extract all paths from the container */
		JsonPathGinPath path = {0};

		cxt.extract_entries(&entries, &root, path);
	}

	*nentries = entries.count;

	return entries.buf;
}

/* Get integer index range if it is constant */
static bool
jsonpath_array_indexes_get_range(JsonPathItem *arr, int i,
								 int32 *fromidx, int32 *toidx)
{
	JsonPathItem from;
	JsonPathItem to;
	bool		range;

	range = jspGetArraySubscript(arr, &from, &to, i);

	if (from.type != jpiNumeric || jspHasNext(&from))
		return false;

	*fromidx = jsonpath_get_array_index(&from);

	if (range)
	{
		if (to.type != jpiNumeric || jspHasNext(&to))
			return false;

		*toidx = jsonpath_get_array_index(&to);
	}
	else
	{
		*toidx = *fromidx;
	}

	return true;
}

static bool
jsonpath_array_indexes_contains(JsonPathItem *jsp, int32 index)
{
	int			i = 0;

	Assert(jsp->type == jpiIndexArray);

	for (i = 0; i < jsp->content.array.nelems; i++)
	{
		int32		fromidx;
		int32		toidx;

		if (!jsonpath_array_indexes_get_range(jsp, i, &fromidx, &toidx))
			continue;

		if (index >= fromidx && index <= toidx)
			return true;
	}

	return false;
}

static bool
jsonpath_array_indexes_are_subset(JsonPathItem *query, JsonPathItem *index)
{
	int			i = 0;

	for (i = 0; i < query->content.array.nelems; i++)
	{
		int32		fromidx;
		int32		toidx;
		int32		idx;

		if (!jsonpath_array_indexes_get_range(query, i, &fromidx, &toidx))
			return false;

		for (idx = fromidx; idx <= toidx; idx++)
		{
			if (!jsonpath_array_indexes_contains(index, idx))
				return false;
		}
	}

	return true;
}

static bool
jsonpath_array_subscripts_contain_zero(JsonPathItem *jsp)
{
	int			i;

	Assert(jsp->type == jpiIndexArray);

	/* check whether 0th index falls into subscript range */
	for (i = 0; i < jsp->content.array.nelems; i++)
	{
		JsonPathItem from;
		JsonPathItem to;
		bool		range = jspGetArraySubscript(jsp, &from, &to, 0);

		if (from.type == jpiNumeric && !jspHasNext(&from))
		{
			int32		fromidx = jsonpath_get_array_index(&from);

			if (range)
			{
				if (to.type == jpiNumeric && !jspHasNext(&to))
				{
					int32		toidx = jsonpath_get_array_index(&to);

					if (fromidx <= 0 && toidx >= 0)
						return true;
				}
				else if (to.type == jpiLast && !jspHasNext(&to))
				{
					if (fromidx <= 0)
						return true;
				}
			}
			else
			{
				if (!fromidx)
					return true;
			}
		}
	}

	return false;
}

static bool
jsonpath_match_next(JsonPathItem *index, List *queryl, ListCell *querylc,
					bool lax)
{
	JsonPathItem idxnext;

	if (!jspGetNext(index, &idxnext))
		return true;

	return jsonpath_match(&idxnext, queryl, querylc, lax, true);
}

static bool
jsonpath_match_any(JsonPathItem *index, List *queryl, ListCell *querylc,
				   bool lax, uint32 level)
{
	JsonPathItem *query;
	uint32		ifirst;
	uint32		ilast;

	check_stack_depth();

	Assert(index->type == jpiAny);

	ifirst = index->content.anybounds.first;
	ilast = index->content.anybounds.last;

	if (!querylc)
	{
		JsonPathItem idxnext;

		for (;;)
		{
			if (level < ifirst)
				return false;

			level -= ifirst;

			if (!jspGetNext(index, &idxnext))
				break;

			index = &idxnext;

			if (index->type != jpiAny)
				return false;

			ifirst = index->content.anybounds.first;
			ilast = index->content.anybounds.last;
		}

		return true;
	}

	query = lfirst(querylc);

	/* try to skip current item if the current level is returned by it */
	if (level >= ifirst && level <= ilast &&
		jsonpath_match_next(index, queryl, querylc, lax))
		return true;

	switch (query->type)
	{
		case jpiKey:
		case jpiAnyKey:
		case jpiIndexArray:
		case jpiAnyArray:
			/* try to consume current query item with level increment */
			if (++level > ilast)
				return false;

			return jsonpath_match_any(index, queryl, lnext(queryl, querylc),
									  lax, level);

		case jpiAny:
			{
				uint32		qfirst = query->content.anybounds.first;
				uint32		qlast = query->content.anybounds.last;

				if (qlast != UINT32_MAX)
				{
					/* all query levels should match */
					for (int i = qfirst; i <= qlast; i++)
						if (!jsonpath_match_any(index, queryl,
												lnext(queryl, querylc), lax,
												level + i))
							return false;

					return true;
				}
				else
				{
					bool		ilast_inf = ilast == UINT32_MAX;
					uint64		qfirst_total = qfirst;
					uint64		ifirst_total = ifirst;
					JsonPathItem idxnext;

					while ((querylc = lnext(queryl, querylc)))
					{
						query = lfirst(querylc);

						if (query->type != jpiAny)
							break;

						qfirst_total += query->content.anybounds.first;
					}

					while ((index = jspGetNext(index, &idxnext) ? &idxnext : NULL))
					{
						if (index->type != jpiAny)
							break;

						ifirst_total += index->content.anybounds.first;
						ilast_inf |= index->content.anybounds.last == UINT32_MAX;
					}

					if (!ilast_inf || ifirst_total - level > qfirst_total)
						return false;

					if (!index)
						return true;

					return jsonpath_match(index, queryl, querylc, lax, true);
				}
			}

		default:
			return false;
	}
}

#if 1
static bool
jsonpath_match(JsonPathItem *index, List *queryl, ListCell *querylc,
			   bool lax, bool unwrap)
{
	JsonPathItem *query;

	check_stack_depth();

	if (!index)
		return true;

#if 1
	if (!querylc)
	{
		JsonPathItem next;

		if (lax)
		{
			/* skip trailing [*] and [0] items in lax mode */
			while (index->type == jpiAnyArray /*||
				   (index->type == jpiIndexArray &&
					jsonpath_array_subscripts_contain_zero(index))*/)
			{
				if (!jspGetNext(index, &next))
					return true;

				index = &next;
			}
		}

		if (index->type == jpiAny)
			return jsonpath_match_any(index, NULL, NULL, lax, 0);

		return false;
	}
#endif

	query = lfirst(querylc);

	if (index->type == jpiAny)
		return jsonpath_match_any(index, queryl, querylc, lax, 0);

	switch (query->type)
	{
		case jpiRoot:
			if (index->type == jpiRoot)
				break;

			return false;

		case jpiKey:
		case jpiAnyKey:
			if (index->type == jpiAnyKey)
				break;

			if (query->type == jpiKey && index->type == jpiKey)
			{
				int			len1;
				int			len2;
				char	   *key1 = jspGetString(index, &len1);
				char	   *key2 = jspGetString(query, &len2);

				if (len1 != len2 || memcmp(key1, key2, len1))
					return false;

				break;
			}

			/* skip [*] and [0] lax index items */
			if (lax &&
				(index->type == jpiAnyArray ||
				 (index->type == jpiIndexArray &&
				  jsonpath_array_subscripts_contain_zero(index))))
				return jsonpath_match_next(index, queryl, querylc, lax);

			return false;

		case jpiIndexArray:
		case jpiAnyArray:
			if (index->type == jpiAnyArray)
				break;

			if (query->type == jpiIndexArray &&
				index->type == jpiIndexArray &&
				jsonpath_array_indexes_are_subset(query, index))
				break;

			/* skip current query item if lax index item is autounwrapped */
			if (lax && unwrap &&
				(index->type == jpiKey ||
				 index->type == jpiAnyKey))
				return jsonpath_match(index, queryl, lnext(queryl, querylc),
									  lax, false);

			return false;

		case jpiAny:
			if (!query->content.anybounds.first &&
				!query->content.anybounds.last)
				/* skip .**{0} items in query */
				return jsonpath_match(index, queryl, lnext(queryl, querylc), lax, true);

			return false;

		default:
			return false;
	}

	/* match next index item with next query item */
	return jsonpath_match_next(index, queryl, lnext(queryl, querylc), lax);
}
#else
static bool
jsonpath_match(JsonPathItem *index, List *queryl, ListCell *querylc, bool lax)
{
	JsonPathItem *query;
	JsonPathItemType query_type;

	check_stack_depth();

	if (querylc)
	{
		query = lfirst(querylc);
		query_type = query->type;
	}
	else
	{
		query = NULL;
		query_type = jpiNull;
	}

#if 0
		JsonPathItem next;

		if (lax)
		{
			/* skip trailing [*] and [0] items in lax mode */
			while (index->type == jpiAnyArray ||
				   (index->type == jpiIndexArray &&
					jsonpath_array_subscripts_contain_zero(index)))
			{
				if (!jspGetNext(index, &next))
					return true;

				index = &next;
			}
		}

		if (index->type == jpiAny)
			return jsonpath_match_any(index, NULL, NULL, lax, 0);

		return false;
	}
#endif

	if (query_type == jpiAny &&
		!query->content.anybounds.first &&
		!query->content.anybounds.last)
		/* skip .**{0} items in query */
		return jsonpath_match(index, queryl, lnext(queryl, querylc), lax);

	switch (index->type)
	{
		case jpiRoot:
			if (query_type != jpiRoot)
				return false;
			break;

		case jpiKey:
			if (lax &&
				(query_type == jpiIndexArray || query_type == jpiAnyArray))
			{
				if (!(querylc = lnext(queryl, querylc)))
					return false;

				query = lfirst(querylc);
				query_type = query->type;
			}

			if (query_type != jpiKey)
				return false;
			else
			{
				int			len1;
				int			len2;
				char	   *key1 = jspGetString(index, &len1);
				char	   *key2 = jspGetString(query, &len2);

				if (len1 != len2 || memcmp(key1, key2, len1))
					return false;
			}
			break;

		case jpiAnyKey:
			if (lax &&
				(query_type == jpiIndexArray || query_type == jpiAnyArray))
			{
				if (!(querylc = lnext(queryl, querylc)))
					return false;

				query = lfirst(querylc);
				query_type = query->type;
			}

			if (query_type != jpiKey && query_type != jpiAnyKey)
				return false;

			break;

		case jpiIndexArray:
			/* try to skip current index item if subscripts contain zero */
#if 0
			if (lax &&
				jsonpath_array_subscripts_contain_zero(index) &&
				jsonpath_match_next(index, queryl, querylc, lax))
				return true;
#endif

			if (query_type != jpiIndexArray ||
				!jsonpath_array_indexes_are_subset(query, index))
				return false;

			break;

		case jpiAnyArray:
			/* try to skip current index item */
			if (lax && jsonpath_match_next(index, queryl, querylc, lax))
				return true;

			if (query_type != jpiIndexArray && query_type != jpiAnyArray)
				return false;

			break;

		case jpiAny:
			return jsonpath_match_any(index, queryl, querylc, lax, 0);

		default:
			return false;
	}

	/* match next index item with next query item */
	return jsonpath_match_next(index, queryl, lnext(queryl, querylc), lax);
}
#endif

typedef struct GinJspIsIndexedContext
{
	JsonPathItemList query;
	bool		lax_query;
} GinJspIsIndexedContext;

static GinTernaryValue
jsonpath_is_indexed_cb(GinForEachPathContext *context, JsonPathItem *root)
{
	GinJspIsIndexedContext *cxt = context->cxt;

	return jsonpath_match(root, cxt->query, list_head(cxt->query),
						  context->lax && !cxt->lax_query, true) ?
		GIN_TRUE : GIN_FALSE;
}

static void
append_jsonpath_item(JsonPathItemList *path, JsonPathItem *jsp)
{
	*path = lappend(*path, memcpy(palloc(sizeof(*jsp)), jsp, sizeof(*jsp)));
}

typedef struct JsonPathItemListExt
{
	JsonPathItemList path;
	bool		non_array;
} JsonPathItemListExt;

static void
duplicate_jsonpaths(List **paths, JsonPathItem *tail, bool arrays_only)
{
	List	   *paths2 = NIL;
	ListCell   *lc;

	foreach(lc, *paths)
	{
		JsonPathItemListExt *old_path = lfirst(lc);
		JsonPathItemListExt *new_path;

		if (arrays_only && old_path->non_array)
			continue;

		old_path->non_array = true;

		new_path = palloc(sizeof(*new_path));
		new_path->path = list_copy(old_path->path);
		new_path->non_array = false;
		append_jsonpath_item(&new_path->path, tail);

		paths2 = lappend(paths2, new_path);
	}

	*paths = list_concat(*paths, paths2);
}

static void
append_jsonpath_array_unwrap_item(List **paths)
{
	JsonPathItem anyarr;

	anyarr.type = jpiAnyArray;

	duplicate_jsonpaths(paths, &anyarr, true);
}

static List *
build_lax_paths(JsonPathItemList path, bool unwrap)
{
	JsonPathItemListExt *root = palloc(sizeof(*root));
	List	   *paths;
	List	   *lax_paths = NIL;
	ListCell   *lc;

	root->path = NIL;
	root->non_array = false;
	paths = list_make1(root);	/* start from single empty path */

	foreach(lc, path)
	{
		JsonPathItem *jsp = lfirst(lc);
		ListCell   *lc2;
		bool		skip;

		switch (jsp->type)
		{
			case jpiKey:
			case jpiAnyKey:
				/* append item for automatic array unwrapping */
				append_jsonpath_array_unwrap_item(&paths);
				skip = false;
				break;

			case jpiAnyArray:
				/* [*] returns item for non-arrays */
				skip = true;
				break;

			case jpiIndexArray:
				/* [0] returns item for non-arrays */
				skip = jsonpath_array_subscripts_contain_zero(jsp);
				break;

			default:
				skip = false;
				break;
		}

		if (skip)
			duplicate_jsonpaths(&paths, jsp, true);
		else
		{
			foreach(lc2, paths)
			{
				JsonPathItemListExt *path = lfirst(lc2);

				append_jsonpath_item(&path->path, jsp);
				path->non_array = false;
			}
		}
	}

	if (unwrap)
		append_jsonpath_array_unwrap_item(&paths);

	foreach(lc, paths)
	{
		JsonPathItemListExt *path = lfirst(lc);

		lax_paths = lappend(lax_paths, path->path);
	}

	return lax_paths;
}

static bool
jsonpath_is_indexed(JsonPath *indexed_paths, JsonPathItemList query_path,
					bool lax_query, bool unwrap)
{
	GinJspIsIndexedContext cxt;
	ListCell   *lc;
	List	   *query_paths;

	Assert(indexed_paths);

	cxt.lax_query = lax_query;

	query_paths = lax_query && !(indexed_paths->header & JSONPATH_LAX) ?
		build_lax_paths(query_path, unwrap) : list_make1(query_path);

	foreach(lc, query_paths)
	{
		cxt.query = lfirst(lc);

		if (foreach_jsonpath(indexed_paths, jsonpath_is_indexed_cb, &cxt) != GIN_TRUE)
			return false;
	}

	return true;
}

Datum
jsonpath_is_subset(PG_FUNCTION_ARGS)
{
	JsonPath   *jp1 = PG_GETARG_JSONPATH_P(0);
	JsonPath   *jp2 = PG_GETARG_JSONPATH_P(1);
	JsonPathItem jsp1;
	JsonPathItem jsp2;
	List	   *path = NIL;

	jspInit(&jsp1, jp1);
	jspInit(&jsp2, jp2);

	if (jsp1.type != jpiRoot)
		PG_RETURN_NULL();

	do
	{
		append_jsonpath_item(&path, &jsp1);
	} while (jspGetNext(&jsp1, &jsp1));

	PG_RETURN_BOOL(jsonpath_is_indexed(jp2, path,
									   (jp1->header & JSONPATH_LAX) != 0,
									   false));
}

/* Append JsonPathGinPathItem to JsonPathGinPath (jsonb_ops) */
static bool
jsonb_ops__add_path_item(JsonPathGinPath *path, JsonPathItem *jsp)
{
	JsonPathGinPathItem *pentry;
	Datum		keyName;

	switch (jsp->type)
	{
		case jpiRoot:
			path->items = NULL; /* reset path */
			return true;

		case jpiKey:
			{
				int			len;
				char	   *key = jspGetString(jsp, &len);

				keyName = make_text_key(JGINFLAG_KEY, key, len);
				break;
			}

		case jpiAny:
		case jpiAnyKey:
		case jpiAnyArray:
		case jpiIndexArray:
			keyName = PointerGetDatum(NULL);
			break;

		default:
			/* other path items like item methods are not supported */
			return false;
	}

	pentry = palloc(sizeof(*pentry));

	pentry->type = jsp->type;
	pentry->keyName = keyName;
	pentry->parent = path->items;

	path->items = pentry;

	return true;
}

/* Combine existing path hash with next key hash (jsonb_path_ops) */
static bool
jsonb_path_ops__add_path_item(JsonPathGinPath *path, JsonPathItem *jsp)
{
	switch (jsp->type)
	{
		case jpiRoot:
			path->hash = 0;		/* reset path hash */
			return true;

		case jpiKey:
			{
				JsonbValue	jbv;

				jbv.type = jbvString;
				jbv.val.string.val = jspGetString(jsp, &jbv.val.string.len);

				JsonbHashScalarValue(&jbv, &path->hash);
				return true;
			}

		case jpiIndexArray:
		case jpiAnyArray:
			return true;		/* path hash is unchanged */

		default:
			/* other items (wildcard paths, item methods) are not supported */
			return false;
	}
}

static JsonPathGinNode *
make_jsp_entry_node(Datum entry)
{
	JsonPathGinNode *node = palloc(offsetof(JsonPathGinNode, args));

	node->type = JSP_GIN_ENTRY;
	node->val.entryDatum = entry;

	return node;
}

static JsonPathGinNode *
make_jsp_entry_node_scalar(JsonbValue *scalar, bool iskey)
{
	return make_jsp_entry_node(make_scalar_key(scalar, iskey));
}

static JsonPathGinNode *
make_jsp_expr_node(JsonPathGinNodeType type, int nargs)
{
	JsonPathGinNode *node = palloc(offsetof(JsonPathGinNode, args) +
								   sizeof(node->args[0]) * nargs);

	node->type = type;
	node->val.nargs = nargs;

	return node;
}

static JsonPathGinNode *
make_jsp_expr_node_args(JsonPathGinNodeType type, List *args)
{
	JsonPathGinNode *node = make_jsp_expr_node(type, list_length(args));
	ListCell   *lc;
	int			i = 0;

	foreach(lc, args)
		node->args[i++] = lfirst(lc);

	return node;
}

static JsonPathGinNode *
make_jsp_expr_node_binary(JsonPathGinNodeType type,
						  JsonPathGinNode *arg1, JsonPathGinNode *arg2)
{
	JsonPathGinNode *node = make_jsp_expr_node(type, 2);

	node->args[0] = arg1;
	node->args[1] = arg2;

	return node;
}

/* Append a list of nodes from the jsonpath (jsonb_ops). */
static List *
jsonb_ops__extract_nodes(JsonPathGinContext *cxt, JsonPathGinPath path,
						 JsonbValue *scalar, List *nodes)
{
	JsonPathGinPathItem *pentry;

	if (scalar)
	{
		JsonPathGinNode *node;

		/*
		 * Append path entry nodes only if scalar is provided.  See header
		 * comment for details.
		 */
		for (pentry = path.items; pentry; pentry = pentry->parent)
		{
			if (pentry->type == jpiKey) /* only keys are indexed */
				nodes = lappend(nodes, make_jsp_entry_node(pentry->keyName));
		}

		/* Append scalar node for equality queries. */
		if (scalar->type == jbvString)
		{
			JsonPathGinPathItem *last = path.items;
			GinTernaryValue key_entry;

			/*
			 * Assuming that jsonb_ops interprets string array elements as
			 * keys, we may extract key or non-key entry or even both.  In the
			 * latter case we create OR-node.  It is possible in lax mode
			 * where arrays are automatically unwrapped, or in strict mode for
			 * jpiAny items.
			 */

			if (cxt->lax_query)
				key_entry = GIN_MAYBE;
			else if (!last)		/* root ($) */
				key_entry = GIN_FALSE;
			else if (last->type == jpiAnyArray || last->type == jpiIndexArray)
				key_entry = GIN_TRUE;
			else if (last->type == jpiAny)
				key_entry = GIN_MAYBE;
			else
				key_entry = GIN_FALSE;

			if (key_entry == GIN_MAYBE)
			{
				JsonPathGinNode *n1 = make_jsp_entry_node_scalar(scalar, true);
				JsonPathGinNode *n2 = make_jsp_entry_node_scalar(scalar, false);

				node = make_jsp_expr_node_binary(JSP_GIN_OR, n1, n2);
			}
			else
			{
				node = make_jsp_entry_node_scalar(scalar,
												  key_entry == GIN_TRUE);
			}
		}
		else
		{
			node = make_jsp_entry_node_scalar(scalar, false);
		}

		nodes = lappend(nodes, node);
	}

	return nodes;
}

/* Append a list of nodes from the jsonpath (jsonb_path_ops). */
static List *
jsonb_path_ops__extract_nodes(JsonPathGinContext *cxt, JsonPathGinPath path,
							  JsonbValue *scalar, List *nodes)
{
	if (scalar)
	{
		/* append path hash node for equality queries */
		uint32		hash = path.hash;

		JsonbHashScalarValue(scalar, &hash);

		return lappend(nodes,
					   make_jsp_entry_node(UInt32GetDatum(hash)));
	}
	else
	{
		/* jsonb_path_ops doesn't support EXISTS queries => nothing to append */
		return nodes;
	}
}

/*
 * Extract a list of expression nodes that need to be AND-ed by the caller.
 * Extracted expression is 'path == scalar' if 'scalar' is non-NULL, and
 * 'EXISTS(path)' otherwise.
 */
static List *
extract_jsp_path_expr_nodes(JsonPathGinContext *cxt, JsonPathGinPath path,
							JsonPathItem *jsp, JsonbValue *scalar)
{
	JsonPathItem next;
	List	   *nodes = NIL;

	path.path = list_copy(path.path); /* FIXME */

	for (;;)
	{
		switch (jsp->type)
		{
			case jpiCurrent:
				break;

			case jpiFilter:
				{
					JsonPathItem arg;
					JsonPathGinNode *filter;

					jspGetArg(jsp, &arg);

					filter = extract_jsp_bool_expr(cxt, path, &arg, false);

					if (filter)
						nodes = lappend(nodes, filter);
					break;
				}

			case jpiRoot:
				path.path = NIL;	/* reset path */
				/* FALLTHROUGH */

			default:
				if (!cxt->common.add_path_item(&path, jsp))
					/*
					 * Path is not supported by the index opclass, return only
					 * the extracted filter nodes.
					 */
					return nodes;

				/* Collect path items for indexed paths check */
				if (cxt->common.indexed_paths)
					append_jsonpath_item(&path.path, jsp);
				break;
		}

		if (!jspGetNext(jsp, &next))
			break;

		jsp = &next;
	}

	/* Check if the path is indexed */
	if (cxt->common.indexed_paths &&
		!jsonpath_is_indexed(cxt->common.indexed_paths, path.path,
							 cxt->lax_query, scalar != NULL))
		return NULL;

	/*
	 * Append nodes from the path expression itself to the already extracted
	 * list of filter nodes.
	 */
	return cxt->extract_nodes(cxt, path, scalar, nodes);
}

/*
 * Extract an expression node from one of following jsonpath path expressions:
 *   EXISTS(jsp)    (when 'scalar' is NULL)
 *   jsp == scalar  (when 'scalar' is not NULL).
 *
 * The current path (@) is passed in 'path'.
 */
static JsonPathGinNode *
extract_jsp_path_expr(JsonPathGinContext *cxt, JsonPathGinPath path,
					  JsonPathItem *jsp, JsonbValue *scalar)
{
	/* extract a list of nodes to be AND-ed */
	List	   *nodes;

	path.path = list_copy(path.path); /* FIXME */

	nodes = extract_jsp_path_expr_nodes(cxt, path, jsp, scalar);

	if (list_length(nodes) <= 0)
		/* no nodes were extracted => full scan is needed for this path */
		return NULL;

	if (list_length(nodes) == 1)
		return linitial(nodes); /* avoid extra AND-node */

	/* construct AND-node for path with filters */
	return make_jsp_expr_node_args(JSP_GIN_AND, nodes);
}

/* Recursively extract nodes from the boolean jsonpath expression. */
static JsonPathGinNode *
extract_jsp_bool_expr(JsonPathGinContext *cxt, JsonPathGinPath path,
					  JsonPathItem *jsp, bool not)
{
	check_stack_depth();

	path.path = list_copy(path.path); /* FIXME */

	switch (jsp->type)
	{
		case jpiAnd:			/* expr && expr */
		case jpiOr:				/* expr || expr */
			{
				JsonPathItem arg;
				JsonPathGinNode *larg;
				JsonPathGinNode *rarg;
				JsonPathGinNodeType type;

				jspGetLeftArg(jsp, &arg);
				larg = extract_jsp_bool_expr(cxt, path, &arg, not);

				jspGetRightArg(jsp, &arg);
				rarg = extract_jsp_bool_expr(cxt, path, &arg, not);

				if (!larg || !rarg)
				{
					if (jsp->type == jpiOr)
						return NULL;

					return larg ? larg : rarg;
				}

				type = not ^ (jsp->type == jpiAnd) ? JSP_GIN_AND : JSP_GIN_OR;

				return make_jsp_expr_node_binary(type, larg, rarg);
			}

		case jpiNot:			/* !expr  */
			{
				JsonPathItem arg;

				jspGetArg(jsp, &arg);

				/* extract child expression inverting 'not' flag */
				return extract_jsp_bool_expr(cxt, path, &arg, !not);
			}

		case jpiExists:			/* EXISTS(path) */
			{
				JsonPathItem arg;

				if (not)
					return NULL;	/* NOT EXISTS is not supported */

				jspGetArg(jsp, &arg);

				return extract_jsp_path_expr(cxt, path, &arg, NULL);
			}

		case jpiNotEqual:

			/*
			 * 'not' == true case is not supported here because '!(path !=
			 * scalar)' is not equivalent to 'path == scalar' in the general
			 * case because of sequence comparison semantics: 'path == scalar'
			 * === 'EXISTS (path, @ == scalar)', '!(path != scalar)' ===
			 * 'FOR_ALL(path, @ == scalar)'. So, we should translate '!(path
			 * != scalar)' into GIN query 'path == scalar || EMPTY(path)', but
			 * 'EMPTY(path)' queries are not supported by the both jsonb
			 * opclasses.  However in strict mode we could omit 'EMPTY(path)'
			 * part if the path can return exactly one item (it does not
			 * contain wildcard accessors or item methods like .keyvalue()
			 * etc.).
			 */
			return NULL;

		case jpiEqual:			/* path == scalar */
			{
				JsonPathItem left_item;
				JsonPathItem right_item;
				JsonPathItem *path_item;
				JsonPathItem *scalar_item;
				JsonbValue	scalar;

				if (not)
					return NULL;

				jspGetLeftArg(jsp, &left_item);
				jspGetRightArg(jsp, &right_item);

				if (jspIsScalar(left_item.type))
				{
					scalar_item = &left_item;
					path_item = &right_item;
				}
				else if (jspIsScalar(right_item.type))
				{
					scalar_item = &right_item;
					path_item = &left_item;
				}
				else
					return NULL;	/* at least one operand should be a scalar */

				switch (scalar_item->type)
				{
					case jpiNull:
						scalar.type = jbvNull;
						break;
					case jpiBool:
						scalar.type = jbvBool;
						scalar.val.boolean = !!*scalar_item->content.value.data;
						break;
					case jpiNumeric:
						scalar.type = jbvNumeric;
						scalar.val.numeric =
							(Numeric) scalar_item->content.value.data;
						break;
					case jpiString:
						scalar.type = jbvString;
						scalar.val.string.val = scalar_item->content.value.data;
						scalar.val.string.len =
							scalar_item->content.value.datalen;
						break;
					default:
						elog(ERROR, "invalid scalar jsonpath item type: %d",
							 scalar_item->type);
						return NULL;
				}

				return extract_jsp_path_expr(cxt, path, path_item, &scalar);
			}

		default:
			return NULL;		/* not a boolean expression */
	}
}

/* Recursively emit all GIN entries found in the node tree */
static void
emit_jsp_gin_entries(JsonPathGinNode *node, GinEntries *entries)
{
	check_stack_depth();

	switch (node->type)
	{
		case JSP_GIN_ENTRY:
			/* replace datum with its index in the array */
			node->val.entryIndex = add_gin_entry(entries, node->val.entryDatum);
			break;

		case JSP_GIN_OR:
		case JSP_GIN_AND:
			for (int i = 0; i < node->val.nargs; i++)
				emit_jsp_gin_entries(node->args[i], entries);
			break;
	}
}

static void
init_gin_jsonb_context(JsonbGinContext *cxt, GinJsonOptions *options,
					   bool path_ops)
{
	cxt->options = options;
	cxt->indexed_paths = GIN_GET_JSONPATHS(options);
	cxt->lax_indexed_paths = cxt->indexed_paths &&
		(cxt->indexed_paths->header & JSONPATH_LAX) != 0;

	if (path_ops)
		cxt->add_path_item = jsonb_path_ops__add_path_item;
	else
		cxt->add_path_item = jsonb_ops__add_path_item;
}

/*
 * Recursively extract GIN entries from jsonpath query.
 * Root expression node is put into (*extra_data)[0].
 */
static Datum *
extract_jsp_query(JsonPath *jp, GinJsonOptions *options, StrategyNumber strat,
				  bool pathOps, int32 *nentries, Pointer **extra_data)
{
	JsonPathGinContext cxt;
	JsonPathItem root;
	JsonPathGinNode *node;
	JsonPathGinPath path = {0};
	GinEntries	entries = {0};

	init_gin_jsonb_context(&cxt.common, options, pathOps);

	cxt.lax_query = (jp->header & JSONPATH_LAX) != 0;
	cxt.extract_nodes =
		pathOps ? jsonb_path_ops__extract_nodes : jsonb_ops__extract_nodes;

	jspInit(&root, jp);

	node = strat == JsonbJsonpathExistsStrategyNumber
		? extract_jsp_path_expr(&cxt, path, &root, NULL)
		: extract_jsp_bool_expr(&cxt, path, &root, false);

	if (!node)
	{
		*nentries = 0;
		return NULL;
	}

	emit_jsp_gin_entries(node, &entries);

	*nentries = entries.count;
	if (!*nentries)
		return NULL;

	*extra_data = palloc0(sizeof(**extra_data) * entries.count);
	**extra_data = (Pointer) node;

	return entries.buf;
}

static void
print_jsonpath_query(StringInfo buf, JsonPathGinNode *node, Datum *entries,
					 bool path_ops)
{
	switch (node->type)
	{
		case JSP_GIN_AND:
		case JSP_GIN_OR:
			for (int i = 0; i < node->val.nargs; i++)
			{
				if (i)
					appendStringInfoString(buf, node->type == JSP_GIN_AND ?
										   " && " : " || ");

				if (node->args[i]->type != JSP_GIN_ENTRY)
					appendStringInfoString(buf, "(");

				print_jsonpath_query(buf, node->args[i], entries, path_ops);

				if (node->args[i]->type != JSP_GIN_ENTRY)
					appendStringInfoString(buf, ")");
			}
			break;

		case JSP_GIN_ENTRY:
			{
				Datum		entry = entries[node->val.entryIndex];

				if (path_ops)
					appendStringInfo(buf, "#%08x", DatumGetInt32(entry));
				else
				{
					text	   *key = DatumGetTextP(entry);
					const char *data = VARDATA_ANY(key) + 1;
					int			size = VARSIZE_ANY_EXHDR(key) - 1;
					int			flag = *(char *) VARDATA_ANY(key);
					int			type = flag & ~JGINFLAG_HASHED;

					switch (type)
					{
						case JGINFLAG_KEY:
						case JGINFLAG_STR:
							if (type == JGINFLAG_KEY)
								appendStringInfoString(buf, "K");
							if (flag & JGINFLAG_HASHED)
								appendStringInfoChar(buf, '#');
							escape_json(buf, pnstrdup(data, size));
							break;
						case JGINFLAG_NUM:
							appendStringInfo(buf, "%.*s", size, data);
							break;
						case JGINFLAG_NULL:
							appendStringInfoString(buf, "null");
							break;
						case JGINFLAG_BOOL:
							appendStringInfoString(buf, *data == 't' ? "true" : "false");
							break;
						default:
							elog(ERROR, "invalid jsonpath gin entry type: %d", type);
							break;
					}
				}
				break;
			}

		default:
			elog(ERROR, "invalid jsonpath gin node type: %d", node->type);
	}
}

Datum
gin_debug_jsonpath_query(PG_FUNCTION_ARGS)
{
	JsonPath   *query = PG_GETARG_JSONPATH_P(0);
	JsonPath   *indexed_paths = PG_ARGISNULL(1) ? NULL : PG_GETARG_JSONPATH_P(1);
	bool		path_ops = PG_GETARG_BOOL(2);
	bool		exists = PG_GETARG_BOOL(3);
	GinJsonOptions *options = NULL;
	Datum	   *entries;
	Pointer	   *extra_data;
	StringInfoData buf;
	int32		nentries;

	if (indexed_paths)
	{
		Size		offset = MAXALIGN(sizeof(GinJsonOptions));

		validate_indexed_json_paths(indexed_paths);

		options = palloc(offset + VARSIZE_ANY(indexed_paths));
		options->pathsOffset = offset;
		SET_VARSIZE(options, offset + VARSIZE_ANY(indexed_paths));

		memcpy((char *) options + offset, indexed_paths, VARSIZE_ANY(indexed_paths));
	}

	entries = extract_jsp_query(query, options, exists ?
								JsonbJsonpathExistsStrategyNumber :
								JsonbJsonpathPredicateStrategyNumber,
								path_ops, &nentries, &extra_data);

	if (!entries || !extra_data || !extra_data[0])
		PG_RETURN_NULL();

	initStringInfo(&buf);

	print_jsonpath_query(&buf, (JsonPathGinNode *) extra_data[0], entries,
						 path_ops);

	PG_RETURN_TEXT_P(cstring_to_text(buf.data));
}

/*
 * Recursively execute jsonpath expression.
 * 'check' is a bool[] or a GinTernaryValue[] depending on 'ternary' flag.
 */
static GinTernaryValue
execute_jsp_gin_node(JsonPathGinNode *node, void *check, bool ternary)
{
	GinTernaryValue res;
	GinTernaryValue v;
	int			i;

	switch (node->type)
	{
		case JSP_GIN_AND:
			res = GIN_TRUE;
			for (i = 0; i < node->val.nargs; i++)
			{
				v = execute_jsp_gin_node(node->args[i], check, ternary);
				if (v == GIN_FALSE)
					return GIN_FALSE;
				else if (v == GIN_MAYBE)
					res = GIN_MAYBE;
			}
			return res;

		case JSP_GIN_OR:
			res = GIN_FALSE;
			for (i = 0; i < node->val.nargs; i++)
			{
				v = execute_jsp_gin_node(node->args[i], check, ternary);
				if (v == GIN_TRUE)
					return GIN_TRUE;
				else if (v == GIN_MAYBE)
					res = GIN_MAYBE;
			}
			return res;

		case JSP_GIN_ENTRY:
			{
				int			index = node->val.entryIndex;

				if (ternary)
					return ((GinTernaryValue *) check)[index];
				else
					return ((bool *) check)[index] ? GIN_TRUE : GIN_FALSE;
			}

		default:
			elog(ERROR, "invalid jsonpath gin node type: %d", node->type);
			return GIN_FALSE;	/* keep compiler quiet */
	}
}

typedef struct PathStack
{
	struct PathStack *parent;
	JsonPathGinPath path;
	char	   *key;
	int			keylen;
	GinTernaryValue	indexed;
} PathStack;

static GinTernaryValue
path_is_indexed_rec(JsonPathItem *root, PathStack *path, JsonPathItem *next)
{
	JsonPathItem jsp;
	GinTernaryValue res;

	check_stack_depth();

	if (!path->parent)
	{
		if (root->type != jpiRoot)
			return GIN_FALSE;		/* invalid path */
	}
	else
	{
		res = path_is_indexed_rec(root, path->parent, &jsp);
		if (res != GIN_MAYBE)
			return res;

		if (path->key)
		{
			switch (jsp.type)
			{
				case jpiKey:
					{
						int			keylen;
						const char *key = jspGetString(&jsp, &keylen);

						if (path->keylen != keylen ||
							memcmp(path->key, key, keylen))
							return GIN_FALSE;

						break;
					}

				case jpiAnyKey:
					break;

				case jpiAny:
					if (jsp.content.anybounds.first > 1)
						return GIN_FALSE;
					break;

				default:
					return GIN_FALSE;
			}
		}
		else
		{
			switch (jsp.type)
			{
				case jpiAnyArray:
					break;

				case jpiAny:
					if (jsp.content.anybounds.first > 1)
						return GIN_FALSE;
					break;

				default:
					return GIN_FALSE;
			}
		}

		root = &jsp;
	}

	if (!jspGetNext(root, next))
		return GIN_TRUE;

	return GIN_MAYBE;
}

static GinTernaryValue
path_is_indexed_cb(GinForEachPathContext *context, JsonPathItem *root)
{
	PathStack *path = context->cxt;
	JsonPathItem next;
	GinTernaryValue res;

	res = path_is_indexed_rec(root, path, &next);
	if (res != GIN_MAYBE)
		return res;

	do
	{
		if (next.type != jpiAny || next.content.anybounds.first > 0)
			return GIN_MAYBE;
	} while (jspGetNext(&next, &next));

	return GIN_TRUE;
}

static GinTernaryValue
path_is_indexed(PathStack *stack, JsonPath *paths)
{
	if (!paths)
		return GIN_TRUE;	/* all keys are indexed */

	return foreach_jsonpath(paths, path_is_indexed_cb, stack);
}

static bool
jsonb_key_is_indexed(GinJsonOptions *options, text *keyname)
{
	PathStack	root;
	PathStack	key;
	JsonPath   *paths = GIN_GET_JSONPATHS(options);

	if (!paths)
		return true;

	root.parent = NULL;
	root.path.items = NULL;
	root.path.path = NIL;
	root.key = NULL;
	root.keylen = 0;

	key.parent = &root;
	key.path.items = NULL;
	key.path.path = NIL;
	key.key = VARDATA_ANY(keyname);
	key.keylen = VARSIZE_ANY_EXHDR(keyname);

	return path_is_indexed(&key, paths) == GIN_TRUE;
}

#if 0
static Datum *
gin_extract_jsonb_containment(Jsonb *jb, GinJsonOptions *options, bool path_ops,
							  int *nentries)
{
	GinEntries entries = {0};
	JsonbContainer *jbc = &jb->root;
	GinJsonExtractionContext cxt;
	JsonPath   *paths;
	JsonbIterator *it;
	JsonbValue	v;
	JsonbIteratorToken tok;
	PathStack	root;
	PathStack  *stack;

	init_gin_jsonb_context(&cxt.common, options, path_ops);

	if (!(paths = cxt.common.indexed_paths))
	{
		/* Extract all paths from container */
		JsonPathGinPath path = {0};

		v.type = jbvBinary;
		v.val.binary.data = jbc;
		v.val.binary.len = VARSIZE_ANY_EXHDR(jb);

		cxt.extract_entries(&entries, &v, path);
		*nentries = entries.count;
		return entries.buf;
	}

	/* We keep a stack of partial hashes corresponding to parent key levels */
	root.parent = NULL;
	root.path.items = NULL;
	root.path.path = NIL;
	root.key = NULL;
	root.keylen = 0;
	root.indexed = gin_jsonb_path_is_indexed(&root, paths);

	stack = &root;

	it = JsonbIteratorInit(jbc);

	while ((tok = JsonbIteratorNext(&it, &v, false)) != WJB_DONE)
	{
		PathStack *parent;

		switch (tok)
		{
			case WJB_BEGIN_ARRAY:
			case WJB_BEGIN_OBJECT:
				/* Push a stack level for this object */
				parent = stack;
				stack = palloc(sizeof(*stack));

				/*
				 * We pass forward hashes from outer nesting levels so that
				 * the hashes for nested values will include outer keys as
				 * well as their own keys.
				 *
				 * Nesting an array within another array will not alter
				 * innermost scalar element path values, but that seems
				 * inconsequential.
				 */
				stack->path = parent->path;
				stack->indexed = parent->indexed;
				stack->parent = parent;
				stack->key = NULL;
				stack->keylen = 0;

				if (stack->indexed == GIN_MAYBE &&
					tok == WJB_BEGIN_ARRAY &&
					!v.val.array.rawScalar)
					stack->indexed = gin_jsonb_path_is_indexed(stack, paths);

				break;

			case WJB_KEY:
				/* reset path for next key */
				stack->path = stack->parent->path;
				stack->indexed = stack->parent->indexed;

				if (stack->indexed == GIN_FALSE)
					break;

				stack->key = v.val.string.val;
				stack->keylen = v.val.string.len;

				if (stack->indexed == GIN_MAYBE)
					stack->indexed = gin_jsonb_path_is_indexed(stack, paths);

				if (stack->indexed != GIN_FALSE)
				{
					JsonPathItem jsp;

					jsp.type = jpiKey;
					jsp.content.value.data = stack->key;
					jsp.content.value.datalen = stack->keylen;

					cxt.common.add_path_item(&stack->path, &jsp);
				}
				break;

			case WJB_ELEM:
			case WJB_VALUE:
				if (stack->indexed == GIN_TRUE)
					cxt.extract_entries(&entries, &v, stack->path);
				break;

			case WJB_END_ARRAY:
			case WJB_END_OBJECT:
				/* pop the stack */
				parent = stack->parent;
				pfree(stack);
				stack = parent;
				break;

			default:
				elog(ERROR, "invalid JsonbIteratorNext rc: %d", (int) tok);
		}
	}

	*nentries = entries.count;
	return entries.buf;
}
#endif

Datum
gin_extract_jsonb_query(PG_FUNCTION_ARGS)
{
	int32	   *nentries = (int32 *) PG_GETARG_POINTER(1);
	StrategyNumber strategy = PG_GETARG_UINT16(2);
	int32	   *searchMode = (int32 *) PG_GETARG_POINTER(6);
	GinJsonOptions *options = (GinJsonOptions *) PG_GET_OPCLASS_OPTIONS();
	Datum	   *entries;

	if (strategy == JsonbContainsStrategyNumber)
	{
		/* Query is a jsonb, so just apply gin_extract_jsonb... */
		Jsonb	   *jb = PG_GETARG_JSONB_P(0);
#if 1
		entries = gin_extract_jsonb_internal(jb, options, false, nentries);
#else
		entries = gin_extract_jsonb_containment(jb, options, false, &nentries);
#endif

		/* ...although "contains {}" requires a full index scan */
		if (*nentries == 0)
			*searchMode = GIN_SEARCH_MODE_ALL;
	}
	else if (strategy == JsonbExistsStrategyNumber)
	{
		/* Query is a text string, which we treat as a key */
		text	   *query = PG_GETARG_TEXT_PP(0);

		if (jsonb_key_is_indexed(options, query))
		{
			*nentries = 1;
			entries = (Datum *) palloc(sizeof(Datum));
			entries[0] = make_text_key(JGINFLAG_KEY,
									   VARDATA_ANY(query),
									   VARSIZE_ANY_EXHDR(query));
		}
		else
		{
			entries = NULL;
			*nentries = 0;
			*searchMode = GIN_SEARCH_MODE_ALL;
		}
	}
	else if (strategy == JsonbExistsAnyStrategyNumber ||
			 strategy == JsonbExistsAllStrategyNumber)
	{
		/* Query is a text array; each element is treated as a key */
		ArrayType  *query = PG_GETARG_ARRAYTYPE_P(0);
		Datum	   *key_datums;
		bool	   *key_nulls;
		int			key_count;
		int			i,
					j;

		deconstruct_array(query,
						  TEXTOID, -1, false, TYPALIGN_INT,
						  &key_datums, &key_nulls, &key_count);

		entries = (Datum *) palloc(sizeof(Datum) * key_count);

		for (i = 0, j = 0; i < key_count; i++)
		{
			/* Nulls in the array are ignored */
			if (key_nulls[i])
				continue;

			if (!jsonb_key_is_indexed(options, DatumGetTextP(key_datums[i])))
			{
				/* Need full scan if any key from ExistsAny is not indexed */
				if (strategy == JsonbExistsAnyStrategyNumber)
					*searchMode = GIN_SEARCH_MODE_ALL;
				continue;
			}

			entries[j++] = make_text_key(JGINFLAG_KEY,
										 VARDATA(key_datums[i]),
										 VARSIZE(key_datums[i]) - VARHDRSZ);
		}

		*nentries = j;
		/* ExistsAll with no keys should match everything */
		if (j == 0 && strategy == JsonbExistsAllStrategyNumber)
			*searchMode = GIN_SEARCH_MODE_ALL;
	}
	else if (strategy == JsonbJsonpathPredicateStrategyNumber ||
			 strategy == JsonbJsonpathExistsStrategyNumber)
	{
		JsonPath   *jp = PG_GETARG_JSONPATH_P(0);
		Pointer   **extra_data = (Pointer **) PG_GETARG_POINTER(4);

		entries = extract_jsp_query(jp, options, strategy, false, nentries,
									extra_data);

		if (!entries)
			*searchMode = GIN_SEARCH_MODE_ALL;
	}
	else
	{
		elog(ERROR, "unrecognized strategy number: %d", strategy);
		entries = NULL;			/* keep compiler quiet */
	}

	PG_RETURN_POINTER(entries);
}

Datum
gin_consistent_jsonb(PG_FUNCTION_ARGS)
{
	bool	   *check = (bool *) PG_GETARG_POINTER(0);
	StrategyNumber strategy = PG_GETARG_UINT16(1);

	/* Jsonb	   *query = PG_GETARG_JSONB_P(2); */
	int32		nkeys = PG_GETARG_INT32(3);

	Pointer    *extra_data = (Pointer *) PG_GETARG_POINTER(4);
	bool	   *recheck = (bool *) PG_GETARG_POINTER(5);
	bool		res = true;
	int32		i;

	if (strategy == JsonbContainsStrategyNumber)
	{
		/*
		 * We must always recheck, since we can't tell from the index whether
		 * the positions of the matched items match the structure of the query
		 * object.  (Even if we could, we'd also have to worry about hashed
		 * keys and the index's failure to distinguish keys from string array
		 * elements.)  However, the tuple certainly doesn't match unless it
		 * contains all the query keys.
		 */
		*recheck = true;
		for (i = 0; i < nkeys; i++)
		{
			if (!check[i])
			{
				res = false;
				break;
			}
		}
	}
	else if (strategy == JsonbExistsStrategyNumber)
	{
		/*
		 * Although the key is certainly present in the index, we must recheck
		 * because (1) the key might be hashed, and (2) the index match might
		 * be for a key that's not at top level of the JSON object.  For (1),
		 * we could look at the query key to see if it's hashed and not
		 * recheck if not, but the index lacks enough info to tell about (2).
		 */
		*recheck = true;
		res = true;
	}
	else if (strategy == JsonbExistsAnyStrategyNumber)
	{
		/* As for plain exists, we must recheck */
		*recheck = true;
		res = true;
	}
	else if (strategy == JsonbExistsAllStrategyNumber)
	{
		/* As for plain exists, we must recheck */
		*recheck = true;
		/* ... but unless all the keys are present, we can say "false" */
		for (i = 0; i < nkeys; i++)
		{
			if (!check[i])
			{
				res = false;
				break;
			}
		}
	}
	else if (strategy == JsonbJsonpathPredicateStrategyNumber ||
			 strategy == JsonbJsonpathExistsStrategyNumber)
	{
		*recheck = true;

		if (nkeys > 0)
		{
			Assert(extra_data && extra_data[0]);
			res = execute_jsp_gin_node((JsonPathGinNode *) extra_data[0], check,
									   false) != GIN_FALSE;
		}
	}
	else
		elog(ERROR, "unrecognized strategy number: %d", strategy);

	PG_RETURN_BOOL(res);
}

Datum
gin_triconsistent_jsonb(PG_FUNCTION_ARGS)
{
	GinTernaryValue *check = (GinTernaryValue *) PG_GETARG_POINTER(0);
	StrategyNumber strategy = PG_GETARG_UINT16(1);

	/* Jsonb	   *query = PG_GETARG_JSONB_P(2); */
	int32		nkeys = PG_GETARG_INT32(3);
	Pointer    *extra_data = (Pointer *) PG_GETARG_POINTER(4);
	GinTernaryValue res = GIN_MAYBE;
	int32		i;

	/*
	 * Note that we never return GIN_TRUE, only GIN_MAYBE or GIN_FALSE; this
	 * corresponds to always forcing recheck in the regular consistent
	 * function, for the reasons listed there.
	 */
	if (strategy == JsonbContainsStrategyNumber ||
		strategy == JsonbExistsAllStrategyNumber)
	{
		/* All extracted keys must be present */
		for (i = 0; i < nkeys; i++)
		{
			if (check[i] == GIN_FALSE)
			{
				res = GIN_FALSE;
				break;
			}
		}
	}
	else if (strategy == JsonbExistsStrategyNumber ||
			 strategy == JsonbExistsAnyStrategyNumber)
	{
		/* At least one extracted key must be present */
		res = GIN_FALSE;
		for (i = 0; i < nkeys; i++)
		{
			if (check[i] == GIN_TRUE ||
				check[i] == GIN_MAYBE)
			{
				res = GIN_MAYBE;
				break;
			}
		}
	}
	else if (strategy == JsonbJsonpathPredicateStrategyNumber ||
			 strategy == JsonbJsonpathExistsStrategyNumber)
	{
		if (nkeys > 0)
		{
			Assert(extra_data && extra_data[0]);
			res = execute_jsp_gin_node((JsonPathGinNode *) extra_data[0], check,
									   true);

			/* Should always recheck the result */
			if (res == GIN_TRUE)
				res = GIN_MAYBE;
		}
	}
	else
		elog(ERROR, "unrecognized strategy number: %d", strategy);

	PG_RETURN_GIN_TERNARY_VALUE(res);
}

/*
 *
 * jsonb_path_ops GIN opclass support functions
 *
 * In a jsonb_path_ops index, the GIN keys are uint32 hashes, one per JSON
 * value; but the JSON key(s) leading to each value are also included in its
 * hash computation.  This means we can only support containment queries,
 * but the index can distinguish, for example, {"foo": 42} from {"bar": 42}
 * since different hashes will be generated.
 *
 */

static void
jsonb_path_ops__extract_container(GinEntries *entries, JsonbContainer *jbc,
								  uint32 hash)
{
	JsonbIterator *it;
	JsonbValue	v;
	JsonbIteratorToken r;
	PathHashStack tail;
	PathHashStack *stack;

	/* We keep a stack of partial hashes corresponding to parent key levels */
	tail.parent = NULL;
	tail.hash = hash;
	stack = &tail;

	it = JsonbIteratorInit(jbc);

	while ((r = JsonbIteratorNext(&it, &v, false)) != WJB_DONE)
	{
		PathHashStack *parent;

		switch (r)
		{
			case WJB_BEGIN_ARRAY:
			case WJB_BEGIN_OBJECT:
				/* Push a stack level for this object */
				parent = stack;
				stack = (PathHashStack *) palloc(sizeof(PathHashStack));

				/*
				 * We pass forward hashes from outer nesting levels so that
				 * the hashes for nested values will include outer keys as
				 * well as their own keys.
				 *
				 * Nesting an array within another array will not alter
				 * innermost scalar element hash values, but that seems
				 * inconsequential.
				 */
				stack->hash = parent->hash;
				stack->parent = parent;
				break;
			case WJB_KEY:
				/* mix this key into the current outer hash */
				JsonbHashScalarValue(&v, &stack->hash);
				/* hash is now ready to incorporate the value */
				break;
			case WJB_ELEM:
			case WJB_VALUE:
				/* mix the element or value's hash into the prepared hash */
				JsonbHashScalarValue(&v, &stack->hash);
				/* and emit an index entry */
				add_gin_entry(entries, UInt32GetDatum(stack->hash));
				/* reset hash for next key, value, or sub-object */
				stack->hash = stack->parent->hash;
				break;
			case WJB_END_ARRAY:
			case WJB_END_OBJECT:
				/* Pop the stack */
				parent = stack->parent;
				pfree(stack);
				stack = parent;
				/* reset hash for next key, value, or sub-object */
				if (stack->parent)
					stack->hash = stack->parent->hash;
				else
					stack->hash = hash;
				break;
			default:
				elog(ERROR, "invalid JsonbIteratorNext rc: %d", (int) r);
		}
	}
}

/* jsonb_path_ops: Extract entries from container placed at "path" */
static void
jsonb_path_ops__extract_entries(GinEntries *entries, JsonbValue *jbv,
								JsonPathGinPath path)
{
	uint32		hash = path.hash;

	/* Add all entries from container using the preceding path hash */
	if (jbv->type == jbvBinary)
		jsonb_path_ops__extract_container(entries, jbv->val.binary.data, hash);
	else
	{
		JsonbHashScalarValue(jbv, &hash);
		add_gin_entry(entries, UInt32GetDatum(hash));
	}
}

/*
 *
 * jsonb_path_ops GIN opclass support functions
 *
 * In a jsonb_path_ops index, the GIN keys are uint32 hashes, one per JSON
 * value; but the JSON key(s) leading to each value are also included in its
 * hash computation.  This means we can only support containment queries,
 * but the index can distinguish, for example, {"foo": 42} from {"bar": 42}
 * since different hashes will be generated.
 *
 */

Datum
gin_extract_jsonb_path(PG_FUNCTION_ARGS)
{
	Jsonb	   *jb = (Jsonb *) PG_GETARG_JSONB_P(0);
	int32	   *nentries = (int32 *) PG_GETARG_POINTER(1);
	GinJsonOptions *options = (GinJsonOptions *) PG_GET_OPCLASS_OPTIONS();

	PG_RETURN_POINTER(gin_extract_jsonb_internal(jb, options, true, nentries));
}

Datum
gin_extract_jsonb_query_path(PG_FUNCTION_ARGS)
{
	int32	   *nentries = (int32 *) PG_GETARG_POINTER(1);
	StrategyNumber strategy = PG_GETARG_UINT16(2);
	int32	   *searchMode = (int32 *) PG_GETARG_POINTER(6);
	GinJsonOptions *options = (GinJsonOptions *) PG_GET_OPCLASS_OPTIONS();
	Datum	   *entries;

	if (strategy == JsonbContainsStrategyNumber)
	{
		/* Query is a jsonb, so just apply gin_extract_jsonb_path... */
		Jsonb	   *jb = PG_GETARG_JSONB_P(0);
#if 1
		entries = gin_extract_jsonb_internal(jb, options, true, nentries);
#else
		entries = gin_extract_jsonb_containment(jb, options, true, nentries);
#endif

		/* ...although "contains {}" requires a full index scan */
		if (*nentries == 0)
			*searchMode = GIN_SEARCH_MODE_ALL;
	}
	else if (strategy == JsonbJsonpathPredicateStrategyNumber ||
			 strategy == JsonbJsonpathExistsStrategyNumber)
	{
		JsonPath   *jp = PG_GETARG_JSONPATH_P(0);
		Pointer   **extra_data = (Pointer **) PG_GETARG_POINTER(4);

		entries = extract_jsp_query(jp, options, strategy, true, nentries,
									extra_data);

		if (!entries)
			*searchMode = GIN_SEARCH_MODE_ALL;
	}
	else
	{
		elog(ERROR, "unrecognized strategy number: %d", strategy);
		entries = NULL;
	}

	PG_RETURN_POINTER(entries);
}

Datum
gin_consistent_jsonb_path(PG_FUNCTION_ARGS)
{
	bool	   *check = (bool *) PG_GETARG_POINTER(0);
	StrategyNumber strategy = PG_GETARG_UINT16(1);

	/* Jsonb	   *query = PG_GETARG_JSONB_P(2); */
	int32		nkeys = PG_GETARG_INT32(3);
	Pointer    *extra_data = (Pointer *) PG_GETARG_POINTER(4);
	bool	   *recheck = (bool *) PG_GETARG_POINTER(5);
	bool		res = true;
	int32		i;

	if (strategy == JsonbContainsStrategyNumber)
	{
		/*
		 * jsonb_path_ops is necessarily lossy, not only because of hash
		 * collisions but also because it doesn't preserve complete
		 * information about the structure of the JSON object.  Besides, there
		 * are some special rules around the containment of raw scalars in
		 * arrays that are not handled here.  So we must always recheck a
		 * match.  However, if not all of the keys are present, the tuple
		 * certainly doesn't match.
		 */
		*recheck = true;
		for (i = 0; i < nkeys; i++)
		{
			if (!check[i])
			{
				res = false;
				break;
			}
		}
	}
	else if (strategy == JsonbJsonpathPredicateStrategyNumber ||
			 strategy == JsonbJsonpathExistsStrategyNumber)
	{
		*recheck = true;

		if (nkeys > 0)
		{
			Assert(extra_data && extra_data[0]);
			res = execute_jsp_gin_node((JsonPathGinNode *) extra_data[0], check,
									   false) != GIN_FALSE;
		}
	}
	else
		elog(ERROR, "unrecognized strategy number: %d", strategy);

	PG_RETURN_BOOL(res);
}

Datum
gin_triconsistent_jsonb_path(PG_FUNCTION_ARGS)
{
	GinTernaryValue *check = (GinTernaryValue *) PG_GETARG_POINTER(0);
	StrategyNumber strategy = PG_GETARG_UINT16(1);

	/* Jsonb	   *query = PG_GETARG_JSONB_P(2); */
	int32		nkeys = PG_GETARG_INT32(3);
	Pointer    *extra_data = (Pointer *) PG_GETARG_POINTER(4);
	GinTernaryValue res = GIN_MAYBE;
	int32		i;

	if (strategy == JsonbContainsStrategyNumber)
	{
		/*
		 * Note that we never return GIN_TRUE, only GIN_MAYBE or GIN_FALSE;
		 * this corresponds to always forcing recheck in the regular
		 * consistent function, for the reasons listed there.
		 */
		for (i = 0; i < nkeys; i++)
		{
			if (check[i] == GIN_FALSE)
			{
				res = GIN_FALSE;
				break;
			}
		}
	}
	else if (strategy == JsonbJsonpathPredicateStrategyNumber ||
			 strategy == JsonbJsonpathExistsStrategyNumber)
	{
		if (nkeys > 0)
		{
			Assert(extra_data && extra_data[0]);
			res = execute_jsp_gin_node((JsonPathGinNode *) extra_data[0], check,
									   true);

			/* Should always recheck the result */
			if (res == GIN_TRUE)
				res = GIN_MAYBE;
		}
	}
	else
		elog(ERROR, "unrecognized strategy number: %d", strategy);

	PG_RETURN_GIN_TERNARY_VALUE(res);
}

/*
 * Construct a jsonb_ops GIN key from a flag byte and a textual representation
 * (which need not be null-terminated).  This function is responsible
 * for hashing overlength text representations; it will add the
 * JGINFLAG_HASHED bit to the flag value if it does that.
 */
static Datum
make_text_key(char flag, const char *str, int len)
{
	text	   *item;
	char		hashbuf[10];

	if (len > JGIN_MAXLENGTH)
	{
		uint32		hashval;

		hashval = DatumGetUInt32(hash_any((const unsigned char *) str, len));
		snprintf(hashbuf, sizeof(hashbuf), "%08x", hashval);
		str = hashbuf;
		len = 8;
		flag |= JGINFLAG_HASHED;
	}

	/*
	 * Now build the text Datum.  For simplicity we build a 4-byte-header
	 * varlena text Datum here, but we expect it will get converted to short
	 * header format when stored in the index.
	 */
	item = (text *) palloc(VARHDRSZ + len + 1);
	SET_VARSIZE(item, VARHDRSZ + len + 1);

	*VARDATA(item) = flag;

	memcpy(VARDATA(item) + 1, str, len);

	return PointerGetDatum(item);
}

/*
 * Create a textual representation of a JsonbValue that will serve as a GIN
 * key in a jsonb_ops index.  is_key is true if the JsonbValue is a key,
 * or if it is a string array element (since we pretend those are keys,
 * see jsonb.h).
 */
static Datum
make_scalar_key(const JsonbValue *scalarVal, bool is_key)
{
	Datum		item;
	char	   *cstr;

	switch (scalarVal->type)
	{
		case jbvNull:
			Assert(!is_key);
			item = make_text_key(JGINFLAG_NULL, "", 0);
			break;
		case jbvBool:
			Assert(!is_key);
			item = make_text_key(JGINFLAG_BOOL,
								 scalarVal->val.boolean ? "t" : "f", 1);
			break;
		case jbvNumeric:
			Assert(!is_key);

			/*
			 * A normalized textual representation, free of trailing zeroes,
			 * is required so that numerically equal values will produce equal
			 * strings.
			 *
			 * It isn't ideal that numerics are stored in a relatively bulky
			 * textual format.  However, it's a notationally convenient way of
			 * storing a "union" type in the GIN B-Tree, and indexing Jsonb
			 * strings takes precedence.
			 */
			cstr = numeric_normalize(scalarVal->val.numeric);
			item = make_text_key(JGINFLAG_NUM, cstr, strlen(cstr));
			pfree(cstr);
			break;
		case jbvString:
			item = make_text_key(is_key ? JGINFLAG_KEY : JGINFLAG_STR,
								 scalarVal->val.string.val,
								 scalarVal->val.string.len);
			break;
		default:
			elog(ERROR, "unrecognized jsonb scalar type: %d", scalarVal->type);
			item = 0;			/* keep compiler quiet */
			break;
	}

	return item;
}

static GinTernaryValue
validate_indexed_json_path(GinForEachPathContext *cxt, JsonPathItem *jsp)
{
	JsonPathItem elem;

	if (jsp->type != jpiRoot)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("invalid value of GIN '%s' parameter",
						GIN_JSONB_PROJECTION_PARAM),
				 errhint("Each element of path sequence should start with $")));

	while (jspHasNext(jsp))
	{
		jspGetNext(jsp, &elem);
		jsp = &elem;

		switch (jsp->type)
		{
			case jpiKey:
			case jpiAnyKey:
			case jpiAnyArray:
			case jpiAny:
				break;

			case jpiIndexArray:
				{
					int			i;

					for (i = 0; i < jsp->content.array.nelems; i++)
					{
						JsonPathItem from;
						JsonPathItem to;
						bool		range;

						range = jspGetArraySubscript(jsp, &from, &to, i);

						if (from.type != jpiNumeric || jspHasNext(&from) ||
							(range &&
							 (to.type != jpiNumeric || jspHasNext(&to))))
							ereport(ERROR,
									(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
									 errmsg("invalid value of GIN '%s' parameter",
											GIN_JSONB_PROJECTION_PARAM),
									 errdetail("Array accessors in paths should contain only constant numeric subscripts")));
					}

					break;
				}

			default:
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						 errmsg("invalid value of GIN '%s' parameter",
								GIN_JSONB_PROJECTION_PARAM),
						 errdetail("Invalid element of indexed path")));
		}
	}

	return GIN_FALSE;
}

static void
validate_indexed_json_paths(JsonPath *jspath)
{
	JsonPathItem root;

	jspInit(&root, jspath);

	if (root.type == jpiSequence && jspHasNext(&root))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("invalid value of GIN '%s' parameter",
						GIN_JSONB_PROJECTION_PARAM),
				 errhint("Parameter value should be a sequence without "
						 "any following accessors, filters or methods")));

	foreach_jsonpath(jspath, validate_indexed_json_path, NULL);
}

static JsonPath *
parse_indexed_json_paths(const char *value, bool validate)
{
	JsonPath   *jspath;

	if (!value)
		return NULL;

	jspath = DatumGetJsonPathP(DirectFunctionCall1(jsonpath_in, CStringGetDatum(value)));

	if (validate)
		validate_indexed_json_paths(jspath);

	return jspath;
}

static void
validate_indexed_json_paths_option(const char *value)
{
	(void) parse_indexed_json_paths(value, true);
}

static Size
fill_indexed_json_paths_option(const char *value, void *data)
{
	JsonPath   *jspath = parse_indexed_json_paths(value, false);

	if (data)
	{
		if (jspath)
			memcpy(data, jspath, VARSIZE(jspath));
		else
			SET_VARSIZE(data, 0);
	}

	return jspath ? VARSIZE(jspath) : 4;
}

Datum
gin_options_jsonb(PG_FUNCTION_ARGS)
{
	local_relopts *relopts = (local_relopts *) PG_GETARG_POINTER(0);

	init_local_reloptions(relopts, sizeof(GinJsonOptions));
	add_local_string_reloption(relopts, GIN_JSONB_PROJECTION_PARAM,
							   "indexed json paths", NULL,
							   validate_indexed_json_paths_option,
							   fill_indexed_json_paths_option,
							   offsetof(GinJsonOptions, pathsOffset));

	PG_RETURN_VOID();
}
