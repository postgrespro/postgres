/*-------------------------------------------------------------------------
 *
 * jsonfuncs.c
 *		Functions to process JSON data types.
 *
 * Portions Copyright (c) 1996-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/utils/adt/jsonfuncs.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include <limits.h>

#include "access/htup_details.h"
#include "catalog/pg_type.h"
#include "common/jsonapi.h"
#include "common/string.h"
#include "fmgr.h"
#include "funcapi.h"
#include "lib/stringinfo.h"
#include "mb/pg_wchar.h"
#include "miscadmin.h"
#include "utils/array.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/hsearch.h"
#include "utils/json.h"
#include "utils/jsonb.h"
#include "utils/json_generic.h"
#include "utils/jsonfuncs.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/syscache.h"
#include "utils/typcache.h"

/* Operations available for setPath */
#define JB_PATH_CREATE					0x0001
#define JB_PATH_DELETE					0x0002
#define JB_PATH_REPLACE					0x0004
#define JB_PATH_INSERT_BEFORE			0x0008
#define JB_PATH_INSERT_AFTER			0x0010
#define JB_PATH_CREATE_OR_INSERT \
	(JB_PATH_INSERT_BEFORE | JB_PATH_INSERT_AFTER | JB_PATH_CREATE)
#define JB_PATH_FILL_GAPS				0x0020
#define JB_PATH_CONSISTENT_POSITION		0x0040

/* state for json_object_keys */
typedef struct OkeysState
{
	JsonLexContext *lex;
	char	  **result;
	int			result_size;
	int			result_count;
	int			sent_count;
} OkeysState;

/* state for iterate_json_values function */
typedef struct IterateJsonStringValuesState
{
	JsonLexContext *lex;
	JsonIterateStringValuesAction action;	/* an action that will be applied
											 * to each json value */
	void	   *action_state;	/* any necessary context for iteration */
	uint32		flags;			/* what kind of elements from a json we want
								 * to iterate */
} IterateJsonStringValuesState;

/* state for transform_json_string_values function */
typedef struct TransformJsonStringValuesState
{
	JsonLexContext *lex;
	StringInfo	strval;			/* resulting json */
	JsonTransformStringValuesAction action; /* an action that will be applied
											 * to each json value */
	void	   *action_state;	/* any necessary context for transformation */
} TransformJsonStringValuesState;

/* state for json_get* functions */
typedef struct GetState
{
	JsonLexContext *lex;
	text	   *tresult;
	char	   *result_start;
	bool		normalize_results;
	bool		next_scalar;
	int			npath;			/* length of each path-related array */
	char	  **path_names;		/* field name(s) being sought */
	int		   *path_indexes;	/* array index(es) being sought */
	bool	   *pathok;			/* is path matched to current depth? */
	int		   *array_cur_index;	/* current element index at each path
									 * level */
} GetState;

/* state for json_array_length */
typedef struct AlenState
{
	JsonLexContext *lex;
	int			count;
} AlenState;

/* state for json_each */
typedef struct EachState
{
	JsonLexContext *lex;
	Tuplestorestate *tuple_store;
	TupleDesc	ret_tdesc;
	MemoryContext tmp_cxt;
	char	   *result_start;
	bool		normalize_results;
	bool		next_scalar;
	char	   *normalized_scalar;
} EachState;

/* state for json_array_elements */
typedef struct ElementsState
{
	JsonLexContext *lex;
	const char *function_name;
	Tuplestorestate *tuple_store;
	TupleDesc	ret_tdesc;
	MemoryContext tmp_cxt;
	char	   *result_start;
	bool		normalize_results;
	bool		next_scalar;
	char	   *normalized_scalar;
} ElementsState;

/* state for get_json_object_as_hash */
typedef struct JHashState
{
	JsonLexContext *lex;
	const char *function_name;
	HTAB	   *hash;
	char	   *saved_scalar;
	char	   *save_json_start;
	JsonTokenType saved_token_type;
} JHashState;

/* hashtable element */
typedef struct JsonHashEntry
{
	char		fname[NAMEDATALEN]; /* hash key (MUST BE FIRST) */
	char	   *val;
	JsonTokenType type;
} JsonHashEntry;

/* structure to cache type I/O metadata needed for populate_scalar() */
typedef struct ScalarIOData
{
	Oid			typioparam;
	FmgrInfo	typiofunc;
} ScalarIOData;

/* these two structures are used recursively */
typedef struct ColumnIOData ColumnIOData;
typedef struct RecordIOData RecordIOData;

/* structure to cache metadata needed for populate_array() */
typedef struct ArrayIOData
{
	ColumnIOData *element_info; /* metadata cache */
	Oid			element_type;	/* array element type id */
	int32		element_typmod; /* array element type modifier */
} ArrayIOData;

/* structure to cache metadata needed for populate_composite() */
typedef struct CompositeIOData
{
	/*
	 * We use pointer to a RecordIOData here because variable-length struct
	 * RecordIOData can't be used directly in ColumnIOData.io union
	 */
	RecordIOData *record_io;	/* metadata cache for populate_record() */
	TupleDesc	tupdesc;		/* cached tuple descriptor */
	/* these fields differ from target type only if domain over composite: */
	Oid			base_typid;		/* base type id */
	int32		base_typmod;	/* base type modifier */
	/* this field is used only if target type is domain over composite: */
	void	   *domain_info;	/* opaque cache for domain checks */
} CompositeIOData;

/* structure to cache metadata needed for populate_domain() */
typedef struct DomainIOData
{
	ColumnIOData *base_io;		/* metadata cache */
	Oid			base_typid;		/* base type id */
	int32		base_typmod;	/* base type modifier */
	void	   *domain_info;	/* opaque cache for domain checks */
} DomainIOData;

/* enumeration type categories */
typedef enum TypeCat
{
	TYPECAT_SCALAR = 's',
	TYPECAT_ARRAY = 'a',
	TYPECAT_COMPOSITE = 'c',
	TYPECAT_COMPOSITE_DOMAIN = 'C',
	TYPECAT_DOMAIN = 'd'
} TypeCat;

/* these two are stolen from hstore / record_out, used in populate_record* */

/* structure to cache record metadata needed for populate_record_field() */
struct ColumnIOData
{
	Oid			typid;			/* column type id */
	int32		typmod;			/* column type modifier */
	TypeCat		typcat;			/* column type category */
	ScalarIOData scalar_io;		/* metadata cache for direct conversion
								 * through input function */
	union
	{
		ArrayIOData array;
		CompositeIOData composite;
		DomainIOData domain;
	}			io;				/* metadata cache for various column type
								 * categories */
};

/* structure to cache record metadata needed for populate_record() */
struct RecordIOData
{
	Oid			record_type;
	int32		record_typmod;
	int			ncolumns;
	ColumnIOData columns[FLEXIBLE_ARRAY_MEMBER];
};

/* per-query cache for populate_record_worker and populate_recordset_worker */
typedef struct PopulateRecordCache
{
	Oid			argtype;		/* declared type of the record argument */
	ColumnIOData c;				/* metadata cache for populate_composite() */
	MemoryContext fn_mcxt;		/* where this is stored */
} PopulateRecordCache;

/* per-call state for populate_recordset */
typedef struct PopulateRecordsetState
{
	JsonLexContext *lex;
	const char *function_name;
	HTAB	   *json_hash;
	char	   *saved_scalar;
	char	   *save_json_start;
	JsonTokenType saved_token_type;
	Tuplestorestate *tuple_store;
	HeapTupleHeader rec;
	PopulateRecordCache *cache;
} PopulateRecordsetState;

/* common data for populate_array_json() and populate_array_dim_jsonb() */
typedef struct PopulateArrayContext
{
	ArrayBuildState *astate;	/* array build state */
	ArrayIOData *aio;			/* metadata cache */
	MemoryContext acxt;			/* array build memory context */
	MemoryContext mcxt;			/* cache memory context */
	const char *colname;		/* for diagnostics only */
	int		   *dims;			/* dimensions */
	int		   *sizes;			/* current dimension counters */
	int			ndims;			/* number of dimensions */
} PopulateArrayContext;

/* state for populate_array_json() */
typedef struct PopulateArrayState
{
	JsonLexContext *lex;		/* json lexer */
	PopulateArrayContext *ctx;	/* context */
	char	   *element_start;	/* start of the current array element */
	char	   *element_scalar; /* current array element token if it is a
								 * scalar */
	JsonTokenType element_type; /* current array element type */
} PopulateArrayState;

/* state for json_strip_nulls */
typedef struct StripnullState
{
	JsonLexContext *lex;
	StringInfo	strval;
	bool		skip_next_null;
} StripnullState;

/* structure for generalized json/jsonb value passing */
typedef struct JsValue
{
	union
	{
		JsonbValue *jsonb;		/* jsonb value */
	}			val;
} JsValue;

typedef struct JsObject
{
	union
	{
		JsonbContainer *jsonb_cont;
	}			val;
} JsObject;

/* useful macros for testing JsValue properties */
#define JsValueIsJson(jsv) false

#define JsValueIsNull(jsv) \
	((!(jsv)->val.jsonb || (jsv)->val.jsonb->type == jbvNull))

#define JsValueIsString(jsv) \
	(((jsv)->val.jsonb && (jsv)->val.jsonb->type == jbvString))

#define JsObjectIsEmpty(jso) \
	(!(jso)->val.jsonb_cont || JsonContainerSize((jso)->val.jsonb_cont) == 0)

#define JsObjectFree(jso) ((void) 0)

static int	report_json_context(JsonLexContext *lex);

static JsonValue *get_jsonb_path_all(Json *jb, ArrayType *path,
									 JsonValue *resbuf);
static text *JsonbValueAsText(JsonbValue *v);

static Datum each_worker_json(FunctionCallInfo fcinfo, const char *funcname,
							  bool is_jsonb, bool as_text);

static Datum elements_worker_json(FunctionCallInfo fcinfo, const char *funcname,
								  bool is_jsonb, bool as_text);

/* worker functions for populate_record, to_record, populate_recordset and to_recordset */
static Datum populate_recordset_worker(FunctionCallInfo fcinfo, const char *funcname,
									   bool is_json, bool have_record_arg);
static Datum populate_record_worker(FunctionCallInfo fcinfo, const char *funcname,
									bool is_json, bool have_record_arg);

/* helper functions for populate_record[set] */
static HeapTupleHeader populate_record(TupleDesc tupdesc, RecordIOData **record_p,
									   HeapTupleHeader defaultval, MemoryContext mcxt,
									   JsObject *obj);
static void get_record_type_from_argument(FunctionCallInfo fcinfo,
										  const char *funcname,
										  PopulateRecordCache *cache);
static void get_record_type_from_query(FunctionCallInfo fcinfo,
									   const char *funcname,
									   PopulateRecordCache *cache);
static void JsValueToJsObject(JsValue *jsv, JsObject *jso);
static Datum populate_composite(CompositeIOData *io, Oid typid,
								const char *colname, MemoryContext mcxt,
								HeapTupleHeader defaultval, JsValue *jsv, bool isnull);
static Datum populate_scalar(ScalarIOData *io, Oid typid, int32 typmod, JsValue *jsv);
static void prepare_column_cache(ColumnIOData *column, Oid typid, int32 typmod,
								 MemoryContext mcxt, bool need_scalar);
static Datum populate_record_field(ColumnIOData *col, Oid typid, int32 typmod,
								   const char *colname, MemoryContext mcxt, Datum defaultval,
								   JsValue *jsv, bool *isnull);
static RecordIOData *allocate_record_info(MemoryContext mcxt, int ncolumns);
static bool JsObjectGetField(JsObject *obj, char *field, JsValue *jsv);
static void populate_recordset_record(PopulateRecordsetState *state, JsObject *obj);
static void populate_array_dim_jsonb(PopulateArrayContext *ctx, JsonbValue *jbv,
									 int ndim);
static void populate_array_report_expected_array(PopulateArrayContext *ctx, int ndim);
static void populate_array_assign_ndims(PopulateArrayContext *ctx, int ndims);
static void populate_array_check_dimension(PopulateArrayContext *ctx, int ndim);
static void populate_array_element(PopulateArrayContext *ctx, int ndim, JsValue *jsv);
static Datum populate_array(ArrayIOData *aio, const char *colname,
							MemoryContext mcxt, JsValue *jsv);
static Datum populate_domain(DomainIOData *io, Oid typid, const char *colname,
							 MemoryContext mcxt, JsValue *jsv, bool isnull);

/* functions supporting jsonb_delete, jsonb_set and jsonb_concat */
static JsonbValue *IteratorConcat(JsonbIterator **it1, JsonbIterator **it2,
								  JsonbParseState **state, bool is_jsonb);
static JsonbValue *setPath(JsonbIterator **it, Datum *path_elems,
						   bool *path_nulls, int path_len,
						   JsonbParseState **st, int level, JsonbValue *newval,
						   int op_type);
static JsonbIteratorToken setPathObject(JsonbIterator **it, Datum *path_elems,
										bool *path_nulls, int path_len,
										JsonbParseState **st, int level,
										JsonbValue *newval, int op_type);
static void setPathArray(JsonbIterator **it, Datum *path_elems,
						 bool *path_nulls, int path_len, JsonbParseState **st,
						 int level,
						 JsonbValue *newval, uint32 nelems, int op_type);

static Datum jsonb_strip_nulls_internal(Jsonb *jb);

/*
 * pg_parse_json_or_ereport
 *
 * This function is like pg_parse_json, except that it does not return a
 * JsonParseErrorType. Instead, in case of any failure, this function will
 * ereport(ERROR).
 */
void
pg_parse_json_or_ereport(JsonLexContext *lex, JsonSemAction *sem)
{
	JsonParseErrorType result;

	result = pg_parse_json(lex, sem);
	if (result != JSON_SUCCESS)
		json_ereport_error(result, lex);
}

/*
 * makeJsonLexContext
 *
 * This is like makeJsonLexContextCstringLen, but it accepts a text value
 * directly.
 */
JsonLexContext *
makeJsonLexContext(text *json, bool need_escapes)
{
	return makeJsonLexContextCstringLen(VARDATA_ANY(json),
										VARSIZE_ANY_EXHDR(json),
										GetDatabaseEncoding(),
										need_escapes);
}

/*
 * SQL function json_object_keys
 *
 * Returns the set of keys for the object argument.
 *
 * This SRF operates in value-per-call mode. It processes the
 * object during the first call, and the keys are simply stashed
 * in an array, whose size is expanded as necessary. This is probably
 * safe enough for a list of keys of a single object, since they are
 * limited in size to NAMEDATALEN and the number of keys is unlikely to
 * be so huge that it has major memory implications.
 */
static Datum
jsonb_extract_keys_internal(FunctionCallInfo fcinfo, bool outermost,
							const char * funcname, bool is_jsonb)
{
	FuncCallContext *funcctx;
	OkeysState *state;

	if (SRF_IS_FIRSTCALL())
	{
		MemoryContext oldcontext;
		Jsonb	   *jb = is_jsonb ? PG_GETARG_JSONB_P(0) : PG_GETARG_JSONT_P(0);
		bool		skipNested = false;
		JsonbIterator *it;
		JsonbValue	v;
		JsonbIteratorToken r;

		if (outermost)
		{
			if (JB_ROOT_IS_SCALAR(jb))
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						 errmsg("cannot call %s on a scalar", funcname)));
			else if (JB_ROOT_IS_ARRAY(jb))
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						 errmsg("cannot call %s on an array", funcname)));
		}

		funcctx = SRF_FIRSTCALL_INIT();

		if (!outermost && JB_ROOT_IS_SCALAR(jb))
			SRF_RETURN_DONE(funcctx);

		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		state = palloc(sizeof(OkeysState));

		state->result_size = JB_ROOT_COUNT(jb);
		if (state->result_size < 0)
			state->result_size = 8;
		state->result_count = 0;
		state->sent_count = 0;
		state->result = palloc(state->result_size * sizeof(char *));

		it = JsonbIteratorInit(JsonbRoot(jb));

		while ((r = JsonbIteratorNext(&it, &v, skipNested)) != WJB_DONE)
		{
			skipNested = outermost;

			if (r == WJB_KEY)
			{
				char	   *cstr;

				cstr = palloc(v.val.string.len + 1 * sizeof(char));
				memcpy(cstr, v.val.string.val, v.val.string.len);
				cstr[v.val.string.len] = '\0';
				if (state->result_count >= state->result_size)
				{
					state->result_size *= 2;
					state->result = repalloc(state->result, state->result_size *
															sizeof(char *));
				}
				state->result[state->result_count++] = cstr;
			}
		}

		MemoryContextSwitchTo(oldcontext);
		funcctx->user_fctx = (void *) state;
	}

	funcctx = SRF_PERCALL_SETUP();
	state = (OkeysState *) funcctx->user_fctx;

	if (state->sent_count < state->result_count)
	{
		char	   *nxt = state->result[state->sent_count++];

		SRF_RETURN_NEXT(funcctx, CStringGetTextDatum(nxt));
	}

	SRF_RETURN_DONE(funcctx);
}

Datum
jsonb_object_keys(PG_FUNCTION_ARGS)
{
	return jsonb_extract_keys_internal(fcinfo, true, "jsonb_object_keys", true);
}

Datum
jsonb_extract_keys(PG_FUNCTION_ARGS)
{
	return jsonb_extract_keys_internal(fcinfo, false, "jsonb_extract_keys", true);
}

Datum
json_object_keys(PG_FUNCTION_ARGS)
{
	return jsonb_extract_keys_internal(fcinfo, true, "json_object_keys", false);
}

Datum
json_extract_keys(PG_FUNCTION_ARGS)
{
	return jsonb_extract_keys_internal(fcinfo, false, "json_extract_keys", false);
}

/*
 * Report a JSON error.
 */
void
json_ereport_error(JsonParseErrorType error, JsonLexContext *lex)
{
	if (error == JSON_UNICODE_HIGH_ESCAPE ||
		error == JSON_UNICODE_CODE_POINT_ZERO)
		ereport(ERROR,
				(errcode(ERRCODE_UNTRANSLATABLE_CHARACTER),
				 errmsg("unsupported Unicode escape sequence"),
				 errdetail("%s", json_errdetail(error, lex)),
				 report_json_context(lex)));
	else
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
				 errmsg("invalid input syntax for type %s", "json"),
				 errdetail("%s", json_errdetail(error, lex)),
				 report_json_context(lex)));
}

/*
 * Report a CONTEXT line for bogus JSON input.
 *
 * lex->token_terminator must be set to identify the spot where we detected
 * the error.  Note that lex->token_start might be NULL, in case we recognized
 * error at EOF.
 *
 * The return value isn't meaningful, but we make it non-void so that this
 * can be invoked inside ereport().
 */
static int
report_json_context(JsonLexContext *lex)
{
	const char *context_start;
	const char *context_end;
	const char *line_start;
	char	   *ctxt;
	int			ctxtlen;
	const char *prefix;
	const char *suffix;

	/* Choose boundaries for the part of the input we will display */
	line_start = lex->line_start;
	context_start = line_start;
	context_end = lex->token_terminator;

	/* Advance until we are close enough to context_end */
	while (context_end - context_start >= 50 && context_start < context_end)
	{
		/* Advance to next multibyte character */
		if (IS_HIGHBIT_SET(*context_start))
			context_start += pg_mblen(context_start);
		else
			context_start++;
	}

	/*
	 * We add "..." to indicate that the excerpt doesn't start at the
	 * beginning of the line ... but if we're within 3 characters of the
	 * beginning of the line, we might as well just show the whole line.
	 */
	if (context_start - line_start <= 3)
		context_start = line_start;

	/* Get a null-terminated copy of the data to present */
	ctxtlen = context_end - context_start;
	ctxt = palloc(ctxtlen + 1);
	memcpy(ctxt, context_start, ctxtlen);
	ctxt[ctxtlen] = '\0';

	/*
	 * Show the context, prefixing "..." if not starting at start of line, and
	 * suffixing "..." if not ending at end of line.
	 */
	prefix = (context_start > line_start) ? "..." : "";
	suffix = (lex->token_type != JSON_TOKEN_END && context_end - lex->input < lex->input_length && *context_end != '\n' && *context_end != '\r') ? "..." : "";

	return errcontext("JSON data, line %d: %s%s%s",
					  lex->line_number, prefix, ctxt, suffix);
}

static JsonValue *
json_object_field_internal(Json *jb, text *key)
{
	if (!JB_ROOT_IS_OBJECT(jb))
		return NULL;

	return JsonFindKeyInObject(JsonbRoot(jb),
							   VARDATA_ANY(key),
							   VARSIZE_ANY_EXHDR(key));
}

Datum
jsonb_object_field(PG_FUNCTION_ARGS)
{
	JsonValue  *res = json_object_field_internal(PG_GETARG_JSONB_PC(0),
												 PG_GETARG_TEXT_PP(1));

	if (res)
		PG_RETURN_JSONB_VALUE(res);
	else
		PG_RETURN_NULL();
}

Datum
json_object_field(PG_FUNCTION_ARGS)
{
	JsonValue  *res = json_object_field_internal(PG_GETARG_JSONT_P(0),
												 PG_GETARG_TEXT_PP(1));

	if (res)
		PG_RETURN_JSONT_P(JsonbValueToJsonb(res));
	else
		PG_RETURN_NULL();
}

Datum
jsonb_object_field_text(PG_FUNCTION_ARGS)
{
	JsonValue  *res = json_object_field_internal(PG_GETARG_JSONB_PC(0),
												 PG_GETARG_TEXT_PP(1));

	if (res && res->type != jbvNull)
		PG_RETURN_TEXT_P(JsonbValueAsText(res));
	else
		PG_RETURN_NULL();
}

Datum
json_object_field_text(PG_FUNCTION_ARGS)
{
	JsonValue  *res = json_object_field_internal(PG_GETARG_JSONT_P(0),
												 PG_GETARG_TEXT_PP(1));

	if (res && res->type != jbvNull)
		PG_RETURN_TEXT_P(JsonbValueAsText(res));
	else
		PG_RETURN_NULL();
}

static JsonValue *
json_array_element_internal(Json *jb, int element)
{
	if (!JB_ROOT_IS_ARRAY(jb))
		return NULL;

	/* Handle negative subscript */
	if (element < 0)
	{
		int			nelements = JB_ROOT_COUNT(jb);

		if (nelements < 0)
			nelements = JsonGetArraySize(JsonRoot(jb));

		if (-element > nelements)
			return NULL;
		else
			element += nelements;
	}

	return getIthJsonbValueFromContainer(JsonbRoot(jb), element);
}

Datum
jsonb_array_element(PG_FUNCTION_ARGS)
{
	JsonValue  *res = json_array_element_internal(PG_GETARG_JSONB_P(0),
												  PG_GETARG_INT32(1));

	if (res)
		PG_RETURN_JSONB_P(JsonbValueToJsonb(res));
	else
		PG_RETURN_NULL();
}

Datum
json_array_element(PG_FUNCTION_ARGS)
{
	JsonValue  *res = json_array_element_internal(PG_GETARG_JSONT_P(0),
												  PG_GETARG_INT32(1));

	if (res)
		PG_RETURN_JSONT_P(JsonbValueToJsonb(res));
	else
		PG_RETURN_NULL();
}

Datum
jsonb_array_element_text(PG_FUNCTION_ARGS)
{
	JsonValue  *res = json_array_element_internal(PG_GETARG_JSONB_P(0),
												  PG_GETARG_INT32(1));

	if (res && res->type != jbvNull)
		PG_RETURN_TEXT_P(JsonbValueAsText(res));
	else
		PG_RETURN_NULL();
}

Datum
json_array_element_text(PG_FUNCTION_ARGS)
{
	JsonValue  *res = json_array_element_internal(PG_GETARG_JSONT_P(0),
												  PG_GETARG_INT32(1));

	if (res && res->type != jbvNull)
		PG_RETURN_TEXT_P(JsonbValueAsText(res));
	else
		PG_RETURN_NULL();
}

Datum
jsonb_extract_path(PG_FUNCTION_ARGS)
{
	JsonValue		buf;
	JsonValue	   *res = get_jsonb_path_all(PG_GETARG_JSONB_P(0),
											 PG_GETARG_ARRAYTYPE_P(1), &buf);

	if (res)
		PG_RETURN_JSONB_P(JsonbValueToJsonb(res));
	else
		PG_RETURN_NULL();
}

Datum
json_extract_path(PG_FUNCTION_ARGS)
{
	JsonValue		buf;
	JsonValue	   *res = get_jsonb_path_all(PG_GETARG_JSONT_P(0),
											 PG_GETARG_ARRAYTYPE_P(1), &buf);

	if (res)
		PG_RETURN_JSONT_P(JsonbValueToJsonb(res));
	else
		PG_RETURN_NULL();
}

Datum
jsonb_extract_path_text(PG_FUNCTION_ARGS)
{
	JsonValue		buf;
	JsonValue	   *res = get_jsonb_path_all(PG_GETARG_JSONB_P(0),
											 PG_GETARG_ARRAYTYPE_P(1), &buf);

	if (res && res->type != jbvNull)
		PG_RETURN_TEXT_P(JsonbValueAsText(res));
	else
		PG_RETURN_NULL();
}

Datum
json_extract_path_text(PG_FUNCTION_ARGS)
{
	JsonValue		buf;
	JsonValue	   *res = get_jsonb_path_all(PG_GETARG_JSONT_P(0),
											 PG_GETARG_ARRAYTYPE_P(1), &buf);

	if (res && res->type != jbvNull)
		PG_RETURN_TEXT_P(JsonbValueAsText(res));
	else
		PG_RETURN_NULL();
}

static JsonValue *
get_jsonb_path_all(Json *jb, ArrayType *path, JsonValue *resbuf)
{
	Datum	   *pathtext;
	bool	   *pathnulls;
	int			npath;

	/*
	 * If the array contains any null elements, return NULL, on the grounds
	 * that you'd have gotten NULL if any RHS value were NULL in a nested
	 * series of applications of the -> operator.  (Note: because we also
	 * return NULL for error cases such as no-such-field, this is true
	 * regardless of the contents of the rest of the array.)
	 */
	if (array_contains_nulls(path))
		return NULL;

	deconstruct_array(path, TEXTOID, -1, false, TYPALIGN_INT,
					  &pathtext, &pathnulls, &npath);

	return jsonb_get_element(jb, pathtext, npath, resbuf);
}

JsonValue *
jsonb_get_element(Jsonb *jb, Datum *path, int npath, JsonValue *resbuf)
{
	JsonbContainer *container = JsonbRoot(jb);
	JsonbValue *jbvp = NULL;
	int			i;
	bool		have_object = false,
				have_array = false;

	/* Identify whether we have object, array, or scalar at top-level */
	if (JB_ROOT_IS_OBJECT(jb))
		have_object = true;
	else if (JB_ROOT_IS_ARRAY(jb) && !JB_ROOT_IS_SCALAR(jb))
		have_array = true;
	else
	{
		Assert(JB_ROOT_IS_ARRAY(jb) && JB_ROOT_IS_SCALAR(jb));
		/* Extract the scalar value, if it is what we'll return */
		if (npath <= 0)
			jbvp = getIthJsonbValueFromContainer(container, 0);
	}

	/*
	 * If the array is empty, return the entire LHS object, on the grounds
	 * that we should do zero field or element extractions.  For the
	 * non-scalar case we can just hand back the object without much work. For
	 * the scalar case, fall through and deal with the value below the loop.
	 * (This inconsistency arises because there's no easy way to generate a
	 * JsonbValue directly for root-level containers.)
	 */
	if (npath <= 0 && jbvp == NULL)
		return JsonValueInitBinary(resbuf, container);

	for (i = 0; i < npath; i++)
	{
		if (have_object)
		{
			jbvp = JsonFindKeyInObject(container,
									   VARDATA(path[i]),
									   VARSIZE(path[i]) - VARHDRSZ);
		}
		else if (have_array)
		{
			int			lindex;
			uint32		index;
			char	   *indextext = TextDatumGetCString(path[i]);
			char	   *endptr;

			errno = 0;
			lindex = strtoint(indextext, &endptr, 10);
			if (endptr == indextext || *endptr != '\0' || errno != 0)
				return NULL;

			if (lindex >= 0)
			{
				index = (uint32) lindex;
			}
			else
			{
				/* Handle negative subscript */
				uint32		nelements;

				/* Container must be array, but make sure */

				if (!JsonContainerIsArray(container))
					elog(ERROR, "not a "JSONB" array");

				nelements = JsonContainerSize(container) >= 0 ?
							JsonContainerSize(container) :
							JsonGetArraySize(container);

				if (lindex == INT_MIN || -lindex > nelements)
					return NULL;
				else
					index = nelements + lindex;
			}

			jbvp = getIthJsonbValueFromContainer(container, index);
		}
		else
		{
			/* scalar, extraction yields a null */
			return NULL;
		}

		if (jbvp == NULL)
			return NULL;
		else if (i == npath - 1)
			break;

		if (jbvp->type == jbvBinary)
		{
			container = jbvp->val.binary.data;
			have_object = JsonContainerIsObject(container);
			have_array = JsonContainerIsArray(container);
			Assert(!JsonContainerIsScalar(container));
		}
		else
		{
			have_object = jbvp->type == jbvObject;
			have_array = jbvp->type == jbvArray;
			if (have_object || have_array)
				container = JsonValueToContainer(jbvp);
		}
	}

	return jbvp;
}

Datum
jsonb_set_element(Jsonb *jb, Datum *path, int path_len,
				  JsonbValue *newval)
{
	JsonbValue *res;
	JsonbParseState *state = NULL;
	JsonbIterator *it;
	bool	   *path_nulls = palloc0(path_len * sizeof(bool));

	if (newval->type == jbvArray && newval->val.array.rawScalar)
		*newval = newval->val.array.elems[0];

	it = JsonbIteratorInit(JsonbRoot(jb));

	res = setPath(&it, path, path_nulls, path_len, &state, 0, newval,
				  JB_PATH_CREATE | JB_PATH_FILL_GAPS |
				  JB_PATH_CONSISTENT_POSITION);

	pfree(path_nulls);

	PG_RETURN_JSONB_P(JsonbValueToJsonb(res));
}

static void
push_null_elements(JsonbParseState **ps, int num)
{
	JsonbValue	null;

	null.type = jbvNull;

	while (num-- > 0)
		pushJsonbValue(ps, WJB_ELEM, &null);
}

/*
 * Prepare a new structure containing nested empty objects and arrays
 * corresponding to the specified path, and assign a new value at the end of
 * this path. E.g. the path [a][0][b] with the new value 1 will produce the
 * structure {a: [{b: 1}]}.
 *
 * Called is responsible to make sure such path does not exist yet.
 */
static void
push_path(JsonbParseState **st, int level, Datum *path_elems,
		  bool *path_nulls, int path_len, JsonbValue *newval)
{
	/*
	 * tpath contains expected type of an empty jsonb created at each level
	 * higher or equal than the current one, either jbvObject or jbvArray.
	 * Since it contains only information about path slice from level to the
	 * end, the access index must be normalized by level.
	 */
	enum jbvType *tpath = palloc0((path_len - level) * sizeof(enum jbvType));
	JsonbValue	newkey;

	/*
	 * Create first part of the chain with beginning tokens. For the current
	 * level WJB_BEGIN_OBJECT/WJB_BEGIN_ARRAY was already created, so start
	 * with the next one.
	 */
	for (int i = level + 1; i < path_len; i++)
	{
		char	   *c,
				   *badp;
		int			lindex;

		if (path_nulls[i])
			break;

		/*
		 * Try to convert to an integer to find out the expected type, object
		 * or array.
		 */
		c = TextDatumGetCString(path_elems[i]);
		errno = 0;
		lindex = strtoint(c, &badp, 10);
		if (badp == c || *badp != '\0' || errno != 0)
		{
			/* text, an object is expected */
			newkey.type = jbvString;
			newkey.val.string.len = VARSIZE_ANY_EXHDR(path_elems[i]);
			newkey.val.string.val = VARDATA_ANY(path_elems[i]);

			(void) pushJsonbValue(st, WJB_BEGIN_OBJECT, NULL);
			(void) pushJsonbValue(st, WJB_KEY, &newkey);

			tpath[i - level] = jbvObject;
		}
		else
		{
			/* integer, an array is expected */
			(void) pushJsonbValue(st, WJB_BEGIN_ARRAY, NULL);

			push_null_elements(st, lindex);

			tpath[i - level] = jbvArray;
		}
	}

	/* Insert an actual value for either an object or array */
	if (tpath[(path_len - level) - 1] == jbvArray)
	{
		(void) pushJsonbValueExt(st, WJB_ELEM, newval, false);
	}
	else
		(void) pushJsonbValueExt(st, WJB_VALUE, newval, false);

	/*
	 * Close everything up to the last but one level. The last one will be
	 * closed outside of this function.
	 */
	for (int i = path_len - 1; i > level; i--)
	{
		if (path_nulls[i])
			break;

		if (tpath[i - level] == jbvObject)
			(void) pushJsonbValue(st, WJB_END_OBJECT, NULL);
		else
			(void) pushJsonbValue(st, WJB_END_ARRAY, NULL);
	}
}

/*
 * Return the text representation of the given JsonbValue.
 */
static text *
JsonbValueAsText(JsonbValue *v)
{
	JsonbValue	vbuf;

	switch (v->type)
	{
		case jbvNull:
			return NULL;

		case jbvBool:
			return v->val.boolean ?
				cstring_to_text_with_len("true", 4) :
				cstring_to_text_with_len("false", 5);

		case jbvString:
			return cstring_to_text_with_len(v->val.string.val,
											v->val.string.len);

		case jbvNumeric:
			{
				Datum		cstr;

				cstr = DirectFunctionCall1(numeric_out,
										   PointerGetDatum(v->val.numeric));

				return cstring_to_text(DatumGetCString(cstr));
			}

		case jbvObject:
		case jbvArray:
			v = JsonValueWrapInBinary(v, &vbuf);
			/* fall through */

		case jbvBinary:
			{
				StringInfoData jtext;

				initStringInfo(&jtext);
				(void) JsonToCString(v->val.binary.data, &jtext);

				return cstring_to_text_with_len(jtext.data, jtext.len);
			}

		default:
			elog(ERROR, "unrecognized jsonb type: %d", (int) v->type);
			return NULL;
	}
}

static int
json_array_length_internal(Json *jb)
{
	if (JB_ROOT_IS_SCALAR(jb))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("cannot get array length of a scalar")));
	else if (!JB_ROOT_IS_ARRAY(jb))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("cannot get array length of a non-array")));

	return JB_ROOT_COUNT(jb) >= 0 ? JB_ROOT_COUNT(jb) :
		JsonGetArraySize(JsonRoot(jb));
}

Datum
jsonb_array_length(PG_FUNCTION_ARGS)
{
	PG_RETURN_INT32(json_array_length_internal(PG_GETARG_JSONB_P(0)));
}

Datum
json_array_length(PG_FUNCTION_ARGS)
{
	PG_RETURN_INT32(json_array_length_internal(PG_GETARG_JSONT_P(0)));
}

Datum
jsonb_each(PG_FUNCTION_ARGS)
{
	return each_worker_json(fcinfo, "jsonb_each", true, false);
}

Datum
jsonb_each_text(PG_FUNCTION_ARGS)
{
	return each_worker_json(fcinfo, "jsonb_each_text", true, true);
}

Datum
json_each(PG_FUNCTION_ARGS)
{
	return each_worker_json(fcinfo, "json_each", false, false);
}

Datum
json_each_text(PG_FUNCTION_ARGS)
{
	return each_worker_json(fcinfo, "json_each_text", false, true);
}

static Datum
each_worker_json(FunctionCallInfo fcinfo, const char *funcname,
				 bool is_jsonb, bool as_text)
{
	Json	   *jb = is_jsonb ? PG_GETARG_JSONB_P(0) : PG_GETARG_JSONT_P(0);
	ReturnSetInfo *rsi;
	Tuplestorestate *tuple_store;
	TupleDesc	tupdesc;
	TupleDesc	ret_tdesc;
	MemoryContext old_cxt,
				tmp_cxt;
	bool		skipNested = false;
	JsonbIterator *it;
	JsonbValue	v;
	JsonbIteratorToken r;

	if (!JB_ROOT_IS_OBJECT(jb))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("cannot call %s on a non-object",
						funcname)));

	rsi = (ReturnSetInfo *) fcinfo->resultinfo;

	if (!rsi || !IsA(rsi, ReturnSetInfo) ||
		(rsi->allowedModes & SFRM_Materialize) == 0 ||
		rsi->expectedDesc == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("set-valued function called in context that "
						"cannot accept a set")));

	rsi->returnMode = SFRM_Materialize;

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("function returning record called in context "
						"that cannot accept type record")));

	old_cxt = MemoryContextSwitchTo(rsi->econtext->ecxt_per_query_memory);

	ret_tdesc = CreateTupleDescCopy(tupdesc);
	BlessTupleDesc(ret_tdesc);
	tuple_store =
		tuplestore_begin_heap(rsi->allowedModes & SFRM_Materialize_Random,
							  false, work_mem);

	MemoryContextSwitchTo(old_cxt);

	tmp_cxt = AllocSetContextCreate(CurrentMemoryContext,
									"json_each temporary cxt",
									ALLOCSET_DEFAULT_SIZES);

	it = JsonbIteratorInit(JsonbRoot(jb));

	while ((r = JsonbIteratorNext(&it, &v, skipNested)) != WJB_DONE)
	{
		skipNested = true;

		if (r == WJB_KEY)
		{
			text	   *key;
			HeapTuple	tuple;
			Datum		values[2];
			bool		nulls[2] = {false, false};

			/* Use the tmp context so we can clean up after each tuple is done */
			old_cxt = MemoryContextSwitchTo(tmp_cxt);

			key = cstring_to_text_with_len(v.val.string.val, v.val.string.len);

			/*
			 * The next thing the iterator fetches should be the value, no
			 * matter what shape it is.
			 */
			r = JsonbIteratorNext(&it, &v, skipNested);
			Assert(r != WJB_DONE);

			values[0] = PointerGetDatum(key);

			if (as_text)
			{
				if (v.type == jbvNull)
				{
					/* a json null is an sql null in text mode */
					nulls[1] = true;
					values[1] = (Datum) NULL;
				}
				else
					values[1] = PointerGetDatum(JsonbValueAsText(&v));
			}
			else
			{
				/* Not in text mode, just return the Jsonb */
				Jsonb	   *val = JsonbValueToJsonb(&v);

				values[1] = is_jsonb ? JsonbPGetDatum(val) : JsontPGetDatum(val);
			}

			tuple = heap_form_tuple(ret_tdesc, values, nulls);

			tuplestore_puttuple(tuple_store, tuple);

			/* clean up and switch back */
			MemoryContextSwitchTo(old_cxt);
			MemoryContextReset(tmp_cxt);
		}
	}

	MemoryContextDelete(tmp_cxt);

	rsi->setResult = tuple_store;
	rsi->setDesc = ret_tdesc;

	PG_RETURN_NULL();
}

/*
 * SQL functions json_array_elements and json_array_elements_text
 *
 * get the elements from a json array
 *
 * a lot of this processing is similar to the json_each* functions
 */

Datum
jsonb_array_elements(PG_FUNCTION_ARGS)
{
	return elements_worker_json(fcinfo, "jsonb_array_elements", true, false);
}

Datum
jsonb_array_elements_text(PG_FUNCTION_ARGS)
{
	return elements_worker_json(fcinfo, "jsonb_array_elements_text", true, true);
}

Datum
json_array_elements(PG_FUNCTION_ARGS)
{
	return elements_worker_json(fcinfo, "json_array_elements", false, false);
}

Datum
json_array_elements_text(PG_FUNCTION_ARGS)
{
	return elements_worker_json(fcinfo, "json_array_elements_text", false, true);
}

static Datum
elements_worker_json(FunctionCallInfo fcinfo, const char *funcname,
					 bool is_jsonb, bool as_text)
{
	Json	   *jb = is_jsonb ? PG_GETARG_JSONB_P(0) : PG_GETARG_JSONT_P(0);
	ReturnSetInfo *rsi;
	Tuplestorestate *tuple_store;
	TupleDesc	tupdesc;
	TupleDesc	ret_tdesc;
	MemoryContext old_cxt,
				tmp_cxt;
	bool		skipNested = false;
	JsonbIterator *it;
	JsonbValue	v;
	JsonbIteratorToken r;

	if (JB_ROOT_IS_SCALAR(jb))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("cannot extract elements from a scalar")));
	else if (!JB_ROOT_IS_ARRAY(jb))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("cannot extract elements from an object")));

	rsi = (ReturnSetInfo *) fcinfo->resultinfo;

	if (!rsi || !IsA(rsi, ReturnSetInfo) ||
		(rsi->allowedModes & SFRM_Materialize) == 0 ||
		rsi->expectedDesc == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("set-valued function called in context that "
						"cannot accept a set")));

	rsi->returnMode = SFRM_Materialize;

	/* it's a simple type, so don't use get_call_result_type() */
	tupdesc = rsi->expectedDesc;

	old_cxt = MemoryContextSwitchTo(rsi->econtext->ecxt_per_query_memory);

	ret_tdesc = CreateTupleDescCopy(tupdesc);
	BlessTupleDesc(ret_tdesc);
	tuple_store =
		tuplestore_begin_heap(rsi->allowedModes & SFRM_Materialize_Random,
							  false, work_mem);

	MemoryContextSwitchTo(old_cxt);

	tmp_cxt = AllocSetContextCreate(CurrentMemoryContext,
									JSONB"_array_elements temporary cxt",
									ALLOCSET_DEFAULT_SIZES);

	it = JsonbIteratorInit(JsonbRoot(jb));

	while ((r = JsonbIteratorNext(&it, &v, skipNested)) != WJB_DONE)
	{
		skipNested = true;

		if (r == WJB_ELEM)
		{
			HeapTuple	tuple;
			Datum		values[1];
			bool		nulls[1] = {false};

			/* use the tmp context so we can clean up after each tuple is done */
			old_cxt = MemoryContextSwitchTo(tmp_cxt);

			if (as_text)
			{
				if (v.type == jbvNull)
				{
					/* a json null is an sql null in text mode */
					nulls[0] = true;
					values[0] = (Datum) NULL;
				}
				else
					values[0] = PointerGetDatum(JsonbValueAsText(&v));
			}
			else
			{
				/* Not in text mode, just return the Jsonb */
				Jsonb	   *val = JsonbValueToJsonb(&v);

				values[0] = is_jsonb ? JsonbPGetDatum(val) : JsontPGetDatum(val);
			}

			tuple = heap_form_tuple(ret_tdesc, values, nulls);

			tuplestore_puttuple(tuple_store, tuple);

			/* clean up and switch back */
			MemoryContextSwitchTo(old_cxt);
			MemoryContextReset(tmp_cxt);
		}
	}

	MemoryContextDelete(tmp_cxt);

	rsi->setResult = tuple_store;
	rsi->setDesc = ret_tdesc;

	PG_RETURN_NULL();
}

/*
 * SQL function json_populate_record
 *
 * set fields in a record from the argument json
 *
 * Code adapted shamelessly from hstore's populate_record
 * which is in turn partly adapted from record_out.
 *
 * The json is decomposed into a hash table, in which each
 * field in the record is then looked up by name. For jsonb
 * we fetch the values direct from the object.
 */
Datum
jsonb_populate_record(PG_FUNCTION_ARGS)
{
	return populate_record_worker(fcinfo, "jsonb_populate_record", false, true);
}

Datum
jsonb_to_record(PG_FUNCTION_ARGS)
{
	return populate_record_worker(fcinfo, "jsonb_to_record", false, false);
}

Datum
json_populate_record(PG_FUNCTION_ARGS)
{
	return populate_record_worker(fcinfo, "json_populate_record", true, true);
}

Datum
json_to_record(PG_FUNCTION_ARGS)
{
	return populate_record_worker(fcinfo, "json_to_record", true, false);
}

/* helper function for diagnostics */
static void
populate_array_report_expected_array(PopulateArrayContext *ctx, int ndim)
{
	if (ndim <= 0)
	{
		if (ctx->colname)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
					 errmsg("expected JSON array"),
					 errhint("See the value of key \"%s\".", ctx->colname)));
		else
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
					 errmsg("expected JSON array")));
	}
	else
	{
		StringInfoData indices;
		int			i;

		initStringInfo(&indices);

		Assert(ctx->ndims > 0 && ndim < ctx->ndims);

		for (i = 0; i < ndim; i++)
			appendStringInfo(&indices, "[%d]", ctx->sizes[i]);

		if (ctx->colname)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
					 errmsg("expected JSON array"),
					 errhint("See the array element %s of key \"%s\".",
							 indices.data, ctx->colname)));
		else
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
					 errmsg("expected JSON array"),
					 errhint("See the array element %s.",
							 indices.data)));
	}
}

/* set the number of dimensions of the populated array when it becomes known */
static void
populate_array_assign_ndims(PopulateArrayContext *ctx, int ndims)
{
	int			i;

	Assert(ctx->ndims <= 0);

	if (ndims <= 0)
		populate_array_report_expected_array(ctx, ndims);

	ctx->ndims = ndims;
	ctx->dims = palloc(sizeof(int) * ndims);
	ctx->sizes = palloc0(sizeof(int) * ndims);

	for (i = 0; i < ndims; i++)
		ctx->dims[i] = -1;		/* dimensions are unknown yet */
}

/* check the populated subarray dimension */
static void
populate_array_check_dimension(PopulateArrayContext *ctx, int ndim)
{
	int			dim = ctx->sizes[ndim]; /* current dimension counter */

	if (ctx->dims[ndim] == -1)
		ctx->dims[ndim] = dim;	/* assign dimension if not yet known */
	else if (ctx->dims[ndim] != dim)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
				 errmsg("malformed JSON array"),
				 errdetail("Multidimensional arrays must have "
						   "sub-arrays with matching dimensions.")));

	/* reset the current array dimension size counter */
	ctx->sizes[ndim] = 0;

	/* increment the parent dimension counter if it is a nested sub-array */
	if (ndim > 0)
		ctx->sizes[ndim - 1]++;
}

static void
populate_array_element(PopulateArrayContext *ctx, int ndim, JsValue *jsv)
{
	Datum		element;
	bool		element_isnull;

	/* populate the array element */
	element = populate_record_field(ctx->aio->element_info,
									ctx->aio->element_type,
									ctx->aio->element_typmod,
									NULL, ctx->mcxt, PointerGetDatum(NULL),
									jsv, &element_isnull);

	accumArrayResult(ctx->astate, element, element_isnull,
					 ctx->aio->element_type, ctx->acxt);

	Assert(ndim > 0);
	ctx->sizes[ndim - 1]++;		/* increment current dimension counter */
}

/*
 * populate_array_dim_jsonb() -- Iterate recursively through jsonb sub-array
 *		elements and accumulate result using given ArrayBuildState.
 */
static void
populate_array_dim_jsonb(PopulateArrayContext *ctx, /* context */
						 JsonbValue *jbv,	/* jsonb sub-array */
						 int ndim)	/* current dimension */
{
	JsonbContainer *jbc = jbv->val.binary.data;
	JsonbIterator *it;
	JsonbIteratorToken tok;
	JsonbValue	val;
	JsValue		jsv;

	check_stack_depth();

	if (jbv->type != jbvBinary || !JsonContainerIsArray(jbc))
		populate_array_report_expected_array(ctx, ndim - 1);

	Assert(!JsonContainerIsScalar(jbc));

	it = JsonbIteratorInit(jbc);

	tok = JsonbIteratorNext(&it, &val, true);
	Assert(tok == WJB_BEGIN_ARRAY);

	tok = JsonbIteratorNext(&it, &val, true);

	/*
	 * If the number of dimensions is not yet known and we have found end of
	 * the array, or the first child element is not an array, then assign the
	 * number of dimensions now.
	 */
	if (ctx->ndims <= 0 &&
		(tok == WJB_END_ARRAY ||
		 (tok == WJB_ELEM &&
		  (val.type != jbvBinary ||
		   !JsonContainerIsArray(val.val.binary.data)))))
		populate_array_assign_ndims(ctx, ndim);

	jsv.val.jsonb = &val;

	/* process all the array elements */
	while (tok == WJB_ELEM)
	{
		/*
		 * Recurse only if the dimensions of dimensions is still unknown or if
		 * it is not the innermost dimension.
		 */
		if (ctx->ndims > 0 && ndim >= ctx->ndims)
			populate_array_element(ctx, ndim, &jsv);
		else
		{
			/* populate child sub-array */
			populate_array_dim_jsonb(ctx, &val, ndim + 1);

			/* number of dimensions should be already known */
			Assert(ctx->ndims > 0 && ctx->dims);

			populate_array_check_dimension(ctx, ndim);
		}

		tok = JsonbIteratorNext(&it, &val, true);
	}

	Assert(tok == WJB_END_ARRAY);

	/* free iterator, iterating until WJB_DONE */
	tok = JsonbIteratorNext(&it, &val, true);
	Assert(tok == WJB_DONE && !it);
}

/* recursively populate an array from json/jsonb */
static Datum
populate_array(ArrayIOData *aio,
			   const char *colname,
			   MemoryContext mcxt,
			   JsValue *jsv)
{
	PopulateArrayContext ctx;
	Datum		result;
	int		   *lbs;
	int			i;

	ctx.aio = aio;
	ctx.mcxt = mcxt;
	ctx.acxt = CurrentMemoryContext;
	ctx.astate = initArrayResult(aio->element_type, ctx.acxt, true);
	ctx.colname = colname;
	ctx.ndims = 0;				/* unknown yet */
	ctx.dims = NULL;
	ctx.sizes = NULL;

	populate_array_dim_jsonb(&ctx, jsv->val.jsonb, 1);
	ctx.dims[0] = ctx.sizes[0];

	Assert(ctx.ndims > 0);

	lbs = palloc(sizeof(int) * ctx.ndims);

	for (i = 0; i < ctx.ndims; i++)
		lbs[i] = 1;

	result = makeMdArrayResult(ctx.astate, ctx.ndims, ctx.dims, lbs,
							   ctx.acxt, true);

	pfree(ctx.dims);
	pfree(ctx.sizes);
	pfree(lbs);

	return result;
}

static void
JsValueToJsObject(JsValue *jsv, JsObject *jso)
{
	JsonbValue *jbv = jsv->val.jsonb;

	if (jbv->type == jbvBinary &&
		JsonContainerIsObject(jbv->val.binary.data))
	{
		jso->val.jsonb_cont = jbv->val.binary.data;
	}
	else if (jbv->type == jbvObject)
	{
		jso->val.jsonb_cont = JsonValueToContainer(jbv);
	}
	else
	{
		bool		is_scalar;

		is_scalar = IsAJsonbScalar(jbv) ||
			(jbv->type == jbvBinary &&
			 JsonContainerIsScalar(jbv->val.binary.data));
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 is_scalar
				 ? errmsg("cannot call %s on a scalar",
						  "populate_composite")
				 : errmsg("cannot call %s on an array",
						  "populate_composite")));
	}
}

/* acquire or update cached tuple descriptor for a composite type */
static void
update_cached_tupdesc(CompositeIOData *io, MemoryContext mcxt)
{
	if (!io->tupdesc ||
		io->tupdesc->tdtypeid != io->base_typid ||
		io->tupdesc->tdtypmod != io->base_typmod)
	{
		TupleDesc	tupdesc = lookup_rowtype_tupdesc(io->base_typid,
													 io->base_typmod);
		MemoryContext oldcxt;

		if (io->tupdesc)
			FreeTupleDesc(io->tupdesc);

		/* copy tuple desc without constraints into cache memory context */
		oldcxt = MemoryContextSwitchTo(mcxt);
		io->tupdesc = CreateTupleDescCopy(tupdesc);
		MemoryContextSwitchTo(oldcxt);

		ReleaseTupleDesc(tupdesc);
	}
}

/* recursively populate a composite (row type) value from json/jsonb */
static Datum
populate_composite(CompositeIOData *io,
				   Oid typid,
				   const char *colname,
				   MemoryContext mcxt,
				   HeapTupleHeader defaultval,
				   JsValue *jsv,
				   bool isnull)
{
	Datum		result;

	/* acquire/update cached tuple descriptor */
	update_cached_tupdesc(io, mcxt);

	if (isnull)
		result = (Datum) 0;
	else
	{
		HeapTupleHeader tuple;
		JsObject	jso;

		/* prepare input value */
		JsValueToJsObject(jsv, &jso);

		/* populate resulting record tuple */
		tuple = populate_record(io->tupdesc, &io->record_io,
								defaultval, mcxt, &jso);
		result = HeapTupleHeaderGetDatum(tuple);

		JsObjectFree(&jso);
	}

	/*
	 * If it's domain over composite, check domain constraints.  (This should
	 * probably get refactored so that we can see the TYPECAT value, but for
	 * now, we can tell by comparing typid to base_typid.)
	 */
	if (typid != io->base_typid && typid != RECORDOID)
		domain_check(result, isnull, typid, &io->domain_info, mcxt);

	return result;
}

/* populate non-null scalar value from json/jsonb value */
static Datum
populate_scalar(ScalarIOData *io, Oid typid, int32 typmod, JsValue *jsv)
{
	Datum		res;
	char	   *str = NULL;
	char	   *json = NULL;

	{
		JsonbValue *jbv = jsv->val.jsonb;

		if (typid == JSONBOID)
		{
			Jsonb	   *jsonb = JsonbValueToJsonb(jbv); /* directly use jsonb */

			return JsonbPGetDatum(jsonb);
		}
		/* convert jsonb to string for typio call */
		else if (typid == JSONOID && jbv->type != jbvBinary)
		{
			/*
			 * Convert scalar jsonb (non-scalars are passed here as jbvBinary)
			 * to json string, preserving quotes around top-level strings.
			 */
			Jsonb	   *jsonb = JsonbValueToJsonb(jbv);

			str = JsonToCString(&jsonb->root, NULL);
		}
		else if (jbv->type == jbvString)	/* quotes are stripped */
			str = pnstrdup(jbv->val.string.val, jbv->val.string.len);
		else if (jbv->type == jbvBool)
			str = pstrdup(jbv->val.boolean ? "true" : "false");
		else if (jbv->type == jbvNumeric)
			str = DatumGetCString(DirectFunctionCall1(numeric_out,
													  PointerGetDatum(jbv->val.numeric)));
		else if (jbv->type == jbvObject || jbv->type == jbvArray)
			str = JsonToCString(JsonValueToContainer(jbv), NULL);
		else if (jbv->type == jbvBinary)
			str = JsonToCString(jbv->val.binary.data, NULL);
		else
			elog(ERROR, "unrecognized jsonb type: %d", (int) jbv->type);
	}

	res = InputFunctionCall(&io->typiofunc, str, io->typioparam, typmod);

	/* free temporary buffer */
	if (str != json)
		pfree(str);

	return res;
}

static Datum
populate_domain(DomainIOData *io,
				Oid typid,
				const char *colname,
				MemoryContext mcxt,
				JsValue *jsv,
				bool isnull)
{
	Datum		res;

	if (isnull)
		res = (Datum) 0;
	else
	{
		res = populate_record_field(io->base_io,
									io->base_typid, io->base_typmod,
									colname, mcxt, PointerGetDatum(NULL),
									jsv, &isnull);
		Assert(!isnull);
	}

	domain_check(res, isnull, typid, &io->domain_info, mcxt);

	return res;
}

/* prepare column metadata cache for the given type */
static void
prepare_column_cache(ColumnIOData *column,
					 Oid typid,
					 int32 typmod,
					 MemoryContext mcxt,
					 bool need_scalar)
{
	HeapTuple	tup;
	Form_pg_type type;

	column->typid = typid;
	column->typmod = typmod;

	tup = SearchSysCache1(TYPEOID, ObjectIdGetDatum(typid));
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "cache lookup failed for type %u", typid);

	type = (Form_pg_type) GETSTRUCT(tup);

	if (type->typtype == TYPTYPE_DOMAIN)
	{
		/*
		 * We can move directly to the bottom base type; domain_check() will
		 * take care of checking all constraints for a stack of domains.
		 */
		Oid			base_typid;
		int32		base_typmod = typmod;

		base_typid = getBaseTypeAndTypmod(typid, &base_typmod);
		if (get_typtype(base_typid) == TYPTYPE_COMPOSITE)
		{
			/* domain over composite has its own code path */
			column->typcat = TYPECAT_COMPOSITE_DOMAIN;
			column->io.composite.record_io = NULL;
			column->io.composite.tupdesc = NULL;
			column->io.composite.base_typid = base_typid;
			column->io.composite.base_typmod = base_typmod;
			column->io.composite.domain_info = NULL;
		}
		else
		{
			/* domain over anything else */
			column->typcat = TYPECAT_DOMAIN;
			column->io.domain.base_typid = base_typid;
			column->io.domain.base_typmod = base_typmod;
			column->io.domain.base_io =
				MemoryContextAllocZero(mcxt, sizeof(ColumnIOData));
			column->io.domain.domain_info = NULL;
		}
	}
	else if (type->typtype == TYPTYPE_COMPOSITE || typid == RECORDOID)
	{
		column->typcat = TYPECAT_COMPOSITE;
		column->io.composite.record_io = NULL;
		column->io.composite.tupdesc = NULL;
		column->io.composite.base_typid = typid;
		column->io.composite.base_typmod = typmod;
		column->io.composite.domain_info = NULL;
	}
	else if (IsTrueArrayType(type))
	{
		column->typcat = TYPECAT_ARRAY;
		column->io.array.element_info = MemoryContextAllocZero(mcxt,
															   sizeof(ColumnIOData));
		column->io.array.element_type = type->typelem;
		/* array element typemod stored in attribute's typmod */
		column->io.array.element_typmod = typmod;
	}
	else
	{
		column->typcat = TYPECAT_SCALAR;
		need_scalar = true;
	}

	/* caller can force us to look up scalar_io info even for non-scalars */
	if (need_scalar)
	{
		Oid			typioproc;

		getTypeInputInfo(typid, &typioproc, &column->scalar_io.typioparam);
		fmgr_info_cxt(typioproc, &column->scalar_io.typiofunc, mcxt);
	}

	ReleaseSysCache(tup);
}

/* recursively populate a record field or an array element from a json/jsonb value */
static Datum
populate_record_field(ColumnIOData *col,
					  Oid typid,
					  int32 typmod,
					  const char *colname,
					  MemoryContext mcxt,
					  Datum defaultval,
					  JsValue *jsv,
					  bool *isnull)
{
	TypeCat		typcat;

	check_stack_depth();

	/*
	 * Prepare column metadata cache for the given type.  Force lookup of the
	 * scalar_io data so that the json string hack below will work.
	 */
	if (col->typid != typid || col->typmod != typmod)
		prepare_column_cache(col, typid, typmod, mcxt, true);

	*isnull = JsValueIsNull(jsv);

	typcat = col->typcat;

	/* try to convert json string to a non-scalar type through input function */
	if (JsValueIsString(jsv) &&
		(typcat == TYPECAT_ARRAY ||
		 typcat == TYPECAT_COMPOSITE ||
		 typcat == TYPECAT_COMPOSITE_DOMAIN))
		typcat = TYPECAT_SCALAR;

	/* we must perform domain checks for NULLs, otherwise exit immediately */
	if (*isnull &&
		typcat != TYPECAT_DOMAIN &&
		typcat != TYPECAT_COMPOSITE_DOMAIN)
		return (Datum) 0;

	switch (typcat)
	{
		case TYPECAT_SCALAR:
			return populate_scalar(&col->scalar_io, typid, typmod, jsv);

		case TYPECAT_ARRAY:
			return populate_array(&col->io.array, colname, mcxt, jsv);

		case TYPECAT_COMPOSITE:
		case TYPECAT_COMPOSITE_DOMAIN:
			return populate_composite(&col->io.composite, typid,
									  colname, mcxt,
									  DatumGetPointer(defaultval)
									  ? DatumGetHeapTupleHeader(defaultval)
									  : NULL,
									  jsv, *isnull);

		case TYPECAT_DOMAIN:
			return populate_domain(&col->io.domain, typid, colname, mcxt,
								   jsv, *isnull);

		default:
			elog(ERROR, "unrecognized type category '%c'", typcat);
			return (Datum) 0;
	}
}

static RecordIOData *
allocate_record_info(MemoryContext mcxt, int ncolumns)
{
	RecordIOData *data = (RecordIOData *)
	MemoryContextAlloc(mcxt,
					   offsetof(RecordIOData, columns) +
					   ncolumns * sizeof(ColumnIOData));

	data->record_type = InvalidOid;
	data->record_typmod = 0;
	data->ncolumns = ncolumns;
	MemSet(data->columns, 0, sizeof(ColumnIOData) * ncolumns);

	return data;
}

static bool
JsObjectGetField(JsObject *obj, char *field, JsValue *jsv)
{
	jsv->val.jsonb = !obj->val.jsonb_cont ? NULL :
		JsonFindKeyInObject(obj->val.jsonb_cont, field, strlen(field));

	return jsv->val.jsonb != NULL;
}

/* populate a record tuple from json/jsonb value */
static HeapTupleHeader
populate_record(TupleDesc tupdesc,
				RecordIOData **record_p,
				HeapTupleHeader defaultval,
				MemoryContext mcxt,
				JsObject *obj)
{
	RecordIOData *record = *record_p;
	Datum	   *values;
	bool	   *nulls;
	HeapTuple	res;
	int			ncolumns = tupdesc->natts;
	int			i;

	/*
	 * if the input json is empty, we can only skip the rest if we were passed
	 * in a non-null record, since otherwise there may be issues with domain
	 * nulls.
	 */
	if (defaultval && JsObjectIsEmpty(obj))
		return defaultval;

	/* (re)allocate metadata cache */
	if (record == NULL ||
		record->ncolumns != ncolumns)
		*record_p = record = allocate_record_info(mcxt, ncolumns);

	/* invalidate metadata cache if the record type has changed */
	if (record->record_type != tupdesc->tdtypeid ||
		record->record_typmod != tupdesc->tdtypmod)
	{
		MemSet(record, 0, offsetof(RecordIOData, columns) +
			   ncolumns * sizeof(ColumnIOData));
		record->record_type = tupdesc->tdtypeid;
		record->record_typmod = tupdesc->tdtypmod;
		record->ncolumns = ncolumns;
	}

	values = (Datum *) palloc(ncolumns * sizeof(Datum));
	nulls = (bool *) palloc(ncolumns * sizeof(bool));

	if (defaultval)
	{
		HeapTupleData tuple;

		/* Build a temporary HeapTuple control structure */
		tuple.t_len = HeapTupleHeaderGetDatumLength(defaultval);
		ItemPointerSetInvalid(&(tuple.t_self));
		tuple.t_tableOid = InvalidOid;
		tuple.t_data = defaultval;

		/* Break down the tuple into fields */
		heap_deform_tuple(&tuple, tupdesc, values, nulls);
	}
	else
	{
		for (i = 0; i < ncolumns; ++i)
		{
			values[i] = (Datum) 0;
			nulls[i] = true;
		}
	}

	for (i = 0; i < ncolumns; ++i)
	{
		Form_pg_attribute att = TupleDescAttr(tupdesc, i);
		char	   *colname = NameStr(att->attname);
		JsValue		field = {0};
		bool		found;

		/* Ignore dropped columns in datatype */
		if (att->attisdropped)
		{
			nulls[i] = true;
			continue;
		}

		found = JsObjectGetField(obj, colname, &field);

		/*
		 * we can't just skip here if the key wasn't found since we might have
		 * a domain to deal with. If we were passed in a non-null record
		 * datum, we assume that the existing values are valid (if they're
		 * not, then it's not our fault), but if we were passed in a null,
		 * then every field which we don't populate needs to be run through
		 * the input function just in case it's a domain type.
		 */
		if (defaultval && !found)
			continue;

		values[i] = populate_record_field(&record->columns[i],
										  att->atttypid,
										  att->atttypmod,
										  colname,
										  mcxt,
										  nulls[i] ? (Datum) 0 : values[i],
										  &field,
										  &nulls[i]);
	}

	res = heap_form_tuple(tupdesc, values, nulls);

	pfree(values);
	pfree(nulls);

	return res->t_data;
}

/*
 * Setup for json{b}_populate_record{set}: result type will be same as first
 * argument's type --- unless first argument is "null::record", which we can't
 * extract type info from; we handle that later.
 */
static void
get_record_type_from_argument(FunctionCallInfo fcinfo,
							  const char *funcname,
							  PopulateRecordCache *cache)
{
	cache->argtype = get_fn_expr_argtype(fcinfo->flinfo, 0);
	prepare_column_cache(&cache->c,
						 cache->argtype, -1,
						 cache->fn_mcxt, false);
	if (cache->c.typcat != TYPECAT_COMPOSITE &&
		cache->c.typcat != TYPECAT_COMPOSITE_DOMAIN)
		ereport(ERROR,
				(errcode(ERRCODE_DATATYPE_MISMATCH),
		/* translator: %s is a function name, eg json_to_record */
				 errmsg("first argument of %s must be a row type",
						funcname)));
}

/*
 * Setup for json{b}_to_record{set}: result type is specified by calling
 * query.  We'll also use this code for json{b}_populate_record{set},
 * if we discover that the first argument is a null of type RECORD.
 *
 * Here it is syntactically impossible to specify the target type
 * as domain-over-composite.
 */
static void
get_record_type_from_query(FunctionCallInfo fcinfo,
						   const char *funcname,
						   PopulateRecordCache *cache)
{
	TupleDesc	tupdesc;
	MemoryContext old_cxt;

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
		/* translator: %s is a function name, eg json_to_record */
				 errmsg("could not determine row type for result of %s",
						funcname),
				 errhint("Provide a non-null record argument, "
						 "or call the function in the FROM clause "
						 "using a column definition list.")));

	Assert(tupdesc);
	cache->argtype = tupdesc->tdtypeid;

	/* If we go through this more than once, avoid memory leak */
	if (cache->c.io.composite.tupdesc)
		FreeTupleDesc(cache->c.io.composite.tupdesc);

	/* Save identified tupdesc */
	old_cxt = MemoryContextSwitchTo(cache->fn_mcxt);
	cache->c.io.composite.tupdesc = CreateTupleDescCopy(tupdesc);
	cache->c.io.composite.base_typid = tupdesc->tdtypeid;
	cache->c.io.composite.base_typmod = tupdesc->tdtypmod;
	MemoryContextSwitchTo(old_cxt);
}

/*
 * common worker for json{b}_populate_record() and json{b}_to_record()
 * is_json and have_record_arg identify the specific function
 */
static Datum
populate_record_worker(FunctionCallInfo fcinfo, const char *funcname,
					   bool is_json, bool have_record_arg)
{
	int			json_arg_num = have_record_arg ? 1 : 0;
	JsValue		jsv = {0};
	HeapTupleHeader rec;
	Datum		rettuple;
	JsonbValue	jbv;
	MemoryContext fnmcxt = fcinfo->flinfo->fn_mcxt;
	PopulateRecordCache *cache = fcinfo->flinfo->fn_extra;

	/*
	 * If first time through, identify input/result record type.  Note that
	 * this stanza looks only at fcinfo context, which can't change during the
	 * query; so we may not be able to fully resolve a RECORD input type yet.
	 */
	if (!cache)
	{
		fcinfo->flinfo->fn_extra = cache =
			MemoryContextAllocZero(fnmcxt, sizeof(*cache));
		cache->fn_mcxt = fnmcxt;

		if (have_record_arg)
			get_record_type_from_argument(fcinfo, funcname, cache);
		else
			get_record_type_from_query(fcinfo, funcname, cache);
	}

	/* Collect record arg if we have one */
	if (!have_record_arg)
		rec = NULL;				/* it's json{b}_to_record() */
	else if (!PG_ARGISNULL(0))
	{
		rec = PG_GETARG_HEAPTUPLEHEADER(0);

		/*
		 * When declared arg type is RECORD, identify actual record type from
		 * the tuple itself.
		 */
		if (cache->argtype == RECORDOID)
		{
			cache->c.io.composite.base_typid = HeapTupleHeaderGetTypeId(rec);
			cache->c.io.composite.base_typmod = HeapTupleHeaderGetTypMod(rec);
		}
	}
	else
	{
		rec = NULL;

		/*
		 * When declared arg type is RECORD, identify actual record type from
		 * calling query, or fail if we can't.
		 */
		if (cache->argtype == RECORDOID)
		{
			get_record_type_from_query(fcinfo, funcname, cache);
			/* This can't change argtype, which is important for next time */
			Assert(cache->argtype == RECORDOID);
		}
	}

	/* If no JSON argument, just return the record (if any) unchanged */
	if (PG_ARGISNULL(json_arg_num))
	{
		if (rec)
			PG_RETURN_POINTER(rec);
		else
			PG_RETURN_NULL();
	}

	{
		Jsonb	   *jb = is_json ?
			PG_GETARG_JSONT_P(json_arg_num) :
			PG_GETARG_JSONB_P(json_arg_num);

		jsv.val.jsonb = &jbv;

		/* fill binary jsonb value pointing to jb */
		JsonValueInitBinary(&jbv, JsonRoot(jb));
	}

	rettuple = populate_composite(&cache->c.io.composite, cache->argtype,
								  NULL, fnmcxt, rec, &jsv, false);

	PG_RETURN_DATUM(rettuple);
}

/*
 * SQL function json_populate_recordset
 *
 * set fields in a set of records from the argument json,
 * which must be an array of objects.
 *
 * similar to json_populate_record, but the tuple-building code
 * is pushed down into the semantic action handlers so it's done
 * per object in the array.
 */
Datum
jsonb_populate_recordset(PG_FUNCTION_ARGS)
{
	return populate_recordset_worker(fcinfo, "jsonb_populate_recordset",
									 false, true);
}

Datum
jsonb_to_recordset(PG_FUNCTION_ARGS)
{
	return populate_recordset_worker(fcinfo, "jsonb_to_recordset",
									 false, false);
}

Datum
json_populate_recordset(PG_FUNCTION_ARGS)
{
	return populate_recordset_worker(fcinfo, "json_populate_recordset",
									 true, true);
}

Datum
json_to_recordset(PG_FUNCTION_ARGS)
{
	return populate_recordset_worker(fcinfo, "json_to_recordset",
									 true, false);
}

static void
populate_recordset_record(PopulateRecordsetState *state, JsObject *obj)
{
	PopulateRecordCache *cache = state->cache;
	HeapTupleHeader tuphead;
	HeapTupleData tuple;

	/* acquire/update cached tuple descriptor */
	update_cached_tupdesc(&cache->c.io.composite, cache->fn_mcxt);

	/* replace record fields from json */
	tuphead = populate_record(cache->c.io.composite.tupdesc,
							  &cache->c.io.composite.record_io,
							  state->rec,
							  cache->fn_mcxt,
							  obj);

	/* if it's domain over composite, check domain constraints */
	if (cache->c.typcat == TYPECAT_COMPOSITE_DOMAIN)
		domain_check(HeapTupleHeaderGetDatum(tuphead), false,
					 cache->argtype,
					 &cache->c.io.composite.domain_info,
					 cache->fn_mcxt);

	/* ok, save into tuplestore */
	tuple.t_len = HeapTupleHeaderGetDatumLength(tuphead);
	ItemPointerSetInvalid(&(tuple.t_self));
	tuple.t_tableOid = InvalidOid;
	tuple.t_data = tuphead;

	tuplestore_puttuple(state->tuple_store, &tuple);
}

/*
 * common worker for json{b}_populate_recordset() and json{b}_to_recordset()
 * is_json and have_record_arg identify the specific function
 */
static Datum
populate_recordset_worker(FunctionCallInfo fcinfo, const char *funcname,
						  bool is_json, bool have_record_arg)
{
	int			json_arg_num = have_record_arg ? 1 : 0;
	ReturnSetInfo *rsi;
	MemoryContext old_cxt;
	HeapTupleHeader rec;
	PopulateRecordCache *cache = fcinfo->flinfo->fn_extra;
	PopulateRecordsetState *state;

	rsi = (ReturnSetInfo *) fcinfo->resultinfo;

	if (!rsi || !IsA(rsi, ReturnSetInfo) ||
		(rsi->allowedModes & SFRM_Materialize) == 0)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("set-valued function called in context that "
						"cannot accept a set")));

	rsi->returnMode = SFRM_Materialize;

	/*
	 * If first time through, identify input/result record type.  Note that
	 * this stanza looks only at fcinfo context, which can't change during the
	 * query; so we may not be able to fully resolve a RECORD input type yet.
	 */
	if (!cache)
	{
		fcinfo->flinfo->fn_extra = cache =
			MemoryContextAllocZero(fcinfo->flinfo->fn_mcxt, sizeof(*cache));
		cache->fn_mcxt = fcinfo->flinfo->fn_mcxt;

		if (have_record_arg)
			get_record_type_from_argument(fcinfo, funcname, cache);
		else
			get_record_type_from_query(fcinfo, funcname, cache);
	}

	/* Collect record arg if we have one */
	if (!have_record_arg)
		rec = NULL;				/* it's json{b}_to_recordset() */
	else if (!PG_ARGISNULL(0))
	{
		rec = PG_GETARG_HEAPTUPLEHEADER(0);

		/*
		 * When declared arg type is RECORD, identify actual record type from
		 * the tuple itself.
		 */
		if (cache->argtype == RECORDOID)
		{
			cache->c.io.composite.base_typid = HeapTupleHeaderGetTypeId(rec);
			cache->c.io.composite.base_typmod = HeapTupleHeaderGetTypMod(rec);
		}
	}
	else
	{
		rec = NULL;

		/*
		 * When declared arg type is RECORD, identify actual record type from
		 * calling query, or fail if we can't.
		 */
		if (cache->argtype == RECORDOID)
		{
			get_record_type_from_query(fcinfo, funcname, cache);
			/* This can't change argtype, which is important for next time */
			Assert(cache->argtype == RECORDOID);
		}
	}

	/* if the json is null send back an empty set */
	if (PG_ARGISNULL(json_arg_num))
		PG_RETURN_NULL();

	/*
	 * Forcibly update the cached tupdesc, to ensure we have the right tupdesc
	 * to return even if the JSON contains no rows.
	 */
	update_cached_tupdesc(&cache->c.io.composite, cache->fn_mcxt);

	state = palloc0(sizeof(PopulateRecordsetState));

	/* make tuplestore in a sufficiently long-lived memory context */
	old_cxt = MemoryContextSwitchTo(rsi->econtext->ecxt_per_query_memory);
	state->tuple_store = tuplestore_begin_heap(rsi->allowedModes &
											   SFRM_Materialize_Random,
											   false, work_mem);
	MemoryContextSwitchTo(old_cxt);

	state->function_name = funcname;
	state->cache = cache;
	state->rec = rec;

	{
		Jsonb	   *jb = is_json ?
			PG_GETARG_JSONT_P(json_arg_num) :
			PG_GETARG_JSONB_P(json_arg_num);
		JsonbIterator *it;
		JsonbValue	v;
		bool		skipNested = false;
		JsonbIteratorToken r;

		if (JB_ROOT_IS_SCALAR(jb) || !JB_ROOT_IS_ARRAY(jb))
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("cannot call %s on a non-array",
							funcname)));

		it = JsonbIteratorInit(JsonbRoot(jb));

		while ((r = JsonbIteratorNext(&it, &v, skipNested)) != WJB_DONE)
		{
			skipNested = true;

			if (r == WJB_ELEM)
			{
				JsObject	obj;

				if (v.type != jbvBinary ||
					!JsonContainerIsObject(v.val.binary.data))
					ereport(ERROR,
							(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
							 errmsg("argument of %s must be an array of objects",
									funcname)));

				obj.val.jsonb_cont = v.val.binary.data;

				populate_recordset_record(state, &obj);
			}
		}
	}

	/*
	 * Note: we must copy the cached tupdesc because the executor will free
	 * the passed-back setDesc, but we want to hang onto the cache in case
	 * we're called again in the same query.
	 */
	rsi->setResult = state->tuple_store;
	rsi->setDesc = CreateTupleDescCopy(cache->c.io.composite.tupdesc);

	PG_RETURN_NULL();
}

/*
 * Semantic actions for json_strip_nulls.
 *
 * Simply repeat the input on the output unless we encounter
 * a null object field. State for this is set when the field
 * is started and reset when the scalar action (which must be next)
 * is called.
 */

static void
sn_object_start(void *state)
{
	StripnullState *_state = (StripnullState *) state;

	appendStringInfoCharMacro(_state->strval, '{');
}

static void
sn_object_end(void *state)
{
	StripnullState *_state = (StripnullState *) state;

	appendStringInfoCharMacro(_state->strval, '}');
}

static void
sn_array_start(void *state)
{
	StripnullState *_state = (StripnullState *) state;

	appendStringInfoCharMacro(_state->strval, '[');
}

static void
sn_array_end(void *state)
{
	StripnullState *_state = (StripnullState *) state;

	appendStringInfoCharMacro(_state->strval, ']');
}

static void
sn_object_field_start(void *state, char *fname, bool isnull)
{
	StripnullState *_state = (StripnullState *) state;

	if (isnull)
	{
		/*
		 * The next thing must be a scalar or isnull couldn't be true, so
		 * there is no danger of this state being carried down into a nested
		 * object or array. The flag will be reset in the scalar action.
		 */
		_state->skip_next_null = true;
		return;
	}

	if (_state->strval->data[_state->strval->len - 1] != '{')
		appendStringInfoCharMacro(_state->strval, ',');

	/*
	 * Unfortunately we don't have the quoted and escaped string any more, so
	 * we have to re-escape it.
	 */
	escape_json(_state->strval, fname);

	appendStringInfoCharMacro(_state->strval, ':');
}

static void
sn_array_element_start(void *state, bool isnull)
{
	StripnullState *_state = (StripnullState *) state;

	if (_state->strval->data[_state->strval->len - 1] != '[')
		appendStringInfoCharMacro(_state->strval, ',');
}

static void
sn_scalar(void *state, char *token, JsonTokenType tokentype)
{
	StripnullState *_state = (StripnullState *) state;

	if (_state->skip_next_null)
	{
		Assert(tokentype == JSON_TOKEN_NULL);
		_state->skip_next_null = false;
		return;
	}

	if (tokentype == JSON_TOKEN_STRING)
		escape_json(_state->strval, token);
	else
		appendStringInfoString(_state->strval, token);
}

/*
 * SQL function json_strip_nulls(json) -> json
 */
Datum
json_strip_nulls(PG_FUNCTION_ARGS)
{
	Json	   *json = PG_GETARG_JSONT_P(0);
	JsonContainer *jsc = JsonRoot(json);
	StripnullState *state;
	JsonLexContext *lex;
	JsonSemAction *sem;

	if (jsc->ops != &jsontContainerOps)
		return jsonb_strip_nulls_internal(json);

	lex = makeJsonLexContextCstringLen(JsonContainerDataPtr(jsc), jsc->len,
									   GetDatabaseEncoding(), true);

	state = palloc0(sizeof(StripnullState));
	sem = palloc0(sizeof(JsonSemAction));

	state->strval = makeStringInfo();
	state->skip_next_null = false;
	state->lex = lex;

	sem->semstate = (void *) state;
	sem->object_start = sn_object_start;
	sem->object_end = sn_object_end;
	sem->array_start = sn_array_start;
	sem->array_end = sn_array_end;
	sem->scalar = sn_scalar;
	sem->array_element_start = sn_array_element_start;
	sem->object_field_start = sn_object_field_start;

	pg_parse_json_or_ereport(lex, sem);

	PG_RETURN_TEXT_P(cstring_to_text_with_len(state->strval->data,
											  state->strval->len));

}

/*
 * SQL function jsonb_strip_nulls(jsonb) -> jsonb
 */
Datum
jsonb_strip_nulls(PG_FUNCTION_ARGS)
{
	return jsonb_strip_nulls_internal(PG_GETARG_JSONB_P(0));
}

static Datum
jsonb_strip_nulls_internal(Jsonb *jb)
{
	JsonbIterator *it;
	JsonbParseState *parseState = NULL;
	JsonbValue *res = NULL;
	JsonbValue	v,
				k;
	JsonbIteratorToken type;
	bool		last_was_key = false;

	if (JB_ROOT_IS_SCALAR(jb))
		PG_RETURN_JSONB_P(jb);

	it = JsonbIteratorInit(JsonbRoot(jb));

	while ((type = JsonbIteratorNext(&it, &v, false)) != WJB_DONE)
	{
		Assert(!(type == WJB_KEY && last_was_key));

		if (type == WJB_KEY)
		{
			/* stash the key until we know if it has a null value */
			k = v;
			last_was_key = true;
			continue;
		}

		if (last_was_key)
		{
			/* if the last element was a key this one can't be */
			last_was_key = false;

			/* skip this field if value is null */
			if (type == WJB_VALUE && v.type == jbvNull)
				continue;

			/* otherwise, do a delayed push of the key */
			(void) pushJsonbValue(&parseState, WJB_KEY, &k);
		}

		if (type == WJB_VALUE || type == WJB_ELEM)
			res = pushJsonbValue(&parseState, type, &v);
		else
			res = pushJsonbValue(&parseState, type, NULL);
	}

	Assert(res != NULL);

	PG_RETURN_JSONB_P(JsonbValueToJsonb(res));
}

/*
 * SQL function jsonb_pretty (jsonb)
 *
 * Pretty-printed text for the jsonb
 */
static text *
json_pretty_internal(Json *js)
{
	StringInfo	str = makeStringInfo();

	JsonbToCStringIndent(str, JsonRoot(js), JsonGetSize(js));

	return cstring_to_text_with_len(str->data, str->len);
}

Datum
jsonb_pretty(PG_FUNCTION_ARGS)
{
	PG_RETURN_TEXT_P(json_pretty_internal(PG_GETARG_JSONB_P(0)));
}

Datum
json_pretty(PG_FUNCTION_ARGS)
{
	PG_RETURN_TEXT_P(json_pretty_internal(PG_GETARG_JSONT_P(0)));
}

static text *
json_canonical_internal(Json *js)
{
	StringInfo	str = makeStringInfo();

	JsonbToCStringCanonical(str, JsonRoot(js), JsonGetSize(js));

	return cstring_to_text_with_len(str->data, str->len);
}

Datum
jsonb_canonical(PG_FUNCTION_ARGS)
{
	PG_RETURN_TEXT_P(json_canonical_internal(PG_GETARG_JSONB_P(0)));
}

Datum
json_canonical(PG_FUNCTION_ARGS)
{
	PG_RETURN_TEXT_P(json_canonical_internal(PG_GETARG_JSONT_P(0)));
}

static Json *
json_concat_internal(Json *jb1, Json *jb2, bool is_jsonb)
{
	JsonbParseState *state = NULL;
	JsonbValue *res;
	JsonbIterator *it1,
			   *it2;

	/*
	 * If one of the jsonb is empty, just return the other if it's not scalar
	 * and both are of the same kind.  If it's a scalar or they are of
	 * different kinds we need to perform the concatenation even if one is
	 * empty.
	 */
	if (JB_ROOT_IS_OBJECT(jb1) == JB_ROOT_IS_OBJECT(jb2))
	{
		if (JB_ROOT_COUNT(jb1) == 0 && !JB_ROOT_IS_SCALAR(jb2))
			return jb2;
		else if (JB_ROOT_COUNT(jb2) == 0 && !JB_ROOT_IS_SCALAR(jb1))
			return jb1;
	}

	it1 = JsonbIteratorInit(JsonbRoot(jb1));
	it2 = JsonbIteratorInit(JsonbRoot(jb2));

	res = IteratorConcat(&it1, &it2, &state, is_jsonb);

	Assert(res != NULL);

	return JsonbValueToJsonb(res);
}

/*
 * SQL functions json[b]_concat (json[b], json[b])
 *
 * function for || operator
 */
Datum
jsonb_concat(PG_FUNCTION_ARGS)
{
	PG_RETURN_JSONB_P(json_concat_internal(PG_GETARG_JSONB_P(0),
										   PG_GETARG_JSONB_P(1),
										   true));
}

Datum
json_concat(PG_FUNCTION_ARGS)
{
	PG_RETURN_JSONT_P(json_concat_internal(PG_GETARG_JSONT_P(0),
										   PG_GETARG_JSONT_P(1),
										   false));
}

static Json *
json_delete_internal(Json *in, text *key)
{
	char	   *keyptr = VARDATA_ANY(key);
	int			keylen = VARSIZE_ANY_EXHDR(key);
	JsonbParseState *state = NULL;
	JsonbIterator *it;
	JsonbValue	v,
			   *res = NULL;
	bool		skipNested = false;
	JsonbIteratorToken r;

	if (JB_ROOT_IS_SCALAR(in))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("cannot delete from scalar")));

	if (JB_ROOT_COUNT(in) == 0)
		return in;

	it = JsonbIteratorInit(JsonbRoot(in));

	while ((r = JsonbIteratorNext(&it, &v, skipNested)) != WJB_DONE)
	{
		skipNested = true;

		if ((r == WJB_ELEM || r == WJB_KEY) &&
			(v.type == jbvString && keylen == v.val.string.len &&
			 memcmp(keyptr, v.val.string.val, keylen) == 0))
		{
			/* skip corresponding value as well */
			if (r == WJB_KEY)
				(void) JsonbIteratorNext(&it, &v, true);

			continue;
		}

		res = pushJsonbValueExt(&state, r, r < WJB_BEGIN_ARRAY ? &v : NULL, false);
	}

	Assert(res != NULL);

	return JsonbValueToJsonb(res);
}

/*
 * SQL functions json[b]_delete (json[b], text)
 *
 * return a copy of the jsonb with the indicated item
 * removed.
 */
Datum
jsonb_delete(PG_FUNCTION_ARGS)
{
	PG_RETURN_JSONB_P(json_delete_internal(PG_GETARG_JSONB_P(0),
										   PG_GETARG_TEXT_PP(1)));
}

Datum
json_delete(PG_FUNCTION_ARGS)
{
	PG_RETURN_JSONT_P(json_delete_internal(PG_GETARG_JSONT_P(0),
										   PG_GETARG_TEXT_PP(1)));
}

static Json *
json_delete_array_internal(Json *in, ArrayType *keys)
{
	Datum	   *keys_elems;
	bool	   *keys_nulls;
	int			keys_len;
	JsonbParseState *state = NULL;
	JsonbIterator *it;
	JsonbValue	v,
			   *res = NULL;
	bool		skipNested = false;
	JsonbIteratorToken r;

	if (ARR_NDIM(keys) > 1)
		ereport(ERROR,
				(errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR),
				 errmsg("wrong number of array subscripts")));

	if (JB_ROOT_IS_SCALAR(in))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("cannot delete from scalar")));

	if (JB_ROOT_COUNT(in) == 0)
		return in;

	deconstruct_array(keys, TEXTOID, -1, false, TYPALIGN_INT,
					  &keys_elems, &keys_nulls, &keys_len);

	if (keys_len == 0)
		return in;

	it = JsonbIteratorInit(JsonbRoot(in));

	while ((r = JsonbIteratorNext(&it, &v, skipNested)) != WJB_DONE)
	{
		skipNested = true;

		if ((r == WJB_ELEM || r == WJB_KEY) && v.type == jbvString)
		{
			int			i;
			bool		found = false;

			for (i = 0; i < keys_len; i++)
			{
				char	   *keyptr;
				int			keylen;

				if (keys_nulls[i])
					continue;

				keyptr = VARDATA_ANY(keys_elems[i]);
				keylen = VARSIZE_ANY_EXHDR(keys_elems[i]);
				if (keylen == v.val.string.len &&
					memcmp(keyptr, v.val.string.val, keylen) == 0)
				{
					found = true;
					break;
				}
			}
			if (found)
			{
				/* skip corresponding value as well */
				if (r == WJB_KEY)
					(void) JsonbIteratorNext(&it, &v, true);

				continue;
			}
		}

		res = pushJsonbValueExt(&state, r, r < WJB_BEGIN_ARRAY ? &v : NULL, false);
	}

	Assert(res != NULL);

	return JsonbValueToJsonb(res);
}


/*
 * SQL functions json[b]_delete (json[b], variadic text[])
 *
 * return a copy of the json[b] with the indicated items
 * removed.
 */
Datum
jsonb_delete_array(PG_FUNCTION_ARGS)
{
	PG_RETURN_JSONB_P(json_delete_array_internal(PG_GETARG_JSONB_P(0),
												 PG_GETARG_ARRAYTYPE_P(1)));
}

Datum
json_delete_array(PG_FUNCTION_ARGS)
{
	PG_RETURN_JSONT_P(json_delete_array_internal(PG_GETARG_JSONT_P(0),
												 PG_GETARG_ARRAYTYPE_P(1)));
}

static Json *
json_delete_idx_internal(Json *in, int idx)
{
	JsonbParseState *state = NULL;
	JsonbIterator *it;
	uint32		i = 0,
				n;
	JsonbValue	v,
			   *res = NULL;
	JsonbIteratorToken r;

	if (JB_ROOT_IS_SCALAR(in))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("cannot delete from scalar")));

	if (JB_ROOT_IS_OBJECT(in))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("cannot delete from object using integer index")));

	if (JB_ROOT_COUNT(in) == 0)
		return in;

	it = JsonbIteratorInit(JsonbRoot(in));

	r = JsonbIteratorNext(&it, &v, false);
	Assert(r == WJB_BEGIN_ARRAY);
	n = v.val.array.nElems;

	if (v.val.array.nElems >= 0)
	{
		if (idx < 0)
		{
			if (-idx > n)
				idx = n;
			else
				idx = n + idx;
		}

		if (idx >= n)
			return in;
	}

	pushJsonbValue(&state, r, NULL);

	while ((r = JsonbIteratorNext(&it, &v, true)) != WJB_DONE)
	{
		if (r == WJB_ELEM)
		{
			if (i++ == idx)
				continue;
		}

		res = pushJsonbValueExt(&state, r, r < WJB_BEGIN_ARRAY ? &v : NULL, false);
	}

	Assert(res != NULL);

	if (idx < 0 && -idx <= res->val.array.nElems)
	{
		idx = res->val.array.nElems + idx;
		res->val.array.nElems--;
		memmove(&res->val.array.elems[idx],
				&res->val.array.elems[idx + 1],
				sizeof(JsonValue) * (res->val.array.nElems - idx));
	}

	return JsonbValueToJsonb(res);
}


/*
 * SQL functions json[b]_delete (json[b], int)
 *
 * return a copy of the json[b] with the indicated item
 * removed. Negative int means count back from the
 * end of the items.
 */
Datum
jsonb_delete_idx(PG_FUNCTION_ARGS)
{
	PG_RETURN_JSONB_P(json_delete_idx_internal(PG_GETARG_JSONB_P(0),
											   PG_GETARG_INT32(1)));
}

Datum
json_delete_idx(PG_FUNCTION_ARGS)
{
	PG_RETURN_JSONT_P(json_delete_idx_internal(PG_GETARG_JSONT_P(0),
											   PG_GETARG_INT32(1)));
}

static Json *
json_set_internal(Json *in, ArrayType *path, Json *newjsonb, bool create)
{
	JsonbValue	newval;
	JsonbValue *res = NULL;
	Datum	   *path_elems;
	bool	   *path_nulls;
	int			path_len;
	JsonbIterator *it;
	JsonbParseState *st = NULL;

	JsonToJsonValue(newjsonb, &newval);

	if (ARR_NDIM(path) > 1)
		ereport(ERROR,
				(errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR),
				 errmsg("wrong number of array subscripts")));

	if (JB_ROOT_IS_SCALAR(in))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("cannot set path in scalar")));

	if (JB_ROOT_COUNT(in) == 0 && !create)
		return in;

	deconstruct_array(path, TEXTOID, -1, false, TYPALIGN_INT,
					  &path_elems, &path_nulls, &path_len);

	if (path_len == 0)
		return in;

	it = JsonbIteratorInit(JsonbRoot(in));

	res = setPath(&it, path_elems, path_nulls, path_len, &st,
				  0, &newval, create ? JB_PATH_CREATE : JB_PATH_REPLACE);

	Assert(res != NULL);

	return JsonbValueToJsonb(res);
}

/*
 * SQL functions json[b]_set(json[b], text[], json[b], boolean)
 */
Datum
jsonb_set(PG_FUNCTION_ARGS)
{
	PG_RETURN_JSONB_P(json_set_internal(PG_GETARG_JSONB_P(0),
										PG_GETARG_ARRAYTYPE_P(1),
										PG_GETARG_JSONB_P(2),
										PG_GETARG_BOOL(3)));
}

Datum
json_set(PG_FUNCTION_ARGS)
{
	PG_RETURN_JSONT_P(json_set_internal(PG_GETARG_JSONT_P(0),
										PG_GETARG_ARRAYTYPE_P(1),
										PG_GETARG_JSONT_P(2),
										PG_GETARG_BOOL(3)));
}

static Datum
json_set_lax_internal(FunctionCallInfo fcinfo, bool is_jsonb)
{
	/* Jsonb	   *in = PG_GETARG_JSONB_P(0); */
	/* ArrayType  *path = PG_GETARG_ARRAYTYPE_P(1); */
	/* Jsonb	  *newval = PG_GETARG_JSONB_P(2); */
	/* bool		create = PG_GETARG_BOOL(3); */
	text	   *handle_null;
	char	   *handle_val;

	if (PG_ARGISNULL(0) || PG_ARGISNULL(1) || PG_ARGISNULL(3))
		PG_RETURN_NULL();

	/* could happen if they pass in an explicit NULL */
	if (PG_ARGISNULL(4))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("null_value_treatment must be \"delete_key\", \"return_target\", \"use_json_null\", or \"raise_exception\"")));

	/* if the new value isn't an SQL NULL just call jsonb_set */
	if (!PG_ARGISNULL(2))
		return (is_jsonb ? jsonb_set : json_set)(fcinfo);

	handle_null = PG_GETARG_TEXT_P(4);
	handle_val = text_to_cstring(handle_null);

	if (strcmp(handle_val, "raise_exception") == 0)
	{
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("JSON value must not be null"),
				 errdetail("Exception was raised because null_value_treatment is \"raise_exception\"."),
				 errhint("To avoid, either change the null_value_treatment argument or ensure that an SQL NULL is not passed.")));
		return (Datum) 0;		/* silence stupider compilers */
	}
	else if (strcmp(handle_val, "use_json_null") == 0)
	{
		Datum		newval;

		newval = DirectFunctionCall1(is_jsonb ? jsonb_in : json_in,
									 CStringGetDatum("null"));

		fcinfo->args[2].value = newval;
		fcinfo->args[2].isnull = false;
		return (is_jsonb ? jsonb_set : json_set)(fcinfo);
	}
	else if (strcmp(handle_val, "delete_key") == 0)
	{
		return (is_jsonb ? jsonb_delete_path : json_delete_path)(fcinfo);
	}
	else if (strcmp(handle_val, "return_target") == 0)
	{
		PG_RETURN_DATUM(PG_GETARG_DATUM(0));
	}
	else
	{
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("null_value_treatment must be \"delete_key\", \"return_target\", \"use_json_null\", or \"raise_exception\"")));
		return (Datum) 0;		/* silence stupider compilers */
	}
}

/*
 * SQL functions jsonb_set_lax(json[b], text[], json[b], boolean, text)
 */
Datum
jsonb_set_lax(PG_FUNCTION_ARGS)
{
	return json_set_lax_internal(fcinfo, true);
}

Datum
json_set_lax(PG_FUNCTION_ARGS)
{
	return json_set_lax_internal(fcinfo, false);
}

static Json *
json_delete_path_internal(Json *in, ArrayType *path)
{
	JsonbValue *res = NULL;
	Datum	   *path_elems;
	bool	   *path_nulls;
	int			path_len;
	JsonbIterator *it;
	JsonbParseState *st = NULL;

	if (ARR_NDIM(path) > 1)
		ereport(ERROR,
				(errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR),
				 errmsg("wrong number of array subscripts")));

	if (JB_ROOT_IS_SCALAR(in))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("cannot delete path in scalar")));

	if (JB_ROOT_COUNT(in) == 0)
		return in;

	deconstruct_array(path, TEXTOID, -1, false, TYPALIGN_INT,
					  &path_elems, &path_nulls, &path_len);

	if (path_len == 0)
		return in;

	it = JsonbIteratorInit(JsonbRoot(in));

	res = setPath(&it, path_elems, path_nulls, path_len, &st,
				  0, NULL, JB_PATH_DELETE);

	Assert(res != NULL);

	return JsonbValueToJsonb(res);
}

/*
 * SQL functions json[b]_delete_path(json[b], text[])
 */
Datum
jsonb_delete_path(PG_FUNCTION_ARGS)
{
	PG_RETURN_JSONB_P(json_delete_path_internal(PG_GETARG_JSONB_P(0),
												PG_GETARG_ARRAYTYPE_P(1)));
}

Datum
json_delete_path(PG_FUNCTION_ARGS)
{
	PG_RETURN_JSONT_P(json_delete_path_internal(PG_GETARG_JSONT_P(0),
												PG_GETARG_ARRAYTYPE_P(1)));
}

static Json *
json_insert_internal(Json *in, ArrayType *path, Jsonb *newjsonb, bool after)
{
	JsonbValue	newval;
	JsonbValue *res = NULL;
	Datum	   *path_elems;
	bool	   *path_nulls;
	int			path_len;
	JsonbIterator *it;
	JsonbParseState *st = NULL;

	JsonToJsonValue(newjsonb, &newval);

	if (ARR_NDIM(path) > 1)
		ereport(ERROR,
				(errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR),
				 errmsg("wrong number of array subscripts")));

	if (JB_ROOT_IS_SCALAR(in))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("cannot set path in scalar")));

	deconstruct_array(path, TEXTOID, -1, false, TYPALIGN_INT,
					  &path_elems, &path_nulls, &path_len);

	if (path_len == 0)
		return in;

	it = JsonbIteratorInit(JsonbRoot(in));

	res = setPath(&it, path_elems, path_nulls, path_len, &st, 0, &newval,
				  after ? JB_PATH_INSERT_AFTER : JB_PATH_INSERT_BEFORE);

	Assert(res != NULL);

	return JsonbValueToJsonb(res);
}

/*
 * SQL functions json[b]_insert(json[b], text[], json[b], boolean)
 */
Datum
jsonb_insert(PG_FUNCTION_ARGS)
{
	PG_RETURN_JSONB_P(json_insert_internal(PG_GETARG_JSONB_P(0),
										   PG_GETARG_ARRAYTYPE_P(1),
										   PG_GETARG_JSONB_P(2),
										   PG_GETARG_BOOL(3)));
}

Datum
json_insert(PG_FUNCTION_ARGS)
{
	PG_RETURN_JSONT_P(json_insert_internal(PG_GETARG_JSONT_P(0),
										   PG_GETARG_ARRAYTYPE_P(1),
										   PG_GETARG_JSONT_P(2),
										   PG_GETARG_BOOL(3)));
}

/*
 * Iterate over all jsonb objects and merge them into one.
 * The logic of this function copied from the same hstore function,
 * except the case, when it1 & it2 represents jbvObject.
 * In that case we just append the content of it2 to it1 without any
 * verifications.
 */
static JsonbValue *
IteratorConcat(JsonbIterator **it1, JsonbIterator **it2,
			   JsonbParseState **state, bool is_jsonb)
{
	JsonbValue	v1,
				v2,
			   *res = NULL;
	JsonbIteratorToken r1,
				r2,
				rk1,
				rk2;

	rk1 = JsonbIteratorNext(it1, &v1, false);
	rk2 = JsonbIteratorNext(it2, &v2, false);

	/*
	 * JsonbIteratorNext reports raw scalars as if they were single-element
	 * arrays; hence we only need consider "object" and "array" cases here.
	 */
	if (rk1 == WJB_BEGIN_OBJECT && rk2 == WJB_BEGIN_OBJECT)
	{
		/*
		 * Both inputs are objects.
		 *
		 * Append all the tokens from v1 to res, except last WJB_END_OBJECT
		 * (because res will not be finished yet).
		 */
		pushJsonbValue(state, rk1, NULL);
		while ((r1 = JsonbIteratorNext(it1, &v1, true)) != WJB_END_OBJECT)
			pushJsonbValueExt(state, r1, &v1, false);

		/*
		 * Append all the tokens from v2 to res, including last WJB_END_OBJECT
		 * (the concatenation will be completed).  Any duplicate keys will
		 * automatically override the value from the first object.
		 */
		while ((r2 = JsonbIteratorNext(it2, &v2, true)) != WJB_DONE)
			res = pushJsonbValueExt(state, r2, r2 != WJB_END_OBJECT ? &v2 : NULL, false);
	}
	else if (rk1 == WJB_BEGIN_ARRAY && rk2 == WJB_BEGIN_ARRAY)
	{
		/*
		 * Both inputs are arrays.
		 */
		pushJsonbValue(state, rk1, NULL);

		while ((r1 = JsonbIteratorNext(it1, &v1, true)) != WJB_END_ARRAY)
		{
			Assert(r1 == WJB_ELEM);
			pushJsonbValueExt(state, r1, &v1, false);
		}

		while ((r2 = JsonbIteratorNext(it2, &v2, true)) != WJB_END_ARRAY)
		{
			Assert(r2 == WJB_ELEM);
			pushJsonbValueExt(state, WJB_ELEM, &v2, false);
		}

		res = pushJsonbValue(state, WJB_END_ARRAY, NULL /* signal to sort */ );
	}
	else if (rk1 == WJB_BEGIN_OBJECT)
	{
		/*
		 * We have object || array.
		 */
		Assert(rk2 == WJB_BEGIN_ARRAY);

		pushJsonbValue(state, WJB_BEGIN_ARRAY, NULL);

		pushJsonbValue(state, WJB_BEGIN_OBJECT, NULL);
		while ((r1 = JsonbIteratorNext(it1, &v1, true)) != WJB_DONE)
			pushJsonbValueExt(state, r1, r1 != WJB_END_OBJECT ? &v1 : NULL, false);

		while ((r2 = JsonbIteratorNext(it2, &v2, true)) != WJB_DONE)
			res = pushJsonbValueExt(state, r2, r2 != WJB_END_ARRAY ? &v2 : NULL, false);
	}
	else
	{
		/*
		 * We have array || object.
		 */
		Assert(rk1 == WJB_BEGIN_ARRAY);
		Assert(rk2 == WJB_BEGIN_OBJECT);

		pushJsonbValue(state, WJB_BEGIN_ARRAY, NULL);

		while ((r1 = JsonbIteratorNext(it1, &v1, true)) != WJB_END_ARRAY)
			pushJsonbValueExt(state, r1, &v1, false);

		pushJsonbValue(state, WJB_BEGIN_OBJECT, NULL);
		while ((r2 = JsonbIteratorNext(it2, &v2, true)) != WJB_DONE)
			pushJsonbValueExt(state, r2, r2 != WJB_END_OBJECT ? &v2 : NULL, false);

		res = pushJsonbValue(state, WJB_END_ARRAY, NULL);
	}

	return res;
}

/*
 * Do most of the heavy work for jsonb_set/jsonb_insert
 *
 * If JB_PATH_DELETE bit is set in op_type, the element is to be removed.
 *
 * If any bit mentioned in JB_PATH_CREATE_OR_INSERT is set in op_type,
 * we create the new value if the key or array index does not exist.
 *
 * Bits JB_PATH_INSERT_BEFORE and JB_PATH_INSERT_AFTER in op_type
 * behave as JB_PATH_CREATE if new value is inserted in JsonbObject.
 *
 * If JB_PATH_FILL_GAPS bit is set, this will change an assignment logic in
 * case if target is an array. The assignment index will not be restricted by
 * number of elements in the array, and if there are any empty slots between
 * last element of the array and a new one they will be filled with nulls. If
 * the index is negative, it still will be considered an an index from the end
 * of the array. Of a part of the path is not present and this part is more
 * than just one last element, this flag will instruct to create the whole
 * chain of corresponding objects and insert the value.
 *
 * JB_PATH_CONSISTENT_POSITION for an array indicates that the called wants to
 * keep values with fixed indices. Indices for existing elements could be
 * changed (shifted forward) in case if the array is prepended with a new value
 * and a negative index out of the range, so this behavior will be prevented
 * and return an error.
 *
 * All path elements before the last must already exist
 * whatever bits in op_type are set, or nothing is done.
 */
static JsonbValue *
setPath(JsonbIterator **it, Datum *path_elems,
		bool *path_nulls, int path_len,
		JsonbParseState **st, int level, JsonbValue *newval, int op_type)
{
	JsonbValue	v;
	JsonbIteratorToken r;
	JsonbValue *res;

	check_stack_depth();

	if (path_nulls[level])
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("path element at position %d is null",
						level + 1)));

	r = JsonbIteratorNext(it, &v, false);

	switch (r)
	{
		case WJB_BEGIN_ARRAY:

			/*
			 * If instructed complain about attempts to replace whithin a raw
			 * scalar value. This happens even when current level is equal to
			 * path_len, because the last path key should also correspond to
			 * an object or an array, not raw scalar.
			 */
			if ((op_type & JB_PATH_FILL_GAPS) && (level <= path_len - 1) &&
				v.val.array.rawScalar)
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						 errmsg("cannot replace existing key"),
						 errdetail("The path assumes key is a composite object, "
								   "but it is a scalar value.")));

			(void) pushJsonbValue(st, r, NULL);
			setPathArray(it, path_elems, path_nulls, path_len, st, level,
						 newval, v.val.array.nElems >= 0 ? v.val.array.nElems :
						 JsonGetArraySize((*it)->container), op_type);
			r = JsonbIteratorNext(it, &v, false);
			Assert(r == WJB_END_ARRAY);
			res = pushJsonbValue(st, r, NULL);
			break;
		case WJB_BEGIN_OBJECT:
			(void) pushJsonbValue(st, r, NULL);
			r = setPathObject(it, path_elems, path_nulls, path_len, st, level,
							  newval, op_type);
			Assert(r == WJB_END_OBJECT);
			res = pushJsonbValue(st, r, NULL);
			break;
		case WJB_ELEM:
		case WJB_VALUE:

			/*
			 * If instructed complain about attempts to replace whithin a
			 * scalar value. This happens even when current level is equal to
			 * path_len, because the last path key should also correspond to
			 * an object or an array, not an element or value.
			 */
			if ((op_type & JB_PATH_FILL_GAPS) && (level <= path_len - 1))
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						 errmsg("cannot replace existing key"),
						 errdetail("The path assumes key is a composite object, "
								   "but it is a scalar value.")));

			res = pushJsonbValueExt(st, r, &v, false);
			break;
		default:
			elog(ERROR, "unrecognized iterator result: %d", (int) r);
			res = NULL;			/* keep compiler quiet */
			break;
	}

	return res;
}

/*
 * Object walker for setPath
 */
static JsonbIteratorToken
setPathObject(JsonbIterator **it, Datum *path_elems, bool *path_nulls,
			  int path_len, JsonbParseState **st, int level,
			  JsonbValue *newval, int op_type)
{
	JsonbValue	k,
				v;
	JsonbIteratorToken r;
	bool		done = false;

	if (level >= path_len || path_nulls[level])
		done = true;

	while ((r = JsonbIteratorNext(it, &k, true)) == WJB_KEY)
	{
		if (!done &&
			k.val.string.len == VARSIZE_ANY_EXHDR(path_elems[level]) &&
			memcmp(k.val.string.val, VARDATA_ANY(path_elems[level]),
				   k.val.string.len) == 0)
		{
			done = true;

			if (level == path_len - 1)
			{
				/*
				 * called from jsonb_insert(), it forbids redefining an
				 * existing value
				 */
				if (op_type & (JB_PATH_INSERT_BEFORE | JB_PATH_INSERT_AFTER))
					ereport(ERROR,
							(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
							 errmsg("cannot replace existing key"),
							 errhint("Try using the function %s to replace key value.",
									 JsonContainerIsJsonb((*it)->container) ?
									 "jsonb_set" : "json_set")));

				r = JsonbIteratorNext(it, &v, true);	/* skip value */
				Assert(r == WJB_VALUE);

				if (!(op_type & JB_PATH_DELETE))
				{
					(void) pushJsonbValue(st, WJB_KEY, &k);
					(void) pushJsonbValueExt(st, WJB_VALUE, newval, false);
				}
			}
			else
			{
				(void) pushJsonbValue(st, r, &k);
				setPath(it, path_elems, path_nulls, path_len,
						st, level + 1, newval, op_type);
			}
		}
		else
		{
			(void) pushJsonbValue(st, r, &k);
			r = JsonbIteratorNext(it, &v, true);
			Assert(r == WJB_VALUE);
			(void) pushJsonbValueExt(st, r, &v, false);
		}
	}

	if (done)
		return r;

	/*
	 * If we got here there are only few possibilities:
	 * - no target path was found, and an open object with some keys/values was
	 *   pushed into the state
	 * - an object is empty, only WJB_BEGIN_OBJECT is pushed
	 *
	 * In both cases if instructed to create the path when not present,
	 * generate the whole chain of empty objects and insert the new value
	 * there.
	 */
	if ((level < path_len - 1 && (op_type & JB_PATH_FILL_GAPS)) ||
		(level == path_len - 1 && (op_type & JB_PATH_CREATE_OR_INSERT)))
	{
		JsonbValue	newkey;

		newkey.type = jbvString;
		newkey.val.string.len = VARSIZE_ANY_EXHDR(path_elems[level]);
		newkey.val.string.val = VARDATA_ANY(path_elems[level]);

		(void) pushJsonbValue(st, WJB_KEY, &newkey);

		if (level == path_len - 1)
			(void) pushJsonbValueExt(st, WJB_VALUE, newval, false);
		else
			(void) push_path(st, level, path_elems, path_nulls,
							 path_len, newval);

		/* Result is closed with WJB_END_OBJECT outside of this function */
	}

	return r;
}

/*
 * Array walker for setPath
 */
static void
setPathArray(JsonbIterator **it, Datum *path_elems, bool *path_nulls,
			 int path_len, JsonbParseState **st, int level,
			 JsonbValue *newval, uint32 nelems, int op_type)
{
	JsonbValue	v;
	int			idx,
				i;
	bool		done = false;

	/* pick correct index */
	if (level < path_len && !path_nulls[level])
	{
		char	   *c = TextDatumGetCString(path_elems[level]);
		char	   *badp;

		errno = 0;
		idx = strtoint(c, &badp, 10);
		if (badp == c || *badp != '\0' || errno != 0)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
					 errmsg("path element at position %d is not an integer: \"%s\"",
							level + 1, c)));
	}
	else
		idx = nelems;

	if (idx < 0)
	{
		if (-idx > nelems)
		{
			/*
			 * If asked to keep elements position consistent, it's not allowed
			 * to prepend the array.
			 */
			if (op_type & JB_PATH_CONSISTENT_POSITION)
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						 errmsg("path element at position %d is out of range: %d",
								level + 1, idx)));
			else
				idx = INT_MIN;
		}
		else
			idx = nelems + idx;
	}

	/*
	 * Filling the gaps means there are no limits on the positive index are
	 * imposed, we can set any element. Otherwise limit the index by nelems.
	 */
	if (!(op_type & JB_PATH_FILL_GAPS))
	{
		if (idx > 0 && idx > nelems)
			idx = nelems;
	}

	/*
	 * if we're creating, and idx == INT_MIN, we prepend the new value to the
	 * array also if the array is empty - in which case we don't really care
	 * what the idx value is
	 */
	if ((idx == INT_MIN || nelems == 0) && (level == path_len - 1) &&
		(op_type & JB_PATH_CREATE_OR_INSERT))
	{
		Assert(newval != NULL);

		if (op_type & JB_PATH_FILL_GAPS && nelems == 0 && idx > 0)
			push_null_elements(st, idx);

		(void) pushJsonbValueExt(st, WJB_ELEM, newval, false);

		done = true;
	}

	/* iterate over the array elements */
	for (i = 0; i < nelems; i++)
	{
		JsonbIteratorToken r;

		if (i == idx && level < path_len)
		{
			done = true;

			if (level == path_len - 1)
			{
				r = JsonbIteratorNext(it, &v, true);	/* skip */

				if (op_type & (JB_PATH_INSERT_BEFORE | JB_PATH_CREATE))
					(void) pushJsonbValueExt(st, WJB_ELEM, newval, false);

				/*
				 * We should keep current value only in case of
				 * JB_PATH_INSERT_BEFORE or JB_PATH_INSERT_AFTER because
				 * otherwise it should be deleted or replaced
				 */
				if (op_type & (JB_PATH_INSERT_AFTER | JB_PATH_INSERT_BEFORE))
					(void) pushJsonbValueExt(st, r, &v, false);

				if (op_type & (JB_PATH_INSERT_AFTER | JB_PATH_REPLACE))
					(void) pushJsonbValueExt(st, WJB_ELEM, newval, false);
			}
			else
				(void) setPath(it, path_elems, path_nulls, path_len,
							   st, level + 1, newval, op_type);
		}
		else
		{
			r = JsonbIteratorNext(it, &v, true);
			Assert(r == WJB_ELEM);
			(void) pushJsonbValueExt(st, r, &v, false);
		}
	}

	if ((op_type & JB_PATH_CREATE_OR_INSERT) && !done && level == path_len - 1)
	{
		/*
		 * If asked to fill the gaps, idx could be bigger than nelems, so
		 * prepend the new element with nulls if that's the case.
		 */
		if (op_type & JB_PATH_FILL_GAPS && idx > nelems)
			push_null_elements(st, idx - nelems);

		(void) pushJsonbValueExt(st, WJB_ELEM, newval, false);
		done = true;
	}

	/*--
	 * If we got here there are only few possibilities:
	 * - no target path was found, and an open array with some keys/values was
	 *   pushed into the state
	 * - an array is empty, only WJB_BEGIN_ARRAY is pushed
	 *
	 * In both cases if instructed to create the path when not present,
	 * generate the whole chain of empty objects and insert the new value
	 * there.
	 */
	if (!done && (op_type & JB_PATH_FILL_GAPS) && (level < path_len - 1))
	{
		if (idx > 0)
			push_null_elements(st, idx - nelems);

		(void) push_path(st, level, path_elems, path_nulls,
						 path_len, newval);

		/* Result is closed with WJB_END_OBJECT outside of this function */
	}
}

/*
 * Parse information about what elements of a jsonb document we want to iterate
 * in functions iterate_json(b)_values. This information is presented in jsonb
 * format, so that it can be easily extended in the future.
 */
uint32
parse_jsonb_index_flags(Jsonb *jb)
{
	JsonbIterator *it;
	JsonbValue	v;
	JsonbIteratorToken type;
	uint32		flags = 0;

	it = JsonbIteratorInit(JsonbRoot(jb));

	type = JsonbIteratorNext(&it, &v, false);

	/*
	 * We iterate over array (scalar internally is represented as array, so,
	 * we will accept it too) to check all its elements.  Flag names are
	 * chosen the same as jsonb_typeof uses.
	 */
	if (type != WJB_BEGIN_ARRAY)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						errmsg("wrong flag type, only arrays and scalars are allowed")));

	while ((type = JsonbIteratorNext(&it, &v, false)) == WJB_ELEM)
	{
		if (v.type != jbvString)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("flag array element is not a string"),
					 errhint("Possible values are: \"string\", \"numeric\", \"boolean\", \"key\", and \"all\".")));

		if (v.val.string.len == 3 &&
			pg_strncasecmp(v.val.string.val, "all", 3) == 0)
			flags |= jtiAll;
		else if (v.val.string.len == 3 &&
				 pg_strncasecmp(v.val.string.val, "key", 3) == 0)
			flags |= jtiKey;
		else if (v.val.string.len == 6 &&
				 pg_strncasecmp(v.val.string.val, "string", 6) == 0)
			flags |= jtiString;
		else if (v.val.string.len == 7 &&
				 pg_strncasecmp(v.val.string.val, "numeric", 7) == 0)
			flags |= jtiNumeric;
		else if (v.val.string.len == 7 &&
				 pg_strncasecmp(v.val.string.val, "boolean", 7) == 0)
			flags |= jtiBool;
		else
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("wrong flag in flag array: \"%s\"",
							pnstrdup(v.val.string.val, v.val.string.len)),
					 errhint("Possible values are: \"string\", \"numeric\", \"boolean\", \"key\", and \"all\".")));
	}

	/* expect end of array now */
	if (type != WJB_END_ARRAY)
		elog(ERROR, "unexpected end of flag array");

	/* get final WJB_DONE and free iterator */
	type = JsonbIteratorNext(&it, &v, false);
	if (type != WJB_DONE)
		elog(ERROR, "unexpected end of flag array");

	return flags;
}

/*
 * Iterate over jsonb values or elements, specified by flags, and pass them
 * together with an iteration state to a specified JsonIterateStringValuesAction.
 */
void
iterate_jsonb_values(Jsonb *jb, uint32 flags, void *state,
					 JsonIterateStringValuesAction action)
{
	JsonbIterator *it;
	JsonbValue	v;
	JsonbIteratorToken type;

	it = JsonbIteratorInit(JsonbRoot(jb));

	/*
	 * Just recursively iterating over jsonb and call callback on all
	 * corresponding elements
	 */
	while ((type = JsonbIteratorNext(&it, &v, false)) != WJB_DONE)
	{
		if (type == WJB_KEY)
		{
			if (flags & jtiKey)
				action(state, v.val.string.val, v.val.string.len);

			continue;
		}
		else if (!(type == WJB_VALUE || type == WJB_ELEM))
		{
			/* do not call callback for composite JsonbValue */
			continue;
		}

		/* JsonbValue is a value of object or element of array */
		switch (v.type)
		{
			case jbvString:
				if (flags & jtiString)
					action(state, v.val.string.val, v.val.string.len);
				break;
			case jbvNumeric:
				if (flags & jtiNumeric)
				{
					char	   *val;

					val = DatumGetCString(DirectFunctionCall1(numeric_out,
															  NumericGetDatum(v.val.numeric)));

					action(state, val, strlen(val));
					pfree(val);
				}
				break;
			case jbvBool:
				if (flags & jtiBool)
				{
					if (v.val.boolean)
						action(state, "true", 4);
					else
						action(state, "false", 5);
				}
				break;
			default:
				/* do not call callback for composite JsonbValue */
				break;
		}
	}
}

/*
 * Iterate over a jsonb, and apply a specified JsonTransformStringValuesAction
 * to every string value or element. Any necessary context for a
 * JsonTransformStringValuesAction can be passed in the action_state variable.
 * Function returns a copy of an original jsonb object with transformed values.
 */
Jsonb *
transform_jsonb_string_values(Jsonb *jsonb, void *action_state,
							  JsonTransformStringValuesAction transform_action,
							  bool is_json)
{
	JsonbIterator *it;
	JsonbValue	v,
			   *res = NULL;
	JsonbIteratorToken type;
	JsonbParseState *st = NULL;
	text	   *out;

	it = JsonbIteratorInit(JsonbRoot(jsonb));

	while ((type = JsonbIteratorNext(&it, &v, false)) != WJB_DONE)
	{
		if ((type == WJB_VALUE || type == WJB_ELEM) && v.type == jbvString)
		{
			out = transform_action(action_state, v.val.string.val, v.val.string.len);
			v.val.string.val = VARDATA_ANY(out);
			v.val.string.len = VARSIZE_ANY_EXHDR(out);
			res = pushJsonbValue(&st, type, type < WJB_BEGIN_ARRAY ? &v : NULL);
		}
		else
		{
			res = pushJsonbValue(&st, type, (type == WJB_KEY ||
											 type == WJB_VALUE ||
											 type == WJB_ELEM) ? &v : NULL);

			if (is_json)
			{
				if (type == WJB_BEGIN_OBJECT)
				{
					res->val.object.uniquified = false;
					res->val.object.braceSeparator = '\0';
					res->val.object.colonSeparator.before = '\0';
					res->val.object.colonSeparator.after = '\0';
					res->val.object.fieldSeparator[0] = '\0';
				}
				else if (type == WJB_BEGIN_ARRAY)
				{
					res->val.array.uniquified = false;
					res->val.array.elementSeparator[0] = '\0';
					res->val.array.elementSeparator[1] = '\0';
					res->val.array.elementSeparator[2] = '\0';
				}
			}
		}
	}

	if (res->type == jbvArray)
		res->val.array.rawScalar = JB_ROOT_IS_SCALAR(jsonb);

	return JsonbValueToJsonb(res);
}
