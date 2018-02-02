/*-------------------------------------------------------------------------
 *
 * ts_configmap.c
 *		internal representation of text search configuration and utilities for it
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/tsearch/ts_confimap.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include <ctype.h>

#include "access/heapam.h"
#include "access/genam.h"
#include "access/htup_details.h"
#include "access/sysattr.h"
#include "catalog/indexing.h"
#include "catalog/pg_ts_dict.h"
#include "tsearch/ts_cache.h"
#include "tsearch/ts_configmap.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"

/*
 * Size selected arbitrary, based on assumption that 1024 frames of stack
 * is enough for parsing of configurations
 */
#define JSONB_PARSE_STATE_STACK_SIZE 1024

/*
 * Used during the parsing of TSMapElement from JSONB into internal
 * data structures.
 */
typedef enum TSMapParseState
{
	TSMPS_WAIT_ELEMENT,
	TSMPS_READ_DICT_OID,
	TSMPS_READ_COMPLEX_OBJ,
	TSMPS_READ_EXPRESSION,
	TSMPS_READ_CASE,
	TSMPS_READ_OPERATOR,
	TSMPS_READ_COMMAND,
	TSMPS_READ_CONDITION,
	TSMPS_READ_ELSEBRANCH,
	TSMPS_READ_MATCH,
	TSMPS_READ_KEEP,
	TSMPS_READ_LEFT,
	TSMPS_READ_RIGHT
} TSMapParseState;

/*
 * Context used during JSONB parsing to construct a TSMap
 */
typedef struct TSMapJsonbParseData
{
	TSMapParseState states[JSONB_PARSE_STATE_STACK_SIZE];	/* Stack of states of
															 * JSONB parsing
															 * automaton */
	int			statesIndex;	/* Index of current stack frame */
	TSMapElement *element;		/* Element that is in construction now */
} TSMapJsonbParseData;

static JsonbValue *TSMapElementToJsonbValue(TSMapElement *element, JsonbParseState *jsonbState);
static TSMapElement * JsonbToTSMapElement(JsonbContainer *root);

/*
 * Print name of the dictionary into StringInfo variable result
 */
void
TSMapPrintDictName(Oid dictId, StringInfo result)
{
	Relation	maprel;
	Relation	mapidx;
	ScanKeyData mapskey;
	SysScanDesc mapscan;
	HeapTuple	maptup;
	Form_pg_ts_dict dict;

	if (false)
		return;

	maprel = heap_open(TSDictionaryRelationId, AccessShareLock);
	mapidx = index_open(TSDictionaryOidIndexId, AccessShareLock);

	ScanKeyInit(&mapskey, ObjectIdAttributeNumber,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(dictId));
	mapscan = systable_beginscan_ordered(maprel, mapidx,
										 NULL, 1, &mapskey);

	maptup = systable_getnext_ordered(mapscan, ForwardScanDirection);
	dict = (Form_pg_ts_dict) GETSTRUCT(maptup);
	appendStringInfoString(result, dict->dictname.data);

	systable_endscan_ordered(mapscan);
	index_close(mapidx, AccessShareLock);
	heap_close(maprel, AccessShareLock);
}

/*
 * Print the expression into StringInfo variable result
 */
static void
TSMapPrintExpression(TSMapExpression *expression, StringInfo result)
{

	if (expression->left)
		TSMapPrintElement(expression->left, result);

	switch (expression->operator)
	{
		case TSMAP_OP_UNION:
			appendStringInfoString(result, " UNION ");
			break;
		case TSMAP_OP_EXCEPT:
			appendStringInfoString(result, " EXCEPT ");
			break;
		case TSMAP_OP_INTERSECT:
			appendStringInfoString(result, " INTERSECT ");
			break;
		case TSMAP_OP_COMMA:
			appendStringInfoString(result, ", ");
			break;
		case TSMAP_OP_MAP:
			appendStringInfoString(result, " MAP ");
			break;
		default:
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("text search configuration is invalid"),
					 errdetail("Text search configuration contains invalid expression operator.")));
			break;
	}

	if (expression->right)
		TSMapPrintElement(expression->right, result);
}

/*
 * Print the case configuration construction into StringInfo variable result
 */
static void
TSMapPrintCase(TSMapCase *caseObject, StringInfo result)
{
	appendStringInfoString(result, "CASE ");

	TSMapPrintElement(caseObject->condition, result);

	appendStringInfoString(result, " WHEN ");
	if (!caseObject->match)
		appendStringInfoString(result, "NO ");
	appendStringInfoString(result, "MATCH THEN ");

	TSMapPrintElement(caseObject->command, result);

	if (caseObject->elsebranch != NULL)
	{
		appendStringInfoString(result, "\nELSE ");
		TSMapPrintElement(caseObject->elsebranch, result);
	}
	appendStringInfoString(result, "\nEND");
}

/*
 * Print the element into StringInfo result.
 * Uses other function and serves for element type detection.
 */
void
TSMapPrintElement(TSMapElement *element, StringInfo result)
{
	switch (element->type)
	{
		case TSMAP_EXPRESSION:
			TSMapPrintExpression(element->value.objectExpression, result);
			break;
		case TSMAP_DICTIONARY:
			TSMapPrintDictName(element->value.objectDictionary, result);
			break;
		case TSMAP_CASE:
			TSMapPrintCase(element->value.objectCase, result);
			break;
		case TSMAP_KEEP:
			appendStringInfoString(result, "KEEP");
			break;
		default:
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("text search configuration is invalid"),
					 errdetail("Text search configuration contains elements with invalid type.")));
			break;
	}
}

/*
 * Print the text search configuration as a text.
 */
Datum
dictionary_mapping_to_text(PG_FUNCTION_ARGS)
{
	Oid			cfgOid = PG_GETARG_OID(0);
	int32		tokentype = PG_GETARG_INT32(1);
	StringInfo	rawResult;
	text	   *result = NULL;
	TSConfigCacheEntry *cacheEntry;

	cacheEntry = lookup_ts_config_cache(cfgOid);
	rawResult = makeStringInfo();
	initStringInfo(rawResult);

	if (cacheEntry->lenmap > tokentype && cacheEntry->map[tokentype] != NULL)
	{
		TSMapElement *element = cacheEntry->map[tokentype];

		TSMapPrintElement(element, rawResult);
	}

	result = cstring_to_text(rawResult->data);
	pfree(rawResult);
	PG_RETURN_TEXT_P(result);
}

/* ----------------
 * Functions used to convert TSMap structure into JSONB representation
 * ----------------
 */

/*
 * Convert an integer value into JsonbValue
 */
static JsonbValue *
IntToJsonbValue(int intValue)
{
	char		buffer[16];
	JsonbValue *value = palloc0(sizeof(JsonbValue));

	/*
	 * String size is based on limit of int capacity up to 12 chars with sign
	 * and NULL-character
	 */
	memset(buffer, 0, sizeof(char) * 12);

	pg_ltoa(intValue, buffer);
	value->type = jbvNumeric;
	value->val.numeric = DatumGetNumeric(DirectFunctionCall3(numeric_in,
															 CStringGetDatum(buffer),
															 ObjectIdGetDatum(InvalidOid),
															 Int32GetDatum(-1)
															 ));
	return value;
}

/*
 * Convert a FTS configuration expression into JsonbValue
 */
static JsonbValue *
TSMapExpressionToJsonbValue(TSMapExpression *expression, JsonbParseState *jsonbState)
{
	JsonbValue	key;
	JsonbValue *value = NULL;

	pushJsonbValue(&jsonbState, WJB_BEGIN_OBJECT, NULL);

	key.type = jbvString;
	key.val.string.len = strlen("operator");
	key.val.string.val = "operator";
	value = IntToJsonbValue(expression->operator);

	pushJsonbValue(&jsonbState, WJB_KEY, &key);
	pushJsonbValue(&jsonbState, WJB_VALUE, value);

	key.type = jbvString;
	key.val.string.len = strlen("left");
	key.val.string.val = "left";

	pushJsonbValue(&jsonbState, WJB_KEY, &key);
	value = TSMapElementToJsonbValue(expression->left, jsonbState);
	if (value && IsAJsonbScalar(value))
		pushJsonbValue(&jsonbState, WJB_VALUE, value);

	key.type = jbvString;
	key.val.string.len = strlen("right");
	key.val.string.val = "right";

	pushJsonbValue(&jsonbState, WJB_KEY, &key);
	value = TSMapElementToJsonbValue(expression->right, jsonbState);
	if (value && IsAJsonbScalar(value))
		pushJsonbValue(&jsonbState, WJB_VALUE, value);

	return pushJsonbValue(&jsonbState, WJB_END_OBJECT, NULL);
}

/*
 * Convert a FTS configuration case into JsonbValue
 */
static JsonbValue *
TSMapCaseToJsonbValue(TSMapCase *caseObject, JsonbParseState *jsonbState)
{
	JsonbValue	key;
	JsonbValue *value = NULL;

	pushJsonbValue(&jsonbState, WJB_BEGIN_OBJECT, NULL);

	key.type = jbvString;
	key.val.string.len = strlen("condition");
	key.val.string.val = "condition";

	pushJsonbValue(&jsonbState, WJB_KEY, &key);
	value = TSMapElementToJsonbValue(caseObject->condition, jsonbState);

	if (value && IsAJsonbScalar(value))
		pushJsonbValue(&jsonbState, WJB_VALUE, value);

	key.type = jbvString;
	key.val.string.len = strlen("command");
	key.val.string.val = "command";

	pushJsonbValue(&jsonbState, WJB_KEY, &key);
	value = TSMapElementToJsonbValue(caseObject->command, jsonbState);

	if (value && IsAJsonbScalar(value))
		pushJsonbValue(&jsonbState, WJB_VALUE, value);

	if (caseObject->elsebranch != NULL)
	{
		key.type = jbvString;
		key.val.string.len = strlen("elsebranch");
		key.val.string.val = "elsebranch";

		pushJsonbValue(&jsonbState, WJB_KEY, &key);
		value = TSMapElementToJsonbValue(caseObject->elsebranch, jsonbState);

		if (value && IsAJsonbScalar(value))
			pushJsonbValue(&jsonbState, WJB_VALUE, value);
	}

	key.type = jbvString;
	key.val.string.len = strlen("match");
	key.val.string.val = "match";

	value = IntToJsonbValue(caseObject->match ? 1 : 0);

	pushJsonbValue(&jsonbState, WJB_KEY, &key);
	pushJsonbValue(&jsonbState, WJB_VALUE, value);

	return pushJsonbValue(&jsonbState, WJB_END_OBJECT, NULL);
}

/*
 * Convert a FTS KEEP command into JsonbValue
 */
static JsonbValue *
TSMapKeepToJsonbValue(JsonbParseState *jsonbState)
{
	JsonbValue *value = palloc0(sizeof(JsonbValue));

	value->type = jbvString;
	value->val.string.len = strlen("keep");
	value->val.string.val = "keep";

	return pushJsonbValue(&jsonbState, WJB_VALUE, value);
}

/*
 * Convert a FTS element into JsonbValue. Common point for all types of TSMapElement
 */
JsonbValue *
TSMapElementToJsonbValue(TSMapElement *element, JsonbParseState *jsonbState)
{
	JsonbValue *result = NULL;

	if (element != NULL)
	{
		switch (element->type)
		{
			case TSMAP_EXPRESSION:
				result = TSMapExpressionToJsonbValue(element->value.objectExpression, jsonbState);
				break;
			case TSMAP_DICTIONARY:
				result = IntToJsonbValue(element->value.objectDictionary);
				break;
			case TSMAP_CASE:
				result = TSMapCaseToJsonbValue(element->value.objectCase, jsonbState);
				break;
			case TSMAP_KEEP:
				result = TSMapKeepToJsonbValue(jsonbState);
				break;
			default:
				ereport(ERROR,
						(errcode(ERRCODE_DATA_CORRUPTED),
						 errmsg("text search configuration is invalid"),
						 errdetail("Required text search configuration contains elements with invalid type.")));
				break;
		}
	}
	return result;
}

/*
 * Convert a FTS configuration into JSONB
 */
Jsonb *
TSMapToJsonb(TSMapElement *element)
{
	JsonbParseState *jsonbState = NULL;
	JsonbValue *out;
	Jsonb	   *result;

	out = TSMapElementToJsonbValue(element, jsonbState);

	result = JsonbValueToJsonb(out);
	return result;
}

/* ----------------
 * Functions used to get TSMap structure from JSONB representation
 * ----------------
 */

/*
 * Extract an integer from JsonbValue
 */
static int
JsonbValueToInt(JsonbValue *value)
{
	char	   *str;

	str = DatumGetCString(DirectFunctionCall1(numeric_out, NumericGetDatum(value->val.numeric)));
	return pg_atoi(str, sizeof(int), 0);
}

/*
 * Check is a key one of FTS configuration case fields
 */
static bool
IsTSMapCaseKey(JsonbValue *value)
{
	/*
	 * JsonbValue string may be not null-terminated. Convert it for appropriate
	 * behavior of strcmp function.
	 */
	char	   *key = palloc0(sizeof(char) * (value->val.string.len + 1));

	key[value->val.string.len] = '\0';
	memcpy(key, value->val.string.val, sizeof(char) * value->val.string.len);
	return strcmp(key, "match") == 0 || strcmp(key, "condition") == 0 || strcmp(key, "command") == 0 || strcmp(key, "elsebranch") == 0;
}

/*
 * Check is a key one of FTS configuration expression fields
 */
static bool
IsTSMapExpressionKey(JsonbValue *value)
{
	/*
	 * JsonbValue string may be not null-terminated. Convert it for appropriate
	 * behavior of strcmp function.
	 */
	char	   *key = palloc0(sizeof(char) * (value->val.string.len + 1));

	key[value->val.string.len] = '\0';
	memcpy(key, value->val.string.val, sizeof(char) * value->val.string.len);
	return strcmp(key, "operator") == 0 || strcmp(key, "left") == 0 || strcmp(key, "right") == 0;
}

/*
 * Configure parseData->element according to value (key)
 */
static void
JsonbBeginObjectKey(JsonbValue value, TSMapJsonbParseData *parseData)
{
	TSMapElement *parentElement = parseData->element;

	parseData->element = palloc0(sizeof(TSMapElement));
	parseData->element->parent = parentElement;

	/* Overwrite object-type state based on key */
	if (IsTSMapExpressionKey(&value))
	{
		parseData->states[parseData->statesIndex] = TSMPS_READ_EXPRESSION;
		parseData->element->type = TSMAP_EXPRESSION;
		parseData->element->value.objectExpression = palloc0(sizeof(TSMapExpression));
	}
	else if (IsTSMapCaseKey(&value))
	{
		parseData->states[parseData->statesIndex] = TSMPS_READ_CASE;
		parseData->element->type = TSMAP_CASE;
		parseData->element->value.objectExpression = palloc0(sizeof(TSMapCase));
	}
}

/*
 * Process a JsonbValue inside a FTS configuration expression
 */
static void
JsonbKeyExpressionProcessing(JsonbValue value, TSMapJsonbParseData *parseData)
{
	/*
	 * JsonbValue string may be not null-terminated. Convert it for appropriate
	 * behavior of strcmp function.
	 */
	char	   *key = palloc0(sizeof(char) * (value.val.string.len + 1));

	memcpy(key, value.val.string.val, sizeof(char) * value.val.string.len);
	parseData->statesIndex++;

	if (parseData->statesIndex >= JSONB_PARSE_STATE_STACK_SIZE)
		ereport(ERROR,
				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
				 errmsg("configuration is too complex to be parsed"),
				 errdetail("Configurations with more than %d nested objected are not supported.",
						   JSONB_PARSE_STATE_STACK_SIZE)));

	if (strcmp(key, "operator") == 0)
		parseData->states[parseData->statesIndex] = TSMPS_READ_OPERATOR;
	else if (strcmp(key, "left") == 0)
		parseData->states[parseData->statesIndex] = TSMPS_READ_LEFT;
	else if (strcmp(key, "right") == 0)
		parseData->states[parseData->statesIndex] = TSMPS_READ_RIGHT;
}

/*
 * Process a JsonbValue inside a FTS configuration case
 */
static void
JsonbKeyCaseProcessing(JsonbValue value, TSMapJsonbParseData *parseData)
{
	/*
	 * JsonbValue string may be not null-terminated. Convert it for appropriate
	 * behavior of strcmp function.
	 */
	char	   *key = palloc0(sizeof(char) * (value.val.string.len + 1));

	memcpy(key, value.val.string.val, sizeof(char) * value.val.string.len);
	parseData->statesIndex++;

	if (parseData->statesIndex >= JSONB_PARSE_STATE_STACK_SIZE)
		ereport(ERROR,
				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
				 errmsg("configuration is too complex to be parsed"),
				 errdetail("Configurations with more than %d nested objected are not supported.",
						   JSONB_PARSE_STATE_STACK_SIZE)));

	if (strcmp(key, "condition") == 0)
		parseData->states[parseData->statesIndex] = TSMPS_READ_CONDITION;
	else if (strcmp(key, "command") == 0)
		parseData->states[parseData->statesIndex] = TSMPS_READ_COMMAND;
	else if (strcmp(key, "elsebranch") == 0)
		parseData->states[parseData->statesIndex] = TSMPS_READ_ELSEBRANCH;
	else if (strcmp(key, "match") == 0)
		parseData->states[parseData->statesIndex] = TSMPS_READ_MATCH;
}

/*
 * Convert a JsonbValue into OID TSMapElement
 */
static TSMapElement *
JsonbValueToOidElement(JsonbValue *value, TSMapElement *parent)
{
	TSMapElement *element = palloc0(sizeof(TSMapElement));

	element->parent = parent;
	element->type = TSMAP_DICTIONARY;
	element->value.objectDictionary = JsonbValueToInt(value);
	return element;
}

/*
 * Convert a JsonbValue into string TSMapElement.
 * Used for special values such as KEEP command
 */
static TSMapElement *
JsonbValueReadString(JsonbValue *value, TSMapElement *parent)
{
	char	   *str;
	TSMapElement *element = palloc0(sizeof(TSMapElement));

	element->parent = parent;
	str = palloc0(sizeof(char) * (value->val.string.len + 1));
	memcpy(str, value->val.string.val, sizeof(char) * value->val.string.len);

	if (strcmp(str, "keep") == 0)
		element->type = TSMAP_KEEP;

	pfree(str);

	return element;
}

/*
 * Process a JsonbValue object
 */
static void
JsonbProcessElement(JsonbIteratorToken r, JsonbValue value, TSMapJsonbParseData *parseData)
{
	TSMapElement *element = NULL;

	switch (r)
	{
		case WJB_KEY:

			/*
			 * Construct an TSMapElement object. At first key inside JSONB
			 * object a type is selected based on key.
			 */
			if (parseData->states[parseData->statesIndex] == TSMPS_READ_COMPLEX_OBJ)
				JsonbBeginObjectKey(value, parseData);

			if (parseData->states[parseData->statesIndex] == TSMPS_READ_EXPRESSION)
				JsonbKeyExpressionProcessing(value, parseData);
			else if (parseData->states[parseData->statesIndex] == TSMPS_READ_CASE)
				JsonbKeyCaseProcessing(value, parseData);

			break;
		case WJB_BEGIN_OBJECT:

			/*
			 * Begin construction of new object
			 */
			parseData->statesIndex++;
			parseData->states[parseData->statesIndex] = TSMPS_READ_COMPLEX_OBJ;
			break;
		case WJB_END_OBJECT:

			/*
			 * Save constructed object based on current state of parser
			 */
			if (parseData->states[parseData->statesIndex] == TSMPS_READ_LEFT)
				parseData->element->parent->value.objectExpression->left = parseData->element;
			else if (parseData->states[parseData->statesIndex] == TSMPS_READ_RIGHT)
				parseData->element->parent->value.objectExpression->right = parseData->element;

			else if (parseData->states[parseData->statesIndex] == TSMPS_READ_CONDITION)
				parseData->element->parent->value.objectCase->condition = parseData->element;
			else if (parseData->states[parseData->statesIndex] == TSMPS_READ_COMMAND)
				parseData->element->parent->value.objectCase->command = parseData->element;
			else if (parseData->states[parseData->statesIndex] == TSMPS_READ_ELSEBRANCH)
				parseData->element->parent->value.objectCase->elsebranch = parseData->element;

			parseData->statesIndex--;
			Assert(parseData->statesIndex >= 0);
			if (parseData->element->parent != NULL)
				parseData->element = parseData->element->parent;
			break;
		case WJB_VALUE:

			/*
			 * Save a value inside constructing object
			 */
			if (value.type == jbvBinary)
				element = JsonbToTSMapElement(value.val.binary.data);
			else if (value.type == jbvString)
				element = JsonbValueReadString(&value, parseData->element);
			else if (value.type == jbvNumeric)
				element = JsonbValueToOidElement(&value, parseData->element);
			else
				ereport(ERROR,
						(errcode(ERRCODE_DATA_CORRUPTED),
						 errmsg("text search configuration is invalid"),
						 errdetail("Text search configuration contains object with invalid type.")));

			if (parseData->states[parseData->statesIndex] == TSMPS_READ_CONDITION)
				parseData->element->value.objectCase->condition = element;
			else if (parseData->states[parseData->statesIndex] == TSMPS_READ_COMMAND)
				parseData->element->value.objectCase->command = element;
			else if (parseData->states[parseData->statesIndex] == TSMPS_READ_ELSEBRANCH)
				parseData->element->value.objectCase->elsebranch = element;
			else if (parseData->states[parseData->statesIndex] == TSMPS_READ_MATCH)
				parseData->element->value.objectCase->match = JsonbValueToInt(&value) == 1 ? true : false;

			else if (parseData->states[parseData->statesIndex] == TSMPS_READ_OPERATOR)
				parseData->element->value.objectExpression->operator = JsonbValueToInt(&value);
			else if (parseData->states[parseData->statesIndex] == TSMPS_READ_LEFT)
				parseData->element->value.objectExpression->left = element;
			else if (parseData->states[parseData->statesIndex] == TSMPS_READ_RIGHT)
				parseData->element->value.objectExpression->right = element;

			parseData->statesIndex--;
			Assert(parseData->statesIndex >= 0);
			if (parseData->element->parent != NULL)
				parseData->element = parseData->element->parent;
			break;
		case WJB_ELEM:

			/*
			 * Store a simple element such as dictionary OID
			 */
			if (parseData->states[parseData->statesIndex] == TSMPS_WAIT_ELEMENT)
			{
				if (parseData->element != NULL)
					parseData->element = JsonbValueToOidElement(&value, parseData->element->parent);
				else
					parseData->element = JsonbValueToOidElement(&value, NULL);
			}
			break;
		default:
			/* Ignore unused JSONB tokens */
			break;
	}
}

/*
 * Convert a JsonbContainer into TSMapElement
 */
static TSMapElement *
JsonbToTSMapElement(JsonbContainer *root)
{
	TSMapJsonbParseData parseData;
	JsonbIteratorToken r;
	JsonbIterator *it;
	JsonbValue	val;

	parseData.statesIndex = 0;
	parseData.states[parseData.statesIndex] = TSMPS_WAIT_ELEMENT;
	parseData.element = NULL;

	it = JsonbIteratorInit(root);

	while ((r = JsonbIteratorNext(&it, &val, true)) != WJB_DONE)
		JsonbProcessElement(r, val, &parseData);

	return parseData.element;
}

/*
 * Convert a JSONB into TSMapElement
 */
TSMapElement *
JsonbToTSMap(Jsonb *json)
{
	JsonbContainer *root = &json->root;

	return JsonbToTSMapElement(root);
}

/* ----------------
 * Text Search Configuration Map Utils
 * ----------------
 */

/*
 * Dynamically extendable list of OIDs
 */
typedef struct OidList
{
	Oid		   *data;
	int			size;			/* Size of data array. Uninitialized elements
								 * in data filled with InvalidOid */
} OidList;

/*
 * Initialize a list
 */
static OidList *
OidListInit()
{
	OidList    *result = palloc0(sizeof(OidList));

	result->size = 1;
	result->data = palloc0(result->size * sizeof(Oid));
	result->data[0] = InvalidOid;
	return result;
}

/*
 * Add a new OID into list. If it is already stored in list, it won't be add second time.
 */
static void
OidListAdd(OidList *list, Oid oid)
{
	int			i;

	/* Search for the Oid in the list */
	for (i = 0; list->data[i] != InvalidOid; i++)
		if (list->data[i] == oid)
			return;

	/* If not found, insert it in the end of the list */
	if (i >= list->size - 1)
	{
		int			j;

		list->size = list->size * 2;
		list->data = repalloc(list->data, sizeof(Oid) * list->size);

		for (j = i; j < list->size; j++)
			list->data[j] = InvalidOid;
	}
	list->data[i] = oid;
}

/*
 * Get OIDs of all dictionaries used in TSMapElement.
 * Used for internal recursive calls.
 */
static void
TSMapGetDictionariesInternal(TSMapElement *config, OidList *list)
{
	switch (config->type)
	{
		case TSMAP_EXPRESSION:
			TSMapGetDictionariesInternal(config->value.objectExpression->left, list);
			TSMapGetDictionariesInternal(config->value.objectExpression->right, list);
			break;
		case TSMAP_CASE:
			TSMapGetDictionariesInternal(config->value.objectCase->command, list);
			TSMapGetDictionariesInternal(config->value.objectCase->condition, list);
			if (config->value.objectCase->elsebranch != NULL)
				TSMapGetDictionariesInternal(config->value.objectCase->elsebranch, list);
			break;
		case TSMAP_DICTIONARY:
			OidListAdd(list, config->value.objectDictionary);
			break;
	}
}

/*
 * Get OIDs of all dictionaries used in TSMapElement
 */
Oid *
TSMapGetDictionaries(TSMapElement *config)
{
	Oid		   *result;
	OidList    *list = OidListInit();

	TSMapGetDictionariesInternal(config, list);

	result = list->data;
	pfree(list);

	return result;
}

/*
 * Replace one dictionary OID with another in all instances inside a configuration
 */
void
TSMapReplaceDictionary(TSMapElement *config, Oid oldDict, Oid newDict)
{
	switch (config->type)
	{
		case TSMAP_EXPRESSION:
			TSMapReplaceDictionary(config->value.objectExpression->left, oldDict, newDict);
			TSMapReplaceDictionary(config->value.objectExpression->right, oldDict, newDict);
			break;
		case TSMAP_CASE:
			TSMapReplaceDictionary(config->value.objectCase->command, oldDict, newDict);
			TSMapReplaceDictionary(config->value.objectCase->condition, oldDict, newDict);
			if (config->value.objectCase->elsebranch != NULL)
				TSMapReplaceDictionary(config->value.objectCase->elsebranch, oldDict, newDict);
			break;
		case TSMAP_DICTIONARY:
			if (config->value.objectDictionary == oldDict)
				config->value.objectDictionary = newDict;
			break;
	}
}

/* ----------------
 * Text Search Configuration Map Memory Management
 * ----------------
 */

/*
 * Move a FTS configuration expression to another memory context
 */
static TSMapElement *
TSMapExpressionMoveToMemoryContext(TSMapExpression *expression, MemoryContext context)
{
	TSMapElement *result = MemoryContextAlloc(context, sizeof(TSMapElement));
	TSMapExpression *resultExpression = MemoryContextAlloc(context, sizeof(TSMapExpression));

	memset(resultExpression, 0, sizeof(TSMapExpression));
	result->value.objectExpression = resultExpression;
	result->type = TSMAP_EXPRESSION;

	resultExpression->operator = expression->operator;

	resultExpression->left = TSMapMoveToMemoryContext(expression->left, context);
	resultExpression->left->parent = result;

	resultExpression->right = TSMapMoveToMemoryContext(expression->right, context);
	resultExpression->right->parent = result;

	return result;
}

/*
 * Move a FTS configuration case to another memory context
 */
static TSMapElement *
TSMapCaseMoveToMemoryContext(TSMapCase *caseObject, MemoryContext context)
{
	TSMapElement *result = MemoryContextAlloc(context, sizeof(TSMapElement));
	TSMapCase  *resultCaseObject = MemoryContextAlloc(context, sizeof(TSMapCase));

	memset(resultCaseObject, 0, sizeof(TSMapCase));
	result->value.objectCase = resultCaseObject;
	result->type = TSMAP_CASE;

	resultCaseObject->match = caseObject->match;

	resultCaseObject->command = TSMapMoveToMemoryContext(caseObject->command, context);
	resultCaseObject->command->parent = result;

	resultCaseObject->condition = TSMapMoveToMemoryContext(caseObject->condition, context);
	resultCaseObject->condition->parent = result;

	if (caseObject->elsebranch != NULL)
	{
		resultCaseObject->elsebranch = TSMapMoveToMemoryContext(caseObject->elsebranch, context);
		resultCaseObject->elsebranch->parent = result;
	}

	return result;
}

/*
 * Move a FTS configuration to another memory context
 */
TSMapElement *
TSMapMoveToMemoryContext(TSMapElement *config, MemoryContext context)
{
	TSMapElement *result = NULL;

	switch (config->type)
	{
		case TSMAP_EXPRESSION:
			result = TSMapExpressionMoveToMemoryContext(config->value.objectExpression, context);
			break;
		case TSMAP_CASE:
			result = TSMapCaseMoveToMemoryContext(config->value.objectCase, context);
			break;
		case TSMAP_DICTIONARY:
			result = MemoryContextAlloc(context, sizeof(TSMapElement));
			result->type = TSMAP_DICTIONARY;
			result->value.objectDictionary = config->value.objectDictionary;
			break;
		case TSMAP_KEEP:
			result = MemoryContextAlloc(context, sizeof(TSMapElement));
			result->type = TSMAP_KEEP;
			result->value.object = NULL;
			break;
		default:
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("text search configuration is invalid"),
					 errdetail("Text search configuration contains object with invalid type.")));
			break;
	}

	return result;
}

/*
 * Free memory occupied by FTS configuration expression
 */
static void
TSMapExpressionFree(TSMapExpression *expression)
{
	if (expression->left)
		TSMapElementFree(expression->left);
	if (expression->right)
		TSMapElementFree(expression->right);
	pfree(expression);
}

/*
 * Free memory occupied by FTS configuration case
 */
static void
TSMapCaseFree(TSMapCase *caseObject)
{
	TSMapElementFree(caseObject->condition);
	TSMapElementFree(caseObject->command);
	TSMapElementFree(caseObject->elsebranch);
	pfree(caseObject);
}

/*
 * Free memory occupied by FTS configuration element
 */
void
TSMapElementFree(TSMapElement *element)
{
	if (element != NULL)
	{
		switch (element->type)
		{
			case TSMAP_CASE:
				TSMapCaseFree(element->value.objectCase);
				break;
			case TSMAP_EXPRESSION:
				TSMapExpressionFree(element->value.objectExpression);
				break;
		}
		pfree(element);
	}
}

/*
 * Do a deep comparison of two TSMapElements. Doesn't check parents of elements
 */
bool
TSMapElementEquals(TSMapElement *a, TSMapElement *b)
{
	bool		result = true;

	if (a->type == b->type)
	{
		switch (a->type)
		{
			case TSMAP_CASE:
				if (!TSMapElementEquals(a->value.objectCase->condition, b->value.objectCase->condition))
					result = false;
				if (!TSMapElementEquals(a->value.objectCase->command, b->value.objectCase->command))
					result = false;

				if (a->value.objectCase->elsebranch != NULL && b->value.objectCase->elsebranch != NULL)
				{
					if (!TSMapElementEquals(a->value.objectCase->elsebranch, b->value.objectCase->elsebranch))
						result = false;
				}
				else if (a->value.objectCase->elsebranch != NULL || b->value.objectCase->elsebranch != NULL)
					result = false;

				if (a->value.objectCase->match != b->value.objectCase->match)
					result = false;
				break;
			case TSMAP_EXPRESSION:
				if (!TSMapElementEquals(a->value.objectExpression->left, b->value.objectExpression->left))
					result = false;
				if (!TSMapElementEquals(a->value.objectExpression->right, b->value.objectExpression->right))
					result = false;
				if (a->value.objectExpression->operator != b->value.objectExpression->operator)
					result = false;
				break;
			case TSMAP_DICTIONARY:
				result = a->value.objectDictionary == b->value.objectDictionary;
				break;
			case TSMAP_KEEP:
				result = true;
		}
	}
	else
		result = false;

	return result;
}
