/*-------------------------------------------------------------------------
 *
 * ts_utils.c
 *		various support functions
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/tsearch/ts_utils.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include <ctype.h>

#include "miscadmin.h"
#include "tsearch/ts_locale.h"
#include "tsearch/ts_utils.h"
#include "catalog/indexing.h"
#include "catalog/pg_ts_config_map.h"
#include "catalog/pg_ts_dict.h"
#include "storage/lockdefs.h"
#include "access/heapam.h"
#include "access/genam.h"
#include "access/htup_details.h"
#include "access/sysattr.h"
#include "utils/fmgroids.h"
#include "utils/builtins.h"
#include "tsearch/ts_cache.h"

/*
 * Used during the parsing of TSMapRuleList from JSONB into internal
 * datastructures.
 */
typedef enum TSMapRuleParseState {
	TSMRPS_BEGINING,
	TSMRPS_IN_CASES_ARRAY,
	TSMRPS_IN_CASE,
	TSMRPS_IN_CONDITION,
	TSMRPS_IN_COMMAND,
	TSMRPS_IN_EXPRESSION
} TSMapRuleParseState;

typedef enum TSMapRuleParseNodeType {
	TSMRPT_UNKNOWN,
	TSMRPT_NUMERIC,
	TSMRPT_EXPRESSION,
	TSMRPT_RULE_LIST,
	TSMRPT_RULE,
	TSMRPT_COMMAND,
	TSMRPT_CONDITION,
	TSMRPT_BOOL
} TSMapRuleParseNodeType;

typedef struct TSMapParseNode {
	TSMapRuleParseNodeType type;
	union {
		int					num_val;
		TSMapExpression	   *expression_val;
		TSMapRuleList	   *rule_list_val;
		TSMapRule		   *rule_val;
		TSMapCommand	   *command_val;
		TSMapCondition	   *condition_val;
		bool				bool_val;
	};
} TSMapParseNode;

static JsonbValue *
TSMapToJsonbValue(TSMapRuleList *rules, JsonbParseState *jsonb_state);
static TSMapParseNode *
JsonbToTSMapParse(JsonbContainer *root, TSMapRuleParseState *parse_state);

/*
 * Given the base name and extension of a tsearch config file, return
 * its full path name.  The base name is assumed to be user-supplied,
 * and is checked to prevent pathname attacks.  The extension is assumed
 * to be safe.
 *
 * The result is a palloc'd string.
 */
char *
get_tsearch_config_filename(const char *basename,
							const char *extension)
{
	char		sharepath[MAXPGPATH];
	char	   *result;

	/*
	 * We limit the basename to contain a-z, 0-9, and underscores.  This may
	 * be overly restrictive, but we don't want to allow access to anything
	 * outside the tsearch_data directory, so for instance '/' *must* be
	 * rejected, and on some platforms '\' and ':' are risky as well. Allowing
	 * uppercase might result in incompatible behavior between case-sensitive
	 * and case-insensitive filesystems, and non-ASCII characters create other
	 * interesting risks, so on the whole a tight policy seems best.
	 */
	if (strspn(basename, "abcdefghijklmnopqrstuvwxyz0123456789_") != strlen(basename))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("invalid text search configuration file name \"%s\"",
						basename)));

	get_share_path(my_exec_path, sharepath);
	result = palloc(MAXPGPATH);
	snprintf(result, MAXPGPATH, "%s/tsearch_data/%s.%s",
			 sharepath, basename, extension);

	return result;
}

/*
 * Reads a stop-word file. Each word is run through 'wordop'
 * function, if given.  wordop may either modify the input in-place,
 * or palloc a new version.
 */
void
readstoplist(const char *fname, StopList *s, char *(*wordop) (const char *))
{
	char	  **stop = NULL;

	s->len = 0;
	if (fname && *fname)
	{
		char	   *filename = get_tsearch_config_filename(fname, "stop");
		tsearch_readline_state trst;
		char	   *line;
		int			reallen = 0;

		if (!tsearch_readline_begin(&trst, filename))
			ereport(ERROR,
					(errcode(ERRCODE_CONFIG_FILE_ERROR),
					 errmsg("could not open stop-word file \"%s\": %m",
							filename)));

		while ((line = tsearch_readline(&trst)) != NULL)
		{
			char	   *pbuf = line;

			/* Trim trailing space */
			while (*pbuf && !t_isspace(pbuf))
				pbuf += pg_mblen(pbuf);
			*pbuf = '\0';

			/* Skip empty lines */
			if (*line == '\0')
			{
				pfree(line);
				continue;
			}

			if (s->len >= reallen)
			{
				if (reallen == 0)
				{
					reallen = 64;
					stop = (char **) palloc(sizeof(char *) * reallen);
				}
				else
				{
					reallen *= 2;
					stop = (char **) repalloc((void *) stop,
											  sizeof(char *) * reallen);
				}
			}

			if (wordop)
			{
				stop[s->len] = wordop(line);
				if (stop[s->len] != line)
					pfree(line);
			}
			else
				stop[s->len] = line;

			(s->len)++;
		}

		tsearch_readline_end(&trst);
		pfree(filename);
	}

	s->stop = stop;

	/* Sort to allow binary searching */
	if (s->stop && s->len > 0)
		qsort(s->stop, s->len, sizeof(char *), pg_qsort_strcmp);
}

bool
searchstoplist(StopList *s, char *key)
{
	return (s->stop && s->len > 0 &&
			bsearch(&key, s->stop, s->len,
					sizeof(char *), pg_qsort_strcmp)) ? true : false;
}

Datum
dictionary_pipe_to_text(PG_FUNCTION_ARGS)
{
	PG_RETURN_NULL();
}

static JsonbValue *
TSIntToJsonbValue(int int_value)
{
	char			buffer[16];
	JsonbValue	   *value = palloc0(sizeof(JsonbValue));

	memset(buffer, 0, sizeof(char) * 16);

	pg_ltoa(int_value, buffer);
	value->type = jbvNumeric;
	value->val.numeric = DatumGetNumeric(DirectFunctionCall3(
														  numeric_in,
														  CStringGetDatum(buffer),
														  ObjectIdGetDatum(InvalidOid),
														  Int32GetDatum(-1)
														  ));
	return value;

}

static JsonbValue *
TSExpressionToJsonb(TSMapExpression *expression, JsonbParseState *jsonb_state)
{
	if (expression == NULL)
		return NULL;
	if (expression->dictionary != InvalidOid)
	{
		JsonbValue		key;
		JsonbValue	   *value = NULL;

		pushJsonbValue(&jsonb_state, WJB_BEGIN_OBJECT, NULL);

		key.type = jbvString;
		key.val.string.len = strlen("options");
		key.val.string.val = "options";
		value = TSIntToJsonbValue(expression->options);

		pushJsonbValue(&jsonb_state, WJB_KEY, &key);
		pushJsonbValue(&jsonb_state, WJB_VALUE, value);

		key.type = jbvString;
		key.val.string.len = strlen("dictionary");
		key.val.string.val = "dictionary";
		value = TSIntToJsonbValue(expression->dictionary);

		pushJsonbValue(&jsonb_state, WJB_KEY, &key);
		pushJsonbValue(&jsonb_state, WJB_VALUE, value);

		return pushJsonbValue(&jsonb_state, WJB_END_OBJECT, NULL);
	}
	else if (expression->is_true)
	{
		JsonbValue *value = palloc0(sizeof(JsonbValue));
		value->type = jbvBool;
		value->val.boolean = true;
		return value;
	}
	else
	{
		JsonbValue		key;
		JsonbValue	   *value = NULL;

		pushJsonbValue(&jsonb_state, WJB_BEGIN_OBJECT, NULL);

		key.type = jbvString;
		key.val.string.len = strlen("operator");
		key.val.string.val = "operator";
		value = TSIntToJsonbValue(expression->operator);

		pushJsonbValue(&jsonb_state, WJB_KEY, &key);
		pushJsonbValue(&jsonb_state, WJB_VALUE, value);

		key.type = jbvString;
		key.val.string.len = strlen("options");
		key.val.string.val = "options";
		value = TSIntToJsonbValue(expression->options);

		pushJsonbValue(&jsonb_state, WJB_KEY, &key);
		pushJsonbValue(&jsonb_state, WJB_VALUE, value);

		key.type = jbvString;
		key.val.string.len = strlen("left");
		key.val.string.val = "left";

		pushJsonbValue(&jsonb_state, WJB_KEY, &key);
		value = TSExpressionToJsonb(expression->left, jsonb_state);
		if (value && IsAJsonbScalar(value))
			pushJsonbValue(&jsonb_state, WJB_VALUE, value);

		key.type = jbvString;
		key.val.string.len = strlen("right");
		key.val.string.val = "right";

		pushJsonbValue(&jsonb_state, WJB_KEY, &key);
		value = TSExpressionToJsonb(expression->right, jsonb_state);
		if (value && IsAJsonbScalar(value))
			pushJsonbValue(&jsonb_state, WJB_VALUE, value);

		return pushJsonbValue(&jsonb_state, WJB_END_OBJECT, NULL);
	}
}

static JsonbValue *
TSRuleToJsonbValue(TSMapRule *rule, JsonbParseState *jsonb_state)
{
	if (rule->dictionary != InvalidOid)
	{
		return TSIntToJsonbValue(rule->dictionary);
	}
	else
	{
		JsonbValue		key;
		JsonbValue	   *value = NULL;

		pushJsonbValue(&jsonb_state, WJB_BEGIN_OBJECT, NULL);

		key.type = jbvString;
		key.val.string.len = strlen("condition");
		key.val.string.val = "condition";

		pushJsonbValue(&jsonb_state, WJB_KEY, &key);
		value = TSExpressionToJsonb(rule->condition.expression, jsonb_state);

		if (IsAJsonbScalar(value))
			pushJsonbValue(&jsonb_state, WJB_VALUE, value);

		key.type = jbvString;
		key.val.string.len = strlen("command");
		key.val.string.val = "command";

		pushJsonbValue(&jsonb_state, WJB_KEY, &key);
		if (rule->command.is_expression)
			value = TSExpressionToJsonb(rule->command.expression, jsonb_state);
		else
			value = TSMapToJsonbValue(rule->command.ruleList, jsonb_state);

		if (IsAJsonbScalar(value))
			pushJsonbValue(&jsonb_state, WJB_VALUE, value);

		return pushJsonbValue(&jsonb_state, WJB_END_OBJECT, NULL);
	}
}

static JsonbValue *
TSMapToJsonbValue(TSMapRuleList *rules, JsonbParseState *jsonb_state)
{
	JsonbValue	   *out;
	int				i;

	pushJsonbValue(&jsonb_state, WJB_BEGIN_ARRAY, NULL);
	for (i = 0; i < rules->count; i++)
	{
		JsonbValue *value = TSRuleToJsonbValue(&rules->data[i], jsonb_state);
		if (IsAJsonbScalar(value))
			pushJsonbValue(&jsonb_state, WJB_ELEM, value);
	}
	out = pushJsonbValue(&jsonb_state, WJB_END_ARRAY, NULL);
	return out;
}

Jsonb *
TSMapToJsonb(TSMapRuleList *rules)
{
	JsonbParseState *jsonb_state = NULL;
	JsonbValue	   *out;
	Jsonb		   *result;

	out = TSMapToJsonbValue(rules, jsonb_state);

	result = JsonbValueToJsonb(out);
	return result;
}

static inline TSMapExpression *
JsonbToTSMapGetExpression(TSMapParseNode *node)
{
	TSMapExpression *result;
	if (node->type == TSMRPT_NUMERIC)
	{
		result = palloc0(sizeof(TSMapExpression));
		result->dictionary = node->num_val;
	}
	else if (node->type == TSMRPT_BOOL)
	{
		result = palloc0(sizeof(TSMapExpression));
		result->is_true = node->bool_val;
	}
	else
		result = node->expression_val;

	pfree(node);

	return result;
}

static TSMapParseNode *
JsonbToTSMapParseObject(JsonbValue *value, TSMapRuleParseState *parse_state)
{
	TSMapParseNode	   *result = palloc0(sizeof(TSMapParseNode));
	char			   *str;
	switch (value->type)
	{
		case jbvNumeric:
			result->type = TSMRPT_NUMERIC;
			str = DatumGetCString(
					DirectFunctionCall1(numeric_out, NumericGetDatum(value->val.numeric)));
			result->num_val = pg_atoi(str, sizeof(result->num_val), 0);
			break;
		case jbvArray:
			Assert(*parse_state == TSMRPS_IN_COMMAND);
		case jbvBinary:
			result = JsonbToTSMapParse(value->val.binary.data, parse_state);
			break;
		case jbvBool:
			result->type = TSMRPT_BOOL;
			result->bool_val = value->val.boolean;
			break;
		case jbvObject:
		case jbvNull:
		case jbvString:
			break;
	}
	return result;
}

static TSMapParseNode *
JsonbToTSMapParse(JsonbContainer *root, TSMapRuleParseState *parse_state)
{
	JsonbIteratorToken r;
	JsonbValue		val;
	JsonbIterator  *it;
	TSMapParseNode *result;
	TSMapParseNode *nested_result;
	char		   *key;
	TSMapRuleList  *rule_list = NULL;

	it = JsonbIteratorInit(root);
	result = palloc0(sizeof(TSMapParseNode));
	result->type = TSMRPT_UNKNOWN;
	while ((r = JsonbIteratorNext(&it, &val, true)) != WJB_DONE)
	{
		switch (r)
		{
			case WJB_BEGIN_ARRAY:
				if (*parse_state == TSMRPS_BEGINING || *parse_state == TSMRPS_IN_EXPRESSION)
				{
					*parse_state = TSMRPS_IN_CASES_ARRAY;
					rule_list = palloc0(sizeof(TSMapRuleList));
				}
				break;
			case WJB_KEY:
				key = palloc0(sizeof(char) * (val.val.string.len + 1));
				memcpy(key, val.val.string.val, sizeof(char) * val.val.string.len);

				r = JsonbIteratorNext(&it, &val, true);
				if (*parse_state == TSMRPS_IN_CASE)
				{
					if (strcmp(key, "command") == 0)
						*parse_state = TSMRPS_IN_EXPRESSION;
					else if (strcmp(key, "condition") == 0)
						*parse_state = TSMRPS_IN_EXPRESSION;
				}

				nested_result = JsonbToTSMapParseObject(&val, parse_state);

				if (result->type == TSMRPT_RULE)
				{
					if (strcmp(key, "command") == 0)
					{
						result->rule_val->command.is_expression = nested_result->type == TSMRPT_EXPRESSION ||
															nested_result->type == TSMRPT_NUMERIC;

						if (result->rule_val->command.is_expression)
							result->rule_val->command.expression = JsonbToTSMapGetExpression(nested_result);
						else
							result->rule_val->command.ruleList = nested_result->rule_list_val;
					}
					else if (strcmp(key, "condition") == 0)
					{
						result->rule_val->condition.expression = JsonbToTSMapGetExpression(nested_result);
					}
					*parse_state = TSMRPS_IN_CASE;
				}
				else if (result->type == TSMRPT_COMMAND)
				{
					result->command_val->is_expression = nested_result->type == TSMRPT_EXPRESSION;
					if (result->command_val->is_expression)
						result->command_val->expression = JsonbToTSMapGetExpression(nested_result);
					else
						result->command_val->ruleList = nested_result->rule_list_val;
					*parse_state = TSMRPS_IN_COMMAND;
				}
				else if (result->type == TSMRPT_CONDITION)
				{
					result->condition_val->expression = JsonbToTSMapGetExpression(nested_result);
					*parse_state = TSMRPS_IN_COMMAND;
				}
				else if (result->type == TSMRPT_EXPRESSION)
				{
					if (strcmp(key, "left") == 0)
						result->expression_val->left = JsonbToTSMapGetExpression(nested_result);
					else if (strcmp(key, "right") == 0)
						result->expression_val->right = JsonbToTSMapGetExpression(nested_result);
					else if (strcmp(key, "operator") == 0)
						result->expression_val->operator = nested_result->num_val;
					else if (strcmp(key, "options") == 0)
						result->expression_val->options = nested_result->num_val;
					else if (strcmp(key, "dictionary") == 0)
						result->expression_val->dictionary = nested_result->num_val;
				}

				break;
			case WJB_BEGIN_OBJECT:
				if (*parse_state == TSMRPS_IN_CASES_ARRAY)
				{
					*parse_state = TSMRPS_IN_CASE;
					result->type = TSMRPT_RULE;
					result->rule_val = palloc0(sizeof(TSMapRule));
				}
				else if (*parse_state == TSMRPS_IN_COMMAND)
				{
					result->type = TSMRPT_COMMAND;
					result->command_val = palloc0(sizeof(TSMapCommand));
				}
				else if (*parse_state == TSMRPS_IN_CONDITION)
				{
					result->type = TSMRPT_CONDITION;
					result->condition_val = palloc0(sizeof(TSMapCondition));
				}
				else if (*parse_state == TSMRPS_IN_EXPRESSION)
				{
					result->type = TSMRPT_EXPRESSION;
					result->expression_val = palloc0(sizeof(TSMapExpression));
				}
				break;
			case WJB_END_OBJECT:
				if (*parse_state == TSMRPS_IN_CASE)
					*parse_state = TSMRPS_IN_CASES_ARRAY;
				else if (*parse_state == TSMRPS_IN_CONDITION || *parse_state == TSMRPS_IN_COMMAND)
					*parse_state = TSMRPS_IN_CASE;
				if (rule_list && result->type == TSMRPT_RULE)
				{
					rule_list->count++;
					if (rule_list->data)
						rule_list->data = repalloc(rule_list->data, sizeof(TSMapRule) * rule_list->count);
					else
						rule_list->data = palloc0(sizeof(TSMapRule) * rule_list->count);
					memcpy(rule_list->data + rule_list->count - 1, result->rule_val, sizeof(TSMapRule));
				}
				else
					return result;
			case WJB_END_ARRAY:
				break;
			default:
				nested_result = JsonbToTSMapParseObject(&val, parse_state);
				if (nested_result->type == TSMRPT_NUMERIC)
				{
					if (*parse_state == TSMRPS_IN_CASES_ARRAY)
					{
						/* Add dictionary Oid into array (comma-separated configuration) */
						rule_list->count++;
						if (rule_list->data)
							rule_list->data = repalloc(rule_list->data, sizeof(TSMapRule) * rule_list->count);
						else
							rule_list->data = palloc0(sizeof(TSMapRule) * rule_list->count);
						memset(rule_list->data + rule_list->count - 1, 0, sizeof(TSMapRule));
						rule_list->data[rule_list->count - 1].dictionary = nested_result->num_val;
					}
					else if (result->type == TSMRPT_UNKNOWN && *parse_state == TSMRPS_IN_EXPRESSION)
					{
						result->type = TSMRPT_EXPRESSION;
						result->expression_val = palloc0(sizeof(TSMapExpression));
					}
					if (result->type == TSMRPT_EXPRESSION)
						result->expression_val->dictionary = nested_result->num_val;
				}
				else if (nested_result->type == TSMRPT_RULE && rule_list)
				{
					rule_list->count++;
					if (rule_list->data)
						rule_list->data = repalloc(rule_list->data, sizeof(TSMapRule) * rule_list->count);
					else
						rule_list->data = palloc0(sizeof(TSMapRule) * rule_list->count);
					memcpy(rule_list->data + rule_list->count - 1, nested_result->rule_val, sizeof(TSMapRule));
				}
				break;
		}
	}
	result->type = TSMRPT_RULE_LIST;
	result->rule_list_val = rule_list;
	return result;
}

TSMapRuleList *
JsonbToTSMap(Jsonb *json)
{
	JsonbContainer *root = &json->root;
	TSMapRuleList  *result = palloc0(sizeof(TSMapRuleList));
	TSMapRuleParseState parse_state = TSMRPS_BEGINING;
	TSMapParseNode *parsing_result;

	parsing_result = JsonbToTSMapParse(root, &parse_state);

	Assert(parsing_result->type == TSMRPT_RULE_LIST);
	result = parsing_result->rule_list_val;
	pfree(parsing_result);

	return result;
}

static void
TSMapReplaceDictionaryParseExpression(TSMapExpression *expr, Oid oldDict, Oid newDict)
{
	if (expr->left)
		TSMapReplaceDictionaryParseExpression(expr->left, oldDict, newDict);
	if (expr->right)
		TSMapReplaceDictionaryParseExpression(expr->right, oldDict, newDict);

	if (expr->dictionary == oldDict)
		expr->dictionary = newDict;
}

static void
TSMapReplaceDictionaryParseMap(TSMapRule *rule, Oid oldDict, Oid newDict)
{
	if (rule->dictionary != InvalidOid)
	{
		Oid *result;
		result = palloc0(sizeof(Oid) * 2);
		result[0] = rule->dictionary;
		result[1] = InvalidOid;
	}
	else
	{
		TSMapReplaceDictionaryParseExpression(rule->condition.expression, oldDict, newDict);

		if (rule->command.is_expression)
			TSMapReplaceDictionaryParseExpression(rule->command.expression, oldDict, newDict);
		else
			TSMapReplaceDictionary(rule->command.ruleList, oldDict, newDict);
	}
}

void
TSMapReplaceDictionary(TSMapRuleList *rules, Oid oldDict, Oid newDict)
{
	int i;

	for (i = 0; i < rules->count; i++)
		TSMapReplaceDictionaryParseMap(&rules->data[i], oldDict, newDict);
}

static Oid *
TSMapGetDictionariesParseExpression(TSMapExpression *expr)
{
	Oid *left_res;
	Oid *right_res;
	Oid *result;

	left_res = right_res = NULL;

	if (expr->left && expr->right)
	{
		Oid *ptr;
		int count_l;
		int count_r;

		left_res = TSMapGetDictionariesParseExpression(expr->left);
		right_res = TSMapGetDictionariesParseExpression(expr->right);

		for (ptr = left_res, count_l = 0; *ptr != InvalidOid; count_l++, ptr++)
			/* EMPTY */ ;
		for (ptr = right_res, count_r = 0; *ptr != InvalidOid; count_r++, ptr++)
			/* EMPTY */ ;

		result = palloc0(sizeof(Oid) * (count_l + count_r + 1));
		memcpy(result, left_res, sizeof(Oid) * count_l);
		memcpy(result + count_l, right_res, sizeof(Oid) * count_r);
		result[count_l + count_r] = InvalidOid;

		pfree(left_res);
		pfree(right_res);
	}
	else
	{
		result = palloc0(sizeof(Oid) * 2);
		result[0] = expr->dictionary;
		result[1] = InvalidOid;
	}

	return result;
}

static Oid *
TSMapGetDictionariesParseRule(TSMapRule *rule)
{
	Oid *result;

	if (rule->dictionary)
	{
		result = palloc0(sizeof(Oid) * 2);
		result[0] = rule->dictionary;
		result[1] = InvalidOid;
	}
	else
	{
		if (rule->command.is_expression)
			result = TSMapGetDictionariesParseExpression(rule->command.expression);
		else
			result = TSMapGetDictionariesList(rule->command.ruleList);
	}
	return result;
}

Oid *
TSMapGetDictionariesList(TSMapRuleList *rules)
{
	int		i;
	Oid	  **results_arr;
	int	   *sizes;
	Oid	   *result;
	int		size;
	int		offset;

	results_arr = palloc0(sizeof(Oid*) * rules->count);
	sizes = palloc0(sizeof(int) * rules->count);
	size = 0;
	for (i = 0; i < rules->count; i++)
	{
		int count;
		Oid *ptr;

		results_arr[i] = TSMapGetDictionariesParseRule(&rules->data[i]);

		for (count = 0, ptr = results_arr[i]; *ptr != InvalidOid; count++, ptr++)
			/* EMPTY */ ;

		sizes[i] = count;
		size += count;
	}

	result = palloc(sizeof(Oid) * (size + 1));
	offset = 0;
	for (i = 0; i < rules->count; i++)
	{
		memcpy(result + offset, results_arr[i], sizeof(Oid) * sizes[i]);
		offset += sizes[i];
		pfree(results_arr[i]);
	}
	result[offset] = InvalidOid;

	pfree(results_arr);
	pfree(sizes);

	return result;
}

ListDictionary *
TSMapGetListDictionary(TSMapRuleList *rules)
{
	ListDictionary *result = palloc0(sizeof(ListDictionary));
	Oid			   *oids = TSMapGetDictionariesList(rules);
	int				i;
	int				count;
	Oid			   *ptr;

	ptr = oids;
	count = 0;
	while (*ptr != InvalidOid)
	{
		count++;
		ptr++;
	}

	result->len = count;
	result->dictIds = palloc0(sizeof(Oid) * result->len);
	ptr = oids;
	i = 0;
	while (*ptr != InvalidOid)
		result->dictIds[i++] = *(ptr++);

	return result;
}

static TSMapExpression *
TSMapExpressionMoveToMemoryContext(TSMapExpression *expr, MemoryContext context)
{
	TSMapExpression *result;
	if (expr == NULL)
		return NULL;
	result = MemoryContextAlloc(context, sizeof(TSMapExpression));
	memset(result, 0, sizeof(TSMapExpression));
	if (expr->dictionary != InvalidOid || expr->is_true)
	{
		result->dictionary = expr->dictionary;
		result->is_true = expr->is_true;
		result->options = expr->options;
		result->left = result->right = NULL;
		result->operator = 0;
	}
	else
	{
		result->left = TSMapExpressionMoveToMemoryContext(expr->left, context);
		result->right = TSMapExpressionMoveToMemoryContext(expr->right, context);
		result->operator = expr->operator;
		result->options = expr->options;
		result->dictionary = InvalidOid;
		result->is_true = false;
	}
	return result;
}

static TSMapRule
TSMapRuleMoveToMemoryContext(TSMapRule *rule, MemoryContext context)
{
	TSMapRule result;
	memset(&result, 0, sizeof(TSMapRule));

	if (rule->dictionary)
	{
		result.dictionary = rule->dictionary;
	}
	else
	{
		result.condition.expression = TSMapExpressionMoveToMemoryContext(rule->condition.expression, context);

		result.command.is_expression = rule->command.is_expression;
		if (rule->command.is_expression)
			result.command.expression = TSMapExpressionMoveToMemoryContext(rule->command.expression, context);
		else
			result.command.ruleList = TSMapMoveToMemoryContext(rule->command.ruleList, context);
	}

	return result;
}

TSMapRuleList *
TSMapMoveToMemoryContext(TSMapRuleList *rules, MemoryContext context)
{
	int				i;
	TSMapRuleList  *result = MemoryContextAlloc(context, sizeof(TSMapRuleList));

	memset(result, 0, sizeof(TSMapRuleList));

	result->count = rules->count;
	result->data = MemoryContextAlloc(context, sizeof(TSMapRule) * result->count);

	for (i = 0; i < result->count; i++)
		result->data[i] = TSMapRuleMoveToMemoryContext(&rules->data[i], context);

	return result;
}

static void
TSMapExpressionFree(TSMapExpression *expression)
{
	if (expression->left)
		TSMapExpressionFree(expression->left);
	if (expression->right)
		TSMapExpressionFree(expression->right);
	pfree(expression);
}

static void
TSMapRuleFree(TSMapRule rule)
{
	if (rule.dictionary == InvalidOid)
	{
		if (rule.command.is_expression)
			TSMapExpressionFree(rule.command.expression);
		else
			TSMapFree(rule.command.ruleList);

		TSMapExpressionFree(rule.condition.expression);
	}
}

void
TSMapFree(TSMapRuleList *rules)
{
	int i;
	for (i = 0; i < rules->count; i++)
		TSMapRuleFree(rules->data[i]);
	pfree(rules->data);
	pfree(rules);
}

