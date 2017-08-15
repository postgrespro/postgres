/*-------------------------------------------------------------------------
 *
 * ts_parse.c
 *		main parse functions for tsearch
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/tsearch/ts_parse.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "tsearch/ts_cache.h"
#include "tsearch/ts_utils.h"
#include "catalog/pg_ts_config_map.h"

#define IGNORE_LONGLEXEME	1

/*
 * Lexize subsystem
 */

typedef struct ParsedLex
{
	int			type;
	char	   *lemm;
	int			lenlemm;
	int			maplen;
	bool	   *accepted;
	bool	   *rejected;
	bool	   *notFinished;
	bool	   *holdAccepted;
	struct ParsedLex *next;
} ParsedLex;

typedef struct ListParsedLex
{
	ParsedLex  *head;
	ParsedLex  *tail;
} ListParsedLex;

typedef struct DictState
{
	Oid				relatedDictionary;
	DictSubState	subState;
	ListParsedLex	acceptedTokens;
	ListParsedLex	intermediateTokens;
	bool			storeToAccepted;
	bool			processed;
	TSLexeme	   *tmpResult;
} DictState;

typedef struct DictStateList
{
	int			listLength;
	DictState  *states;
} DictStateList;

typedef struct LexemesBufferEntry
{
	Oid			dictId;
	ParsedLex  *token;
	TSLexeme   *data;
} LexemesBufferEntry;

typedef struct LexemesBuffer
{
	int					size;
	LexemesBufferEntry *data;
} LexemesBuffer;

typedef struct ResultStorage
{
	TSLexeme	   *lexemes;
	TSLexeme	   *accepted;
} ResultStorage;

typedef struct
{
	TSConfigCacheEntry *cfg;
	Oid			curDictId;
	int			posDict;
	DictSubState dictState;
	ParsedLex  *curSub;
	DictStateList dslist;
	ListParsedLex towork;		/* current list to work */
	ListParsedLex waste;		/* list of lexemes that already lexized */
	LexemesBuffer buffer;
	ResultStorage delayedResults;
	Oid			skipDictionary;

	/*
	 * field to store last variant to lexize (basically, thesaurus or similar
	 * to, which wants	several lexemes
	 */
	TSLexeme   *tmpRes;
} LexizeData;

static TSLexeme *LexizeExecMapBy(LexizeData *ld, ParsedLex *token, TSMapExpression *left, TSMapExpression *right);

static void
LexizeInit(LexizeData *ld, TSConfigCacheEntry *cfg)
{
	ld->cfg = cfg;
	ld->curDictId = InvalidOid;
	ld->posDict = 0;
	ld->skipDictionary = InvalidOid;
	ld->towork.head = ld->towork.tail = ld->curSub = NULL;
	ld->waste.head = ld->waste.tail = NULL;
	ld->tmpRes = NULL;
	ld->dslist.listLength = 0;
	ld->dslist.states = NULL;
	ld->buffer.size = 0;
	ld->buffer.data = NULL;
	ld->delayedResults.lexemes = NULL;
	ld->delayedResults.accepted = NULL;
}

static void
LPLAddTail(ListParsedLex *list, ParsedLex *newpl)
{
	if (list->tail)
	{
		list->tail->next = newpl;
		list->tail = newpl;
	}
	else
		list->head = list->tail = newpl;
	newpl->next = NULL;
}

static void
LPLAddTailCopy(ListParsedLex *list, ParsedLex *newpl)
{
	ParsedLex *copy = palloc0(sizeof(ParsedLex));
	copy->lenlemm = newpl->lenlemm;
	copy->type = newpl->type;
	copy->lemm = newpl->lemm;
	copy->next = NULL;

	if (list->tail)
	{
		list->tail->next = copy;
		list->tail = copy;
	}
	else
		list->head = list->tail = copy;
}

static ParsedLex *
LPLRemoveHead(ListParsedLex *list)
{
	ParsedLex  *res = list->head;

	if (list->head)
		list->head = list->head->next;

	if (list->head == NULL)
		list->tail = NULL;

	return res;
}

static void
LexizeAddLemm(LexizeData *ld, int type, char *lemm, int lenlemm)
{
	ParsedLex  *newpl = (ParsedLex *) palloc(sizeof(ParsedLex));
	int len;

	if (type != 0 && (type >= ld->cfg->lenmap))
	{
		len = 1;
	}
	else
	{
		ListDictionary	   *map = ld->cfg->map + type;
		len = map->len;
	}

	newpl->type = type;
	newpl->lemm = lemm;
	newpl->lenlemm = lenlemm;
	newpl->maplen = len;
	newpl->accepted = palloc0(sizeof(bool) * len);
	newpl->rejected = palloc0(sizeof(bool) * len);
	newpl->notFinished = palloc0(sizeof(bool) * len);
	newpl->holdAccepted = palloc0(sizeof(bool) * len);
	LPLAddTail(&ld->towork, newpl);
	ld->curSub = ld->towork.tail;
}

static void
RemoveHead(LexizeData *ld)
{
	LPLAddTail(&ld->waste, LPLRemoveHead(&ld->towork));

	ld->posDict = 0;
}

static void
setCorrLex(LexizeData *ld, ParsedLex **correspondLexem)
{
	if (correspondLexem)
	{
		*correspondLexem = ld->waste.head;
	}
	else
	{
		ParsedLex  *tmp,
				   *ptr = ld->waste.head;

		while (ptr)
		{
			tmp = ptr->next;
			pfree(ptr);
			ptr = tmp;
		}
	}
	ld->waste.head = ld->waste.tail = NULL;
}

static int
TSLexemeGetSize(TSLexeme *lexeme)
{
	int res = 0;
	while (lexeme != NULL && lexeme->lexeme)
	{
		res++;
		lexeme++;
	}
	return res;
}

static void
setNewTmpRes(LexizeData *ld, TSLexeme *res)
{
	int i;
	if (ld->tmpRes)
	{
		TSLexeme   *ptr;

		for (ptr = ld->tmpRes; ptr->lexeme; ptr++)
			pfree(ptr->lexeme);
		pfree(ld->tmpRes);
	}
	if (res == NULL)
	{
		ld->tmpRes = NULL;
		return;
	}
	ld->tmpRes = palloc0(sizeof(TSLexeme) * (TSLexemeGetSize(res) + 1));
	for (i = 0; i < TSLexemeGetSize(res); i++)
	{
		ld->tmpRes[i].flags = res[i].flags;
		ld->tmpRes[i].nvariant = res[i].nvariant;
		ld->tmpRes[i].lexeme = palloc0(sizeof(char) * (strlen(res[i].lexeme) + 1));
		memcpy(ld->tmpRes[i].lexeme, res[i].lexeme, sizeof(char) * strlen(res[i].lexeme));
	}
}

static DictState *
DictStateListGet(DictStateList *list, Oid dictId)
{
	int i;
	DictState *result = NULL;

	for (i = 0; i < list->listLength; i++)
		if (list->states[i].relatedDictionary == dictId)
			result = &list->states[i];

	return result;
}

static void
DictStateListRemove(DictStateList *list, Oid dictId)
{
	int i;

	for (i = 0; i < list->listLength; i++)
		if (list->states[i].relatedDictionary == dictId)
			break;

	if (i != list->listLength)
	{
		memcpy(list->states + i, list->states + i + 1, sizeof(DictState) * (list->listLength - i - 1));
		list->listLength--;
		if (list->listLength == 0)
			list->states = NULL;
		else
			list->states = repalloc(list->states, sizeof(DictState) * list->listLength);
	}
}

static DictState *
DictStateListAdd(DictStateList *list, DictState *state)
{
	DictStateListRemove(list, state->relatedDictionary);

	list->listLength++;
	if (list->states)
		list->states = repalloc(list->states, sizeof(DictState) * list->listLength);
	else
		list->states = palloc0(sizeof(DictState) * list->listLength);

	memcpy(list->states + list->listLength - 1, state, sizeof(DictState));

	return list->states + list->listLength - 1;
}

static void
DictStateListClear(DictStateList *list)
{
	list->listLength = 0;
	if (list->states)
		pfree(list->states);
	list->states = NULL;
}

static bool
LexemesBufferContains(LexemesBuffer *buffer, Oid dictId, ParsedLex *token)
{
	int i;

	for (i = 0; i < buffer->size; i++)
		if (buffer->data[i].dictId == dictId && buffer->data[i].token == token)
			return true;

	return false;
}

static TSLexeme *
LexemesBufferGet(LexemesBuffer *buffer, Oid dictId, ParsedLex *token)
{
	int i;
	TSLexeme *result = NULL;

	for (i = 0; i < buffer->size; i++)
		if (buffer->data[i].dictId == dictId && buffer->data[i].token == token)
			result = buffer->data[i].data;

	return result;
}

static void
LexemesBufferRemove(LexemesBuffer *buffer, Oid dictId, ParsedLex *token)
{
	int i;

	for (i = 0; i < buffer->size; i++)
		if (buffer->data[i].dictId == dictId && buffer->data[i].token == token)
			break;

	if (i != buffer->size)
	{
		memcpy(buffer->data + i, buffer->data + i + 1, sizeof(LexemesBufferEntry) * (buffer->size - i - 1));
		buffer->size--;
		if (buffer->size == 0)
			buffer->data = NULL;
		else
			buffer->data = repalloc(buffer->data, sizeof(LexemesBufferEntry) * buffer->size);
	}
}

static void
LexemesBufferAdd(LexemesBuffer *buffer, Oid dictId, ParsedLex *token, TSLexeme *data)
{
	LexemesBufferRemove(buffer, dictId, token);

	buffer->size++;
	if (buffer->data)
		buffer->data = repalloc(buffer->data, sizeof(LexemesBufferEntry) * buffer->size);
	else
		buffer->data = palloc0(sizeof(LexemesBufferEntry) * buffer->size);

	buffer->data[buffer->size - 1].token = token;
	buffer->data[buffer->size - 1].dictId = dictId;
	buffer->data[buffer->size - 1].data = data;
}

static void
LexemesBufferClear(LexemesBuffer *buffer)
{
	buffer->size = 0;
	if (buffer->data)
		pfree(buffer->data);
	buffer->data = NULL;
}

static int
TSLexemeGetSize(TSLexeme *lex)
{
	int result = 0;
	TSLexeme *ptr = lex;

	while (ptr && ptr->lexeme)
	{
		result++;
		ptr++;
	}

	return result;
}

static TSLexeme *
TSLexemeRemoveDuplications(TSLexeme *lexeme)
{
	TSLexeme	   *res;
	int				curLexIndex;
	int				i;
	int				lexemeSize = TSLexemeGetSize(lexeme);
	int				shouldCopyCount = lexemeSize;
	bool		   *shouldCopy;

	if (lexeme == NULL)
		return NULL;

	shouldCopy = palloc(sizeof(bool) * lexemeSize);
	memset(shouldCopy, true, sizeof(bool) * lexemeSize);

	for (curLexIndex = 0; curLexIndex < lexemeSize; curLexIndex++)
	{
		for (i = curLexIndex + 1; i < lexemeSize; i++)
		{
			if (!shouldCopy[i])
				continue;

			if (strcmp(lexeme[curLexIndex].lexeme, lexeme[i].lexeme) == 0)
			{
				if (lexeme[curLexIndex].nvariant == lexeme[i].nvariant)
				{
					shouldCopy[i] = false;
					shouldCopyCount--;
					continue;
				}
				else
				{
					/*
					 * Check for same set of lexemes in another nvariant series
					 */
					int		nvariantCountL = 0;
					int		nvariantCountR = 0;
					int		nvariantOverlap = 1;
					int		j;

					for (j = 0; j < lexemeSize; j++)
						if (lexeme[curLexIndex].nvariant == lexeme[j].nvariant)
							nvariantCountL++;
					for (j = 0; j < lexemeSize; j++)
						if (lexeme[i].nvariant == lexeme[j].nvariant)
							nvariantCountR++;

					if (nvariantCountL != nvariantCountR)
						continue;

					for (j = 1; j < nvariantCountR; j++)
					{
						if (strcmp(lexeme[curLexIndex + j].lexeme, lexeme[i + j].lexeme) == 0
								&& lexeme[curLexIndex + j].nvariant == lexeme[i + j].nvariant)
							nvariantOverlap++;
					}

					if (nvariantOverlap != nvariantCountR)
						continue;

					for (j = 0; j < nvariantCountR; j++)
					{
						shouldCopy[i + j] = false;
					}
				}
			}
		}
	}

	res = palloc0(sizeof(TSLexeme) * (shouldCopyCount + 1));

	for (i = 0, curLexIndex = 0; curLexIndex < lexemeSize; curLexIndex++)
	{
		if (shouldCopy[curLexIndex])
		{
			memcpy(res + i, lexeme + curLexIndex, sizeof(TSLexeme));
			i++;
		}
	}

	pfree(shouldCopy);
	pfree(lexeme);
	return res;
}

static TSLexeme *
TSLexemeUnionOpt(TSLexeme *left, TSLexeme *right, bool addposFlag)
{
	TSLexeme *result;
	int left_size = TSLexemeGetSize(left);
	int right_size = TSLexemeGetSize(right);
	int left_max_nvariant = 0;
	int i;

	// TODO: TLS_ADDPOS flag ordering
	if (left == NULL && right == NULL)
	{
		result = NULL;
	}
	else
	{

		result = palloc0(sizeof(TSLexeme) * (left_size + right_size + 1));

		for (i = 0; i < left_size; i++)
			if (left[i].nvariant > left_max_nvariant)
				left_max_nvariant = left[i].nvariant;

		if (left_size > 0)
			memcpy(result, left, sizeof(TSLexeme) * left_size);
		if (right_size > 0)
			memcpy(result + left_size, right, sizeof(TSLexeme) * right_size);
		if (addposFlag && left_size > 0 && right_size > 0)
			result[left_size].flags |= TSL_ADDPOS;

		for (i = left_size; i < left_size + right_size; i++)
			result[i].nvariant += left_max_nvariant;
	}

	return result;
}

static TSLexeme *
TSLexemeUnion(TSLexeme *left, TSLexeme *right)
{
	return TSLexemeUnionOpt(left, right, false);
}

static TSLexeme *
TSLexemeExcept(TSLexeme *left, TSLexeme *right)
{
	TSLexeme *result = NULL;
	int i, j, k;
	int left_size = TSLexemeGetSize(left);
	int right_size = TSLexemeGetSize(right);

	result = palloc0(sizeof(TSLexeme) * (left_size + 1));

	for (k = 0, i = 0; i < left_size; i++)
	{
		bool found = false;
		for (j = 0; j < right_size; j++)
		{
			if (strcmp(left[i].lexeme, right[j].lexeme) == 0)
				found = true;
		}

		if (!found)
			result[k++] = left[i];
	}

	return result;
}

static TSLexeme *
TSLexemeIntersect(TSLexeme *left, TSLexeme *right)
{
	TSLexeme *result = NULL;
	int i, j, k;
	int left_size = TSLexemeGetSize(left);
	int right_size = TSLexemeGetSize(right);

	result = palloc0(sizeof(TSLexeme) * (left_size + 1));

	for (k = 0, i = 0; i < left_size; i++)
	{
		bool found = false;
		for (j = 0; j < right_size; j++)
		{
			if (strcmp(left[i].lexeme, right[j].lexeme) == 0)
				found = true;
		}

		if (found)
			result[k++] = left[i];
	}

	return result;
}

static void
ResultStorageAdd(ResultStorage *storage, ParsedLex *token, TSLexeme *lexs)
{
	TSLexeme *oldLexs = storage->lexemes;
	storage->lexemes = TSLexemeUnionOpt(storage->lexemes, lexs, true);
	if (oldLexs)
		pfree(oldLexs);
}

static void
ResultStorageMoveToAccepted(ResultStorage *storage)
{
	if (storage->accepted)
	{
		TSLexeme *prevAccepted = storage->accepted;
		storage->accepted = TSLexemeUnionOpt(storage->accepted, storage->lexemes, true);
		if (prevAccepted)
			pfree(prevAccepted);
		if (storage->lexemes)
			pfree(storage->lexemes);
	}
	else
	{
		storage->accepted = storage->lexemes;
	}
	storage->lexemes = NULL;
}

static void
ResultStorageClearLexemes(ResultStorage *storage)
{
	if (storage->lexemes)
		pfree(storage->lexemes);
	storage->lexemes = NULL;
}

static void
ResultStorageClear(ResultStorage *storage)
{
	ResultStorageClearLexemes(storage);

	if (storage->accepted)
		pfree(storage->accepted);
	storage->accepted = NULL;
}

static TSLexeme *
LexizeExecDictionary(LexizeData *ld, ParsedLex *token, Oid dictId)
{
	TSLexeme *res;
	TSDictionaryCacheEntry *dict;
	DictSubState subState;

	if (ld->skipDictionary == dictId)
		return NULL;

	if (LexemesBufferContains(&ld->buffer, dictId, token))
	{
		res = LexemesBufferGet(&ld->buffer, dictId, token);
	}
	else
	{
		char	   *curValLemm = token->lemm;
		int			curValLenLemm = token->lenlemm;
		DictState  *state = DictStateListGet(&ld->dslist, dictId);

		dict = lookup_ts_dictionary_cache(dictId);

		if (state)
		{
			subState = state->subState;
			state->processed = true;
		}
		else
		{
			subState.isend = subState.getnext = false;
			subState.private_state = NULL;
		}

		res = (TSLexeme *) DatumGetPointer(FunctionCall4(
													 &(dict->lexize),
									 PointerGetDatum(dict->dictData),
										 PointerGetDatum(curValLemm),
										Int32GetDatum(curValLenLemm),
										  PointerGetDatum(&subState)
														 ));


		if (subState.getnext)
		{
			/*
			 * Dictionary wants next word, so store current context and state
			 * in the DictStateList
			 */
			if (state == NULL)
			{
				state = palloc0(sizeof(DictState));
				state->processed = true;
				state->relatedDictionary = dictId;
				state->intermediateTokens.head = state->intermediateTokens.tail = NULL;
				state->acceptedTokens.head = state->acceptedTokens.tail = NULL;
				state->tmpResult = NULL;
				/*
				 * Add state to the list and update pointer in order to work with
				 * copy from the list
				 */
				state = DictStateListAdd(&ld->dslist, state);
			}

			state->subState = subState;
			state->storeToAccepted = res != NULL;

			if (res)
			{
				if (state->intermediateTokens.head != NULL)
				{
					ParsedLex *ptr = state->intermediateTokens.head;
					while (ptr)
					{
						LPLAddTailCopy(&state->acceptedTokens, ptr);
						ptr = ptr->next;
					}
					state->intermediateTokens.head = state->intermediateTokens.tail = NULL;
				}

				if (state->tmpResult)
					pfree(state->tmpResult);
				state->tmpResult = res;
				res = NULL;
			}
		}
		else if (state != NULL)
		{
			if (res)
				DictStateListRemove(&ld->dslist, dictId);
			else
			{
				/*
				 * Trigger post-processing in order to check tmpResult and
				 * restart processing (see LexizeExec function)
				 */
				state->processed = false;
			}
		}
		LexemesBufferAdd(&ld->buffer, dictId, token, res);
	}

	return res;
}

static bool
LexizeExecDictionaryWaitNext(LexizeData *ld, Oid dictId)
{
	DictState *state = DictStateListGet(&ld->dslist, dictId);
	if (state)
		return state->subState.getnext;
	else
		return false;
}

static bool
LexizeExecIsNull(LexizeData *ld, ParsedLex *token, Oid dictId)
{
	TSLexeme *lexemes = LexizeExecDictionary(ld, token, dictId);
	if (lexemes)
		return false;
	else
		return !LexizeExecDictionaryWaitNext(ld, dictId);
}

static bool
LexizeExecIsStop(LexizeData *ld, ParsedLex *token, Oid dictId)
{
	TSLexeme *lex = LexizeExecDictionary(ld, token, dictId);
	return lex != NULL && lex[0].lexeme == NULL;
}

static bool
LexizeExecExpressionBool(LexizeData *ld, ParsedLex *token, TSMapExpression *expression)
{
	bool result;
	if (expression == NULL)
		result = false;
	else if (expression->is_true)
		result = true;
	else if (expression->dictionary != InvalidOid)
	{
		bool is_null = LexizeExecIsNull(ld, token, expression->dictionary);
		bool is_stop = LexizeExecIsStop(ld, token, expression->dictionary);
		bool invert = (expression->options & DICTMAP_OPT_NOT) != 0;

		result = true;
		if ((expression->options & DICTMAP_OPT_IS_NULL) != 0)
			result = result && (invert ? !is_null : is_null);
		if ((expression->options & DICTMAP_OPT_IS_STOP) != 0)
			result = result && (invert ? !is_stop : is_stop);
	}
	else
	{
		if (expression->operator == DICTMAP_OP_MAPBY)
		{
			TSLexeme *mapby_result = LexizeExecMapBy(ld, token, expression->left, expression->right);
			bool is_null = mapby_result == NULL;
			bool is_stop = mapby_result != NULL && mapby_result[0].lexeme == NULL;
			bool invert = (expression->options & DICTMAP_OPT_NOT) != 0;
			if (expression->left->dictionary != InvalidOid && LexizeExecDictionaryWaitNext(ld, expression->left->dictionary))
				is_null = false;

			result = true;
			if ((expression->options & DICTMAP_OPT_IS_NULL) != 0)
				result = result && (invert ? !is_null : is_null);
			if ((expression->options & DICTMAP_OPT_IS_STOP) != 0)
				result = result && (invert ? !is_stop : is_stop);
		}
		else
		{
			bool res_left = LexizeExecExpressionBool(ld, token, expression->left);
			bool res_right = LexizeExecExpressionBool(ld, token, expression->right);
			switch (expression->operator)
			{
				case DICTMAP_OP_NOT:
					result = !res_right;
					break;
				case DICTMAP_OP_OR:
					result = res_left || res_right;
					break;
				case DICTMAP_OP_AND:
					result = res_left && res_right;
					break;
				default:
					ereport(ERROR,
							(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
							 errmsg("invalid text search configuration boolean expression")));
					break;
			}
		}
	}

	return result;
}

static TSLexeme *
LexizeExecExpressionSet(LexizeData *ld, ParsedLex *token, TSMapExpression *expression)
{
	TSLexeme *result;

	if (expression->dictionary != InvalidOid)
	{
		result = LexizeExecDictionary(ld, token, expression->dictionary);
	}
	else
	{
		if (expression->operator == DICTMAP_OP_MAPBY)
		{
			result = LexizeExecMapBy(ld, token, expression->left, expression->right);
		}
		else
		{
			TSLexeme *res_left = LexizeExecExpressionSet(ld, token, expression->left);
			TSLexeme *res_right = LexizeExecExpressionSet(ld, token, expression->right);

			switch (expression->operator)
			{
				case DICTMAP_OP_UNION:
					result = TSLexemeUnion(res_left, res_right);
					break;
				case DICTMAP_OP_EXCEPT:
					result = TSLexemeExcept(res_left, res_right);
					break;
				case DICTMAP_OP_INTERSECT:
					result = TSLexemeIntersect(res_left, res_right);
					break;
				default:
					ereport(ERROR,
							(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
							 errmsg("invalid text search configuration result set expression")));
					result = NULL;
					break;
			}
		}
	}

	return result;
}

static TSLexeme *
LexizeExecMapBy(LexizeData *ld, ParsedLex *token, TSMapExpression *left, TSMapExpression *right)
{
	TSLexeme *right_res = LexizeExecExpressionSet(ld, token, right);
	TSLexeme *result;
	int right_size = TSLexemeGetSize(right_res);
	int i;

	result = NULL;
	for (i = 0; i < right_size; i++)
	{
		TSLexeme *tmp_res;
		TSLexeme *prev_res;
		ParsedLex tmp_token;

		tmp_token.lemm = right_res[i].lexeme;
		tmp_token.lenlemm = strlen(right_res[i].lexeme);
		tmp_token.type = token->type;
		tmp_token.next = NULL;

		tmp_res = LexizeExecExpressionSet(ld, &tmp_token, left);
		prev_res = result;
		result = TSLexemeUnion(prev_res, tmp_res);
		if (prev_res)
			pfree(prev_res);
	}

	return result;
}

static TSLexeme *
LexizeExecCase(LexizeData *ld, ParsedLex *token, TSMapRuleList *rules)
{
	TSLexeme *res = NULL;

	if (ld->cfg->lenmap <= token->type || rules == NULL)
	{
		res = NULL;
	}
	else
	{
		int i;
		for (i = 0; i < rules->count; i++)
		{
			if (rules->data[i].dictionary != InvalidOid)
			{
				res = LexizeExecDictionary(ld, token, rules->data[i].dictionary);
				if (!LexizeExecIsNull(ld, token, rules->data[i].dictionary))
					break;
			}
			else if (LexizeExecExpressionBool(ld, token, rules->data[i].condition.expression))
			{
				if (rules->data[i].command.is_expression)
					res = LexizeExecExpressionSet(ld, token, rules->data[i].command.expression);
				else
					res = LexizeExecCase(ld, token, rules);
				break;
			}
		}
	}

	return res;
}

static TSLexeme *
LexizeExecFinishProcessing(LexizeData *ld)
{
	int i;
	TSLexeme *res = NULL;
	for (i = 0; i < ld->dslist.listLength; i++)
	{
		TSLexeme *last_res = res;
		res = TSLexemeUnion(res, ld->dslist.states[i].tmpResult);
		if (last_res)
			pfree(last_res);
	}

	return res;
}

static TSLexeme *
LexizeExecGetPreviousResults(LexizeData *ld)
{
	int i;
	TSLexeme *res = NULL;
	for (i = 0; i < ld->dslist.listLength; i++)
	{
		if (!ld->dslist.states[i].processed)
		{
			TSLexeme *last_res = res;
			res = TSLexemeUnion(res, ld->dslist.states[i].tmpResult);
			if (last_res)
				pfree(last_res);
		}
	}

	return res;
}

static void
LexizeExecClearDictStates(LexizeData *ld)
{
	int i;
	for (i = 0; i < ld->dslist.listLength; i++)
	{
		if (!ld->dslist.states[i].processed)
		{
			DictStateListRemove(&ld->dslist, ld->dslist.states[i].relatedDictionary);
			i = 0;
		}
	}
}

static bool
LexizeExecNotProcessedDictStates(LexizeData *ld)
{
	int i;

	for (i = 0; i < ld->dslist.listLength; i++)
		if (!ld->dslist.states[i].processed)
			return true;

	return false;
}

static TSLexeme *
LexizeExec(LexizeData *ld, ParsedLex **correspondLexem)
{
	ParsedLex *token;
	TSMapRuleList *rules;
	TSLexeme *res = NULL;
	TSLexeme *prevIterationResult = NULL;
	bool removeHead = false;
	bool resetSkipDictionary = false;
	bool accepted = false;
	int i;

	for (i = 0; i < ld->dslist.listLength; i++)
		ld->dslist.states[i].processed = false;
	if (ld->skipDictionary != InvalidOid)
		resetSkipDictionary = true;

	token = ld->towork.head;
	if (token == NULL)
	{
		setCorrLex(ld, correspondLexem);
		return NULL;
	}
	else if (token->type == 0) /* Processing of EOF-like token */
	{
		res = LexizeExecFinishProcessing(ld);
		removeHead = true;
		if (LexizeExecNotProcessedDictStates(ld))
		{
			int i;
			ListParsedLex *intermediateTokens = NULL;

			for (i = 0; i < ld->dslist.listLength; i++)
			{
				if (!ld->dslist.states[i].processed)
				{
					intermediateTokens = &ld->dslist.states[i].intermediateTokens;
					ld->skipDictionary = ld->dslist.states[i].relatedDictionary;
					break;
				}
			}

			if (intermediateTokens && intermediateTokens->head)
			{
				ParsedLex *head = ld->towork.head;
				ld->towork.head = intermediateTokens->head;
				intermediateTokens->tail->next = head;
				head->next = NULL;
				ld->towork.tail = head;
				removeHead = false;
			}
			ResultStorageClear(&ld->delayedResults);
		}
		DictStateListClear(&ld->dslist);
	}
	else
	{
		rules = ld->cfg->map[token->type];
		res = LexizeExecCase(ld, token, rules);

		if (rules != NULL)
		{
			prevIterationResult = LexizeExecGetPreviousResults(ld);
			removeHead = prevIterationResult == NULL;
			if (LexizeExecNotProcessedDictStates(ld)) /* Rollback processing */
			{
				int i;
				ListParsedLex *intermediateTokens = NULL;

				for (i = 0; i < ld->dslist.listLength; i++)
				{
					if (!ld->dslist.states[i].processed)
					{
						intermediateTokens = &ld->dslist.states[i].intermediateTokens;
						if (!prevIterationResult)
							ld->skipDictionary = ld->dslist.states[i].relatedDictionary;
					}
				}

				if (intermediateTokens && intermediateTokens->head)
				{
					ParsedLex *head = ld->towork.head;
					ld->towork.head = intermediateTokens->head;
					intermediateTokens->tail->next = head;
					head->next = NULL;
					ld->towork.tail = head;
					removeHead = false;
				}
				// TODO: Clear only intermediate reulsts, keep accepted ones
				ResultStorageClearLexemes(&ld->delayedResults);
				res = NULL;
			}

			if (prevIterationResult)
			{
				res = prevIterationResult;
			}
			else
			{
				int i;
				for (i = 0; i < ld->dslist.listLength; i++)
				{
					if (!ld->dslist.states[i].processed)
						continue;

					if (ld->dslist.states[i].storeToAccepted)
					{
						LPLAddTailCopy(&ld->dslist.states[i].acceptedTokens, token);
						accepted = true;
					}
					else
					{
						LPLAddTailCopy(&ld->dslist.states[i].intermediateTokens, token);
					}
				}
			}
			LexizeExecClearDictStates(ld);
		}
		else
		{
			removeHead = true;
		}
	}

	if (removeHead)
		RemoveHead(ld);

	if (ld->dslist.listLength > 0)
	{
		ResultStorageAdd(&ld->delayedResults, token, res);
		if (accepted)
			ResultStorageMoveToAccepted(&ld->delayedResults);
		if (res)
			pfree(res);
		res = NULL;
	}
	else
	{
		if (ld->delayedResults.accepted != NULL)
		{
			TSLexeme *oldRes = res;
			res = TSLexemeUnionOpt(ld->delayedResults.accepted, res, prevIterationResult == NULL);
			if (oldRes)
				pfree(oldRes);
			ResultStorageClear(&ld->delayedResults);
		}
	}

	if (resetSkipDictionary)
		ld->skipDictionary = InvalidOid;

	LexemesBufferClear(&ld->buffer);
	if (res)
		res = TSLexemeRemoveDuplications(res);

	setCorrLex(ld, correspondLexem);
	return res;
}

/*
 * Parse string and lexize words.
 *
 * prs will be filled in.
 */
void
parsetext(Oid cfgId, ParsedText *prs, char *buf, int buflen)
{
	int			type = -1,
				lenlemm;
	char	   *lemm = NULL;
	LexizeData	ldata;
	TSLexeme   *norms;
	TSConfigCacheEntry *cfg;
	TSParserCacheEntry *prsobj;
	void	   *prsdata;

	cfg = lookup_ts_config_cache(cfgId);
	prsobj = lookup_ts_parser_cache(cfg->prsId);

	prsdata = (void *) DatumGetPointer(FunctionCall2(&prsobj->prsstart,
													 PointerGetDatum(buf),
													 Int32GetDatum(buflen)));

	LexizeInit(&ldata, cfg);

	type = 1;
	do
	{
		if (type > 0)
		{
			type = DatumGetInt32(FunctionCall3(&(prsobj->prstoken),
											   PointerGetDatum(prsdata),
											   PointerGetDatum(&lemm),
											   PointerGetDatum(&lenlemm)));

			if (type > 0 && lenlemm >= MAXSTRLEN)
			{
#ifdef IGNORE_LONGLEXEME
				ereport(NOTICE,
						(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
						 errmsg("word is too long to be indexed"),
						 errdetail("Words longer than %d characters are ignored.",
								   MAXSTRLEN)));
				continue;
#else
				ereport(ERROR,
						(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
						 errmsg("word is too long to be indexed"),
						 errdetail("Words longer than %d characters are ignored.",
								   MAXSTRLEN)));
#endif
			}

			LexizeAddLemm(&ldata, type, lemm, lenlemm);
		}

		while ((norms = LexizeExec(&ldata, NULL)) != NULL)
		{
			TSLexeme   *ptr;
			ptr = norms;

			prs->pos++;			/* set pos */

			while (ptr->lexeme)
			{
				if (prs->curwords == prs->lenwords)
				{
					prs->lenwords *= 2;
					prs->words = (ParsedWord *) repalloc((void *) prs->words, prs->lenwords * sizeof(ParsedWord));
				}

				if (ptr->flags & TSL_ADDPOS)
					prs->pos++;
				prs->words[prs->curwords].len = strlen(ptr->lexeme);
				prs->words[prs->curwords].word = ptr->lexeme;
				prs->words[prs->curwords].nvariant = ptr->nvariant;
				prs->words[prs->curwords].flags = ptr->flags & TSL_PREFIX;
				prs->words[prs->curwords].alen = 0;
				prs->words[prs->curwords].pos.pos = LIMITPOS(prs->pos);
				ptr++;
				prs->curwords++;
			}
			pfree(norms);
		}
	} while (type > 0 || ldata.towork.head);

	FunctionCall1(&(prsobj->prsend), PointerGetDatum(prsdata));
}

/*
 * Headline framework
 */
static void
hladdword(HeadlineParsedText *prs, char *buf, int buflen, int type)
{
	while (prs->curwords >= prs->lenwords)
	{
		prs->lenwords *= 2;
		prs->words = (HeadlineWordEntry *) repalloc((void *) prs->words, prs->lenwords * sizeof(HeadlineWordEntry));
	}
	memset(&(prs->words[prs->curwords]), 0, sizeof(HeadlineWordEntry));
	prs->words[prs->curwords].type = (uint8) type;
	prs->words[prs->curwords].len = buflen;
	prs->words[prs->curwords].word = palloc(buflen);
	memcpy(prs->words[prs->curwords].word, buf, buflen);
	prs->curwords++;
}

static void
hlfinditem(HeadlineParsedText *prs, TSQuery query, int32 pos, char *buf, int buflen)
{
	int			i;
	QueryItem  *item = GETQUERY(query);
	HeadlineWordEntry *word;

	while (prs->curwords + query->size >= prs->lenwords)
	{
		prs->lenwords *= 2;
		prs->words = (HeadlineWordEntry *) repalloc((void *) prs->words, prs->lenwords * sizeof(HeadlineWordEntry));
	}

	word = &(prs->words[prs->curwords - 1]);
	word->pos = LIMITPOS(pos);
	for (i = 0; i < query->size; i++)
	{
		if (item->type == QI_VAL &&
			tsCompareString(GETOPERAND(query) + item->qoperand.distance, item->qoperand.length,
							buf, buflen, item->qoperand.prefix) == 0)
		{
			if (word->item)
			{
				memcpy(&(prs->words[prs->curwords]), word, sizeof(HeadlineWordEntry));
				prs->words[prs->curwords].item = &item->qoperand;
				prs->words[prs->curwords].repeated = 1;
				prs->curwords++;
			}
			else
				word->item = &item->qoperand;
		}
		item++;
	}
}

static void
addHLParsedLex(HeadlineParsedText *prs, TSQuery query, ParsedLex *lexs, TSLexeme *norms)
{
	ParsedLex  *tmplexs;
	TSLexeme   *ptr;
	int32		savedpos;

	while (lexs)
	{
		if (lexs->type > 0)
			hladdword(prs, lexs->lemm, lexs->lenlemm, lexs->type);

		ptr = norms;
		savedpos = prs->vectorpos;
		while (ptr && ptr->lexeme)
		{
			if (ptr->flags & TSL_ADDPOS)
				savedpos++;
			hlfinditem(prs, query, savedpos, ptr->lexeme, strlen(ptr->lexeme));
			ptr++;
		}

		tmplexs = lexs->next;
		pfree(lexs);
		lexs = tmplexs;
	}

	if (norms)
	{
		ptr = norms;
		while (ptr->lexeme)
		{
			if (ptr->flags & TSL_ADDPOS)
				prs->vectorpos++;
			pfree(ptr->lexeme);
			ptr++;
		}
		pfree(norms);
	}
}

void
hlparsetext(Oid cfgId, HeadlineParsedText *prs, TSQuery query, char *buf, int buflen)
{
	int			type = -1,
				lenlemm;
	char	   *lemm = NULL;
	LexizeData	ldata;
	TSLexeme   *norms;
	ParsedLex  *lexs;
	TSConfigCacheEntry *cfg;
	TSParserCacheEntry *prsobj;
	void	   *prsdata;

	cfg = lookup_ts_config_cache(cfgId);
	prsobj = lookup_ts_parser_cache(cfg->prsId);

	prsdata = (void *) DatumGetPointer(FunctionCall2(&(prsobj->prsstart),
													 PointerGetDatum(buf),
													 Int32GetDatum(buflen)));

	LexizeInit(&ldata, cfg);

	do
	{
		if (type != 0)
		{
			type = DatumGetInt32(FunctionCall3(&(prsobj->prstoken),
											   PointerGetDatum(prsdata),
											   PointerGetDatum(&lemm),
											   PointerGetDatum(&lenlemm)));

			if (type > 0 && lenlemm >= MAXSTRLEN)
			{
#ifdef IGNORE_LONGLEXEME
				ereport(NOTICE,
						(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
						 errmsg("word is too long to be indexed"),
						 errdetail("Words longer than %d characters are ignored.",
								   MAXSTRLEN)));
				continue;
#else
				ereport(ERROR,
						(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
						 errmsg("word is too long to be indexed"),
						 errdetail("Words longer than %d characters are ignored.",
								   MAXSTRLEN)));
#endif
			}

			LexizeAddLemm(&ldata, type, lemm, lenlemm);
		}

		do
		{
			if ((norms = LexizeExec(&ldata, &lexs)) != NULL)
			{
				prs->vectorpos++;
				addHLParsedLex(prs, query, lexs, norms);
			}
			else
				addHLParsedLex(prs, query, lexs, NULL);
		} while (norms);

	} while (type != 0 || ldata.towork.head);

	FunctionCall1(&(prsobj->prsend), PointerGetDatum(prsdata));
}

text *
generateHeadline(HeadlineParsedText *prs)
{
	text	   *out;
	char	   *ptr;
	int			len = 128;
	int			numfragments = 0;
	int16		infrag = 0;

	HeadlineWordEntry *wrd = prs->words;

	out = (text *) palloc(len);
	ptr = ((char *) out) + VARHDRSZ;

	while (wrd - prs->words < prs->curwords)
	{
		while (wrd->len + prs->stopsellen + prs->startsellen + prs->fragdelimlen + (ptr - ((char *) out)) >= len)
		{
			int			dist = ptr - ((char *) out);

			len *= 2;
			out = (text *) repalloc(out, len);
			ptr = ((char *) out) + dist;
		}

		if (wrd->in && !wrd->repeated)
		{
			if (!infrag)
			{

				/* start of a new fragment */
				infrag = 1;
				numfragments++;
				/* add a fragment delimiter if this is after the first one */
				if (numfragments > 1)
				{
					memcpy(ptr, prs->fragdelim, prs->fragdelimlen);
					ptr += prs->fragdelimlen;
				}

			}
			if (wrd->replace)
			{
				*ptr = ' ';
				ptr++;
			}
			else if (!wrd->skip)
			{
				if (wrd->selected)
				{
					memcpy(ptr, prs->startsel, prs->startsellen);
					ptr += prs->startsellen;
				}
				memcpy(ptr, wrd->word, wrd->len);
				ptr += wrd->len;
				if (wrd->selected)
				{
					memcpy(ptr, prs->stopsel, prs->stopsellen);
					ptr += prs->stopsellen;
				}
			}
		}
		else if (!wrd->repeated)
		{
			if (infrag)
				infrag = 0;
			pfree(wrd->word);
		}

		wrd++;
	}

	SET_VARSIZE(out, ptr - ((char *) out));
	return out;
}
