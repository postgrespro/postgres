/*-------------------------------------------------------------------------
 *
 * ts_parse.c
 *		main parse functions for tsearch
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
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
#include "tsearch/ts_configmap.h"
#include "utils/builtins.h"
#include "funcapi.h"

#define IGNORE_LONGLEXEME	1

/*-------------------
 * Lexize subsystem
 *-------------------
 */

/*
 * Representation of token produced by FTS parser. It contains intermediate
 * lexemes in case of phrase dictionary processing.
 */
typedef struct ParsedLex
{
	int			type;			/* Token type */
	char	   *lemm;			/* Token itself */
	int			lenlemm;		/* Length of the token string */
	int			maplen;			/* Length of the map */
	bool	   *accepted;		/* Is accepted by some dictionary */
	bool	   *rejected;		/* Is rejected by all dictionaries */
	bool	   *notFinished;	/* Some dictionary not finished processing and
								 * waits for more tokens */
	struct ParsedLex *next;		/* Next token in the list */
	TSMapElement *relatedRule;	/* Rule which is used to produce lexemes from
								 * the token */
} ParsedLex;

/*
 * List of tokens produced by FTS parser.
 */
typedef struct ListParsedLex
{
	ParsedLex  *head;
	ParsedLex  *tail;
} ListParsedLex;

/*
 * Dictionary state shared between processing of different tokens
 */
typedef struct DictState
{
	Oid			relatedDictionary;	/* DictState contains state of dictionary
									 * with this Oid */
	DictSubState subState;		/* Internal state of the dictionary used to
								 * store some state between dictionary calls */
	ListParsedLex acceptedTokens;	/* Tokens which are processed and
									 * accepted, used in last returned result
									 * by the dictionary */
	ListParsedLex intermediateTokens;	/* Tokens which are not accepted, but
										 * were processed by thesaurus-like
										 * dictionary */
	bool		storeToAccepted;	/* Should current token be appended to
									 * accepted or intermediate tokens */
	bool		processed;		/* Is the dictionary take control during
								 * current token processing */
	TSLexeme   *tmpResult;		/* Last result returned by thesaurus-like
								 * dictionary, if dictionary still waiting for
								 * more lexemes */
} DictState;

/*
 * List of dictionary states
 */
typedef struct DictStateList
{
	int			listLength;
	DictState  *states;
} DictStateList;

/*
 * Buffer entry with lexemes produced from current token
 */
typedef struct LexemesBufferEntry
{
	TSMapElement *key;	/* Element of the mapping configuration produced the entry */
	ParsedLex  *token;	/* Token used for production of the lexemes */
	TSLexeme   *data;	/* Lexemes produced from current token */
} LexemesBufferEntry;

/*
 * Buffer with lexemes produced from current token
 */
typedef struct LexemesBuffer
{
	int			size;
	LexemesBufferEntry *data;
} LexemesBuffer;

/*
 * Storage for accepted and possible accepted lexemes
 */
typedef struct ResultStorage
{
	TSLexeme   *lexemes;		/* Processed lexemes, which is not yet
								 * accepted */
	TSLexeme   *accepted;		/* Already accepted lexemes */
} ResultStorage;

/*
 * FTS processing context
 */
typedef struct LexizeData
{
	TSConfigCacheEntry *cfg;	/* Text search configuration mappings for
								 * current configuration */
	DictStateList dslist;		/* List of all currently stored states of
								 * dictionaries */
	ListParsedLex towork;		/* Current list to work */
	ListParsedLex waste;		/* List of lexemes that already lexized */
	LexemesBuffer buffer;		/* Buffer of processed lexemes. Used to avoid
								 * multiple execution of token lexize process
								 * with same parameters */
	ResultStorage delayedResults;	/* Results that should be returned but may
									 * be rejected in future */
	Oid			skipDictionary; /* The dictionary we should skip during
								 * processing. Used to avoid infinite loop in
								 * configuration with phrase dictionary */
	bool		debugContext;	/* If true, relatedRule attribute is filled */
} LexizeData;

/*
 * FTS processing debug context. Used during ts_debug calls.
 */
typedef struct TSDebugContext
{
	TSConfigCacheEntry *cfg;	/* Text search configuration mappings for
								 * current configuration */
	TSParserCacheEntry *prsobj; /* Parser context of current ts_debug context */
	LexDescr   *tokenTypes;		/* Token types supported by current parser */
	void	   *prsdata;		/* Parser data of current ts_debug context */
	LexizeData	ldata;			/* Lexize data of current ts_debug context */
	int			tokentype;		/* Last token tokentype */
	TSLexeme   *savedLexemes;	/* Last token lexemes stored for ts_debug
								 * output */
	ParsedLex  *leftTokens;		/* Corresponded ParsedLex */
} TSDebugContext;

static TSLexeme *TSLexemeMap(LexizeData *ld, ParsedLex *token, TSMapExpression *expression);
static TSLexeme *LexizeExecTSElement(LexizeData *ld, ParsedLex *token, TSMapElement *config);

/*-------------------
 * ListParsedLex API
 *-------------------
 */

/*
 * Add a ParsedLex to the end of the list
 */
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

/*
 * Add a copy of ParsedLex to the end of the list
 */
static void
LPLAddTailCopy(ListParsedLex *list, ParsedLex *newpl)
{
	ParsedLex  *copy = palloc0(sizeof(ParsedLex));

	copy->lenlemm = newpl->lenlemm;
	copy->type = newpl->type;
	copy->lemm = newpl->lemm;
	copy->relatedRule = newpl->relatedRule;
	copy->next = NULL;

	if (list->tail)
	{
		list->tail->next = copy;
		list->tail = copy;
	}
	else
		list->head = list->tail = copy;
}

/*
 * Remove the head of the list. Return pointer to detached head
 */
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

/*
 * Remove all ParsedLex from the list
 */
static void
LPLClear(ListParsedLex *list)
{
	ParsedLex  *tmp,
			   *ptr = list->head;

	while (ptr)
	{
		tmp = ptr->next;
		pfree(ptr);
		ptr = tmp;
	}

	list->head = list->tail = NULL;
}

/*-------------------
 * LexizeData manipulation functions
 *-------------------
 */

/*
 * Initialize empty LexizeData object
 */
static void
LexizeInit(LexizeData *ld, TSConfigCacheEntry *cfg)
{
	ld->cfg = cfg;
	ld->skipDictionary = InvalidOid;
	ld->towork.head = ld->towork.tail = NULL;
	ld->waste.head = ld->waste.tail = NULL;
	ld->dslist.listLength = 0;
	ld->dslist.states = NULL;
	ld->buffer.size = 0;
	ld->buffer.data = NULL;
	ld->delayedResults.lexemes = NULL;
	ld->delayedResults.accepted = NULL;
}

/*
 * Add a token to the processing queue
 */
static void
LexizeAddLemm(LexizeData *ld, int type, char *lemm, int lenlemm)
{
	ParsedLex  *newpl = (ParsedLex *) palloc(sizeof(ParsedLex));

	newpl->type = type;
	newpl->lemm = lemm;
	newpl->lenlemm = lenlemm;
	newpl->relatedRule = NULL;
	LPLAddTail(&ld->towork, newpl);
}

/*
 * Remove head of the processing queue
 */
static void
RemoveHead(LexizeData *ld)
{
	LPLAddTail(&ld->waste, LPLRemoveHead(&ld->towork));
}

/*
 * Set token corresponded to current lexeme
 */
static void
setCorrLex(LexizeData *ld, ParsedLex **correspondLexem)
{
	if (correspondLexem)
		*correspondLexem = ld->waste.head;
	else
		LPLClear(&ld->waste);

	ld->waste.head = ld->waste.tail = NULL;
}

/*-------------------
 * DictState manipulation functions
 *-------------------
 */

/*
 * Get a state of dictionary based on its OID
 */
static DictState *
DictStateListGet(DictStateList *list, Oid dictId)
{
	int			i;
	DictState  *result = NULL;

	for (i = 0; i < list->listLength; i++)
		if (list->states[i].relatedDictionary == dictId)
			result = &list->states[i];

	return result;
}

/*
 * Remove a state of dictionary based on its OID
 */
static void
DictStateListRemove(DictStateList *list, Oid dictId)
{
	int			i;

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

/*
 * Insert a state of dictionary with specified OID
 */
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

/*
 * Remove states of all dictionaries
 */
static void
DictStateListClear(DictStateList *list)
{
	list->listLength = 0;
	if (list->states)
		pfree(list->states);
	list->states = NULL;
}

/*-------------------
 * LexemesBuffer manipulation functions
 *-------------------
 */

/*
 * Check if there is a saved lexeme generated by specified TSMapElement
 */
static bool
LexemesBufferContains(LexemesBuffer *buffer, TSMapElement *key, ParsedLex *token)
{
	int			i;

	for (i = 0; i < buffer->size; i++)
		if (TSMapElementEquals(buffer->data[i].key, key) && buffer->data[i].token == token)
			return true;

	return false;
}

/*
 * Get a saved lexeme generated by specified TSMapElement
 */
static TSLexeme *
LexemesBufferGet(LexemesBuffer *buffer, TSMapElement *key, ParsedLex *token)
{
	int			i;
	TSLexeme   *result = NULL;

	for (i = 0; i < buffer->size; i++)
		if (TSMapElementEquals(buffer->data[i].key, key) && buffer->data[i].token == token)
			result = buffer->data[i].data;

	return result;
}

/*
 * Remove a saved lexeme generated by specified TSMapElement
 */
static void
LexemesBufferRemove(LexemesBuffer *buffer, TSMapElement *key, ParsedLex *token)
{
	int			i;

	for (i = 0; i < buffer->size; i++)
		if (TSMapElementEquals(buffer->data[i].key, key) && buffer->data[i].token == token)
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

/*
 * Same a lexeme generated by specified TSMapElement
 */
static void
LexemesBufferAdd(LexemesBuffer *buffer, TSMapElement *key, ParsedLex *token, TSLexeme *data)
{
	LexemesBufferRemove(buffer, key, token);

	buffer->size++;
	if (buffer->data)
		buffer->data = repalloc(buffer->data, sizeof(LexemesBufferEntry) * buffer->size);
	else
		buffer->data = palloc0(sizeof(LexemesBufferEntry) * buffer->size);

	buffer->data[buffer->size - 1].token = token;
	buffer->data[buffer->size - 1].key = key;
	buffer->data[buffer->size - 1].data = data;
}

/*
 * Remove all lexemes saved in a buffer
 */
static void
LexemesBufferClear(LexemesBuffer *buffer)
{
	int			i;
	bool	   *skipEntry = palloc0(sizeof(bool) * buffer->size);

	for (i = 0; i < buffer->size; i++)
	{
		if (buffer->data[i].data != NULL && !skipEntry[i])
		{
			int			j;

			for (j = 0; j < buffer->size; j++)
				if (buffer->data[i].data == buffer->data[j].data)
					skipEntry[j] = true;

			pfree(buffer->data[i].data);
		}
	}

	buffer->size = 0;
	if (buffer->data)
		pfree(buffer->data);
	buffer->data = NULL;
}

/*-------------------
 * TSLexeme util functions
 *-------------------
 */

/*
 * Get size of TSLexeme except empty-lexeme
 */
static int
TSLexemeGetSize(TSLexeme *lex)
{
	int			result = 0;
	TSLexeme   *ptr = lex;

	while (ptr && ptr->lexeme)
	{
		result++;
		ptr++;
	}

	return result;
}

/*
 * Remove repeated lexemes. Also remove copies of whole nvariant groups.
 */
static TSLexeme *
TSLexemeRemoveDuplications(TSLexeme *lexeme)
{
	TSLexeme   *res;
	int			curLexIndex;
	int			i;
	int			lexemeSize = TSLexemeGetSize(lexeme);
	int			shouldCopyCount = lexemeSize;
	bool	   *shouldCopy;

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
					 * Check for same set of lexemes in another nvariant
					 * series
					 */
					int			nvariantCountL = 0;
					int			nvariantCountR = 0;
					int			nvariantOverlap = 1;
					int			j;

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
						shouldCopy[i + j] = false;
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
	return res;
}

/*
 * Combine two lexeme lists with respect to positions
 */
static TSLexeme *
TSLexemeMergePositions(TSLexeme *left, TSLexeme *right)
{
	TSLexeme   *result = NULL;

	if (left != NULL || right != NULL)
	{
		int			left_i = 0;
		int			right_i = 0;
		int			left_max_nvariant = 0;
		int			i;
		int			left_size = TSLexemeGetSize(left);
		int			right_size = TSLexemeGetSize(right);

		result = palloc0(sizeof(TSLexeme) * (left_size + right_size + 1));

		for (i = 0; i < left_size; i++)
			if (left[i].nvariant > left_max_nvariant)
				left_max_nvariant = left[i].nvariant;

		for (i = 0; i < right_size; i++)
			right[i].nvariant += left_max_nvariant;
		if (right && right[0].flags & TSL_ADDPOS)
			right[0].flags &= ~TSL_ADDPOS;

		i = 0;
		while (i < left_size + right_size)
		{
			if (left_i < left_size)
			{
				do
				{
					result[i++] = left[left_i++];
				} while (left && left[left_i].lexeme && (left[left_i].flags & TSL_ADDPOS) == 0);
			}

			if (right_i < right_size)
			{
				do
				{
					result[i++] = right[right_i++];
				} while (right && right[right_i].lexeme && (right[right_i].flags & TSL_ADDPOS) == 0);
			}
		}
	}
	return result;
}

/*
 * Split lexemes generated by regular dictionaries and multi-input dictionaries
 * and combine them with respect to positions
 */
static TSLexeme *
TSLexemeFilterMulti(TSLexeme *lexemes)
{
	TSLexeme   *result;
	TSLexeme   *ptr = lexemes;
	int			multi_lexemes = 0;

	while (ptr && ptr->lexeme)
	{
		if (ptr->flags & TSL_MULTI)
			multi_lexemes++;
		ptr++;
	}

	if (multi_lexemes > 0)
	{
		TSLexeme   *lexemes_multi = palloc0(sizeof(TSLexeme) * (multi_lexemes + 1));
		TSLexeme   *lexemes_rest = palloc0(sizeof(TSLexeme) * (TSLexemeGetSize(lexemes) - multi_lexemes + 1));
		int			rest_i = 0;
		int			multi_i = 0;

		ptr = lexemes;
		while (ptr && ptr->lexeme)
		{
			if (ptr->flags & TSL_MULTI)
				lexemes_multi[multi_i++] = *ptr;
			else
				lexemes_rest[rest_i++] = *ptr;

			ptr++;
		}
		result = TSLexemeMergePositions(lexemes_rest, lexemes_multi);
	}
	else
	{
		result = TSLexemeMergePositions(lexemes, NULL);
	}

	return result;
}

/*
 * Mark lexemes as generated by multi-input (thesaurus-like) dictionary
 */
static void
TSLexemeMarkMulti(TSLexeme *lexemes)
{
	TSLexeme   *ptr = lexemes;

	while (ptr && ptr->lexeme)
	{
		ptr->flags |= TSL_MULTI;
		ptr++;
	}
}

/*-------------------
 * Lexemes set operations
 *-------------------
 */

/*
 * Combine left and right lexeme lists into one.
 * If append is true, right lexemes added after last left lexeme with TSL_ADDPOS flag
 */
static TSLexeme *
TSLexemeUnionOpt(TSLexeme *left, TSLexeme *right, bool append)
{
	TSLexeme   *result;
	int			left_size = TSLexemeGetSize(left);
	int			right_size = TSLexemeGetSize(right);
	int			left_max_nvariant = 0;
	int			i;

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
		if (append && left_size > 0 && right_size > 0)
			result[left_size].flags |= TSL_ADDPOS;

		for (i = left_size; i < left_size + right_size; i++)
			result[i].nvariant += left_max_nvariant;
	}

	return result;
}

/*
 * Combine left and right lexeme lists into one
 */
static TSLexeme *
TSLexemeUnion(TSLexeme *left, TSLexeme *right)
{
	return TSLexemeUnionOpt(left, right, false);
}

/*
 * Remove common lexemes and return only which is stored in left list
 */
static TSLexeme *
TSLexemeExcept(TSLexeme *left, TSLexeme *right)
{
	TSLexeme   *result = NULL;
	int			i,
				j,
				k;
	int			left_size = TSLexemeGetSize(left);
	int			right_size = TSLexemeGetSize(right);

	result = palloc0(sizeof(TSLexeme) * (left_size + 1));

	for (k = 0, i = 0; i < left_size; i++)
	{
		bool		found = false;

		for (j = 0; j < right_size; j++)
			if (strcmp(left[i].lexeme, right[j].lexeme) == 0)
				found = true;

		if (!found)
			result[k++] = left[i];
	}

	return result;
}

/*
 * Keep only common lexemes
 */
static TSLexeme *
TSLexemeIntersect(TSLexeme *left, TSLexeme *right)
{
	TSLexeme   *result = NULL;
	int			i,
				j,
				k;
	int			left_size = TSLexemeGetSize(left);
	int			right_size = TSLexemeGetSize(right);

	result = palloc0(sizeof(TSLexeme) * (left_size + 1));

	for (k = 0, i = 0; i < left_size; i++)
	{
		bool		found = false;

		for (j = 0; j < right_size; j++)
			if (strcmp(left[i].lexeme, right[j].lexeme) == 0)
				found = true;

		if (found)
			result[k++] = left[i];
	}

	return result;
}

/*-------------------
 * Result storage functions
 *-------------------
 */

/*
 * Add a lexeme to the result storage
 */
static void
ResultStorageAdd(ResultStorage *storage, ParsedLex *token, TSLexeme *lexs)
{
	TSLexeme   *oldLexs = storage->lexemes;

	storage->lexemes = TSLexemeUnionOpt(storage->lexemes, lexs, true);
	if (oldLexs)
		pfree(oldLexs);
}

/*
 * Move all saved lexemes to accepted list
 */
static void
ResultStorageMoveToAccepted(ResultStorage *storage)
{
	if (storage->accepted)
	{
		TSLexeme   *prevAccepted = storage->accepted;

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

/*
 * Remove all non-accepted lexemes
 */
static void
ResultStorageClearLexemes(ResultStorage *storage)
{
	if (storage->lexemes)
		pfree(storage->lexemes);
	storage->lexemes = NULL;
}

/*
 * Remove all accepted lexemes
 */
static void
ResultStorageClearAccepted(ResultStorage *storage)
{
	if (storage->accepted)
		pfree(storage->accepted);
	storage->accepted = NULL;
}

/*-------------------
 * Condition and command execution
 *-------------------
 */

/*
 * Process a token by the dictionary
 */
static TSLexeme *
LexizeExecDictionary(LexizeData *ld, ParsedLex *token, TSMapElement *dictionary)
{
	TSLexeme   *res;
	TSDictionaryCacheEntry *dict;
	DictSubState subState;
	Oid			dictId = dictionary->value.objectDictionary;

	if (ld->skipDictionary == dictId)
		return NULL;

	if (LexemesBufferContains(&ld->buffer, dictionary, token))
		res = LexemesBufferGet(&ld->buffer, dictionary, token);
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

		res = (TSLexeme *) DatumGetPointer(FunctionCall4(&(dict->lexize),
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
				 * Add state to the list and update pointer in order to work
				 * with copy from the list
				 */
				state = DictStateListAdd(&ld->dslist, state);
			}

			state->subState = subState;
			state->storeToAccepted = res != NULL;

			if (res)
			{
				if (state->intermediateTokens.head != NULL)
				{
					ParsedLex  *ptr = state->intermediateTokens.head;

					while (ptr)
					{
						LPLAddTailCopy(&state->acceptedTokens, ptr);
						ptr = ptr->next;
					}
					state->intermediateTokens.head = state->intermediateTokens.tail = NULL;
				}

				if (state->tmpResult)
					pfree(state->tmpResult);
				TSLexemeMarkMulti(res);
				state->tmpResult = res;
				res = NULL;
			}
		}
		else if (state != NULL)
		{
			if (res)
			{
				if (state)
					TSLexemeMarkMulti(res);
				DictStateListRemove(&ld->dslist, dictId);
			}
			else
			{
				/*
				 * Trigger post-processing in order to check tmpResult and
				 * restart processing (see LexizeExec function)
				 */
				state->processed = false;
			}
		}
		LexemesBufferAdd(&ld->buffer, dictionary, token, res);
	}

	return res;
}

/*
 * Check is dictionary waits for more tokens or not
 */
static bool
LexizeExecDictionaryWaitNext(LexizeData *ld, Oid dictId)
{
	DictState  *state = DictStateListGet(&ld->dslist, dictId);

	if (state)
		return state->subState.getnext;
	else
		return false;
}

/*
 * Check is dictionary result for current token is NULL or not.
 * It dictionary waits for more lexemes, the result is interpreted as not null.
 */
static bool
LexizeExecIsNull(LexizeData *ld, ParsedLex *token, TSMapElement *config)
{
	bool		result = false;

	if (config->type == TSMAP_EXPRESSION)
	{
		TSMapExpression *expression = config->value.objectExpression;

		result = LexizeExecIsNull(ld, token, expression->left) || LexizeExecIsNull(ld, token, expression->right);
	}
	else if (config->type == TSMAP_DICTIONARY)
	{
		Oid			dictOid = config->value.objectDictionary;
		TSLexeme   *lexemes = LexizeExecDictionary(ld, token, config);

		if (lexemes)
			result = false;
		else
			result = !LexizeExecDictionaryWaitNext(ld, dictOid);
	}
	return result;
}

/*
 * Execute a MAP operator
 */
static TSLexeme *
TSLexemeMap(LexizeData *ld, ParsedLex *token, TSMapExpression *expression)
{
	TSLexeme   *left_res;
	TSLexeme   *result = NULL;
	int			left_size;
	int			i;

	left_res = LexizeExecTSElement(ld, token, expression->left);
	left_size = TSLexemeGetSize(left_res);

	if (left_res == NULL && LexizeExecIsNull(ld, token, expression->left))
		result = LexizeExecTSElement(ld, token, expression->right);
	else if (expression->operator == TSMAP_OP_COMMA &&
			((left_res != NULL && (left_res->flags & TSL_FILTER) == 0) || left_res == NULL))
		result = left_res;
	else
	{
		TSMapElement *relatedRuleTmp = NULL;
		relatedRuleTmp = palloc0(sizeof(TSMapElement));
		relatedRuleTmp->parent = NULL;
		relatedRuleTmp->type = TSMAP_EXPRESSION;
		relatedRuleTmp->value.objectExpression = palloc0(sizeof(TSMapExpression));
		relatedRuleTmp->value.objectExpression->operator = expression->operator;
		relatedRuleTmp->value.objectExpression->left = token->relatedRule;

		for (i = 0; i < left_size; i++)
		{
			TSLexeme   *tmp_res = NULL;
			TSLexeme   *prev_res;
			ParsedLex	tmp_token;

			tmp_token.lemm = left_res[i].lexeme;
			tmp_token.lenlemm = strlen(left_res[i].lexeme);
			tmp_token.type = token->type;
			tmp_token.next = NULL;

			tmp_res = LexizeExecTSElement(ld, &tmp_token, expression->right);
			relatedRuleTmp->value.objectExpression->right = tmp_token.relatedRule;
			prev_res = result;
			result = TSLexemeUnion(prev_res, tmp_res);
			if (prev_res)
				pfree(prev_res);
		}
		token->relatedRule = relatedRuleTmp;
	}

	return result;
}

/*
 * Execute a TSMapElement
 * Common point of all possible types of TSMapElement
 */
static TSLexeme *
LexizeExecTSElement(LexizeData *ld, ParsedLex *token, TSMapElement *config)
{
	TSLexeme   *result = NULL;

	if (LexemesBufferContains(&ld->buffer, config, token))
	{
		if (ld->debugContext)
			token->relatedRule = config;
		result = LexemesBufferGet(&ld->buffer, config, token);
	}
	else if (config->type == TSMAP_DICTIONARY)
	{
		if (ld->debugContext)
			token->relatedRule = config;
		result = LexizeExecDictionary(ld, token, config);
	}
	else if (config->type == TSMAP_CASE)
	{
		TSMapCase  *caseObject = config->value.objectCase;
		bool		conditionIsNull = LexizeExecIsNull(ld, token, caseObject->condition);

		if ((!conditionIsNull && caseObject->match) || (conditionIsNull && !caseObject->match))
		{
			if (caseObject->command->type == TSMAP_KEEP)
				result = LexizeExecTSElement(ld, token, caseObject->condition);
			else
				result = LexizeExecTSElement(ld, token, caseObject->command);
		}
		else if (caseObject->elsebranch)
			result = LexizeExecTSElement(ld, token, caseObject->elsebranch);
	}
	else if (config->type == TSMAP_EXPRESSION)
	{
		TSLexeme   *resLeft = NULL;
		TSLexeme   *resRight = NULL;
		TSMapElement *relatedRuleTmp = NULL;
		TSMapExpression *expression = config->value.objectExpression;

		if (expression->operator != TSMAP_OP_MAP && expression->operator != TSMAP_OP_COMMA)
		{
			if (ld->debugContext)
			{
				relatedRuleTmp = palloc0(sizeof(TSMapElement));
				relatedRuleTmp->parent = NULL;
				relatedRuleTmp->type = TSMAP_EXPRESSION;
				relatedRuleTmp->value.objectExpression = palloc0(sizeof(TSMapExpression));
				relatedRuleTmp->value.objectExpression->operator = expression->operator;
			}

			resLeft = LexizeExecTSElement(ld, token, expression->left);
			if (ld->debugContext)
				relatedRuleTmp->value.objectExpression->left = token->relatedRule;

			resRight = LexizeExecTSElement(ld, token, expression->right);
			if (ld->debugContext)
				relatedRuleTmp->value.objectExpression->right = token->relatedRule;
		}

		switch (expression->operator)
		{
			case TSMAP_OP_UNION:
				result = TSLexemeUnion(resLeft, resRight);
				break;
			case TSMAP_OP_EXCEPT:
				result = TSLexemeExcept(resLeft, resRight);
				break;
			case TSMAP_OP_INTERSECT:
				result = TSLexemeIntersect(resLeft, resRight);
				break;
			case TSMAP_OP_MAP:
			case TSMAP_OP_COMMA:
				result = TSLexemeMap(ld, token, expression);
				break;
			default:
				ereport(ERROR,
						(errcode(ERRCODE_DATA_CORRUPTED),
						 errmsg("text search configuration is invalid"),
						 errdetail("Text search configuration contains invalid expression operator.")));
				break;
		}

		if (ld->debugContext && relatedRuleTmp != NULL)
			token->relatedRule = relatedRuleTmp;
	}

	if (!LexemesBufferContains(&ld->buffer, config, token))
		LexemesBufferAdd(&ld->buffer, config, token, result);

	return result;
}

/*-------------------
 * LexizeExec and helpers functions
 *-------------------
 */

/*
 * Processing of EOF-like token.
 * Return all temporary results if any are saved.
 */
static TSLexeme *
LexizeExecFinishProcessing(LexizeData *ld)
{
	int			i;
	TSLexeme   *res = NULL;

	for (i = 0; i < ld->dslist.listLength; i++)
	{
		TSLexeme   *last_res = res;

		res = TSLexemeUnion(res, ld->dslist.states[i].tmpResult);
		if (last_res)
			pfree(last_res);
	}

	return res;
}

/*
 * Get last accepted result of the phrase-dictionary
 */
static TSLexeme *
LexizeExecGetPreviousResults(LexizeData *ld)
{
	int			i;
	TSLexeme   *res = NULL;

	for (i = 0; i < ld->dslist.listLength; i++)
	{
		if (!ld->dslist.states[i].processed)
		{
			TSLexeme   *last_res = res;

			res = TSLexemeUnion(res, ld->dslist.states[i].tmpResult);
			if (last_res)
				pfree(last_res);
		}
	}

	return res;
}

/*
 * Remove all dictionary states which wasn't used for current token
 */
static void
LexizeExecClearDictStates(LexizeData *ld)
{
	int			i;

	for (i = 0; i < ld->dslist.listLength; i++)
	{
		if (!ld->dslist.states[i].processed)
		{
			DictStateListRemove(&ld->dslist, ld->dslist.states[i].relatedDictionary);
			i = 0;
		}
	}
}

/*
 * Check if there are any dictionaries that didn't processed current token
 */
static bool
LexizeExecNotProcessedDictStates(LexizeData *ld)
{
	int			i;

	for (i = 0; i < ld->dslist.listLength; i++)
		if (!ld->dslist.states[i].processed)
			return true;

	return false;
}

/*
 * Do a lexize processing for a towork queue in LexizeData
 */
static TSLexeme *
LexizeExec(LexizeData *ld, ParsedLex **correspondLexem)
{
	ParsedLex  *token;
	TSMapElement *config;
	TSLexeme   *res = NULL;
	TSLexeme   *prevIterationResult = NULL;
	bool		removeHead = false;
	bool		resetSkipDictionary = false;
	bool		accepted = false;
	int			i;

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

	if (token->type >= ld->cfg->lenmap)
	{
		removeHead = true;
	}
	else
	{
		config = ld->cfg->map[token->type];
		if (config != NULL)
		{
			res = LexizeExecTSElement(ld, token, config);
			prevIterationResult = LexizeExecGetPreviousResults(ld);
			removeHead = prevIterationResult == NULL;
		}
		else
		{
			removeHead = true;
			if (token->type == 0)	/* Processing EOF-like token */
			{
				res = LexizeExecFinishProcessing(ld);
				prevIterationResult = NULL;
			}
		}

		if (LexizeExecNotProcessedDictStates(ld) && (token->type == 0 || config != NULL))	/* Rollback processing */
		{
			int			i;
			ListParsedLex *intermediateTokens = NULL;
			ListParsedLex *acceptedTokens = NULL;

			for (i = 0; i < ld->dslist.listLength; i++)
			{
				if (!ld->dslist.states[i].processed)
				{
					intermediateTokens = &ld->dslist.states[i].intermediateTokens;
					acceptedTokens = &ld->dslist.states[i].acceptedTokens;
					if (prevIterationResult == NULL)
						ld->skipDictionary = ld->dslist.states[i].relatedDictionary;
				}
			}

			if (intermediateTokens && intermediateTokens->head)
			{
				ParsedLex  *head = ld->towork.head;

				ld->towork.head = intermediateTokens->head;
				intermediateTokens->tail->next = head;
				head->next = NULL;
				ld->towork.tail = head;
				removeHead = false;
				LPLClear(&ld->waste);
				if (acceptedTokens && acceptedTokens->head)
				{
					ld->waste.head = acceptedTokens->head;
					ld->waste.tail = acceptedTokens->tail;
				}
			}
			ResultStorageClearLexemes(&ld->delayedResults);
			if (config != NULL)
				res = NULL;
		}

		if (config != NULL)
			LexizeExecClearDictStates(ld);
		else if (token->type == 0)
			DictStateListClear(&ld->dslist);
	}

	if (prevIterationResult)
		res = prevIterationResult;
	else
	{
		int			i;

		for (i = 0; i < ld->dslist.listLength; i++)
		{
			if (ld->dslist.states[i].storeToAccepted)
			{
				LPLAddTailCopy(&ld->dslist.states[i].acceptedTokens, token);
				accepted = true;
				ld->dslist.states[i].storeToAccepted = false;
			}
			else
			{
				LPLAddTailCopy(&ld->dslist.states[i].intermediateTokens, token);
			}
		}
	}

	if (removeHead)
		RemoveHead(ld);

	if (ld->dslist.listLength > 0)
	{
		/*
		 * There is at least one thesaurus dictionary in the middle of
		 * processing. Delay return of the result to avoid wrong lexemes in
		 * case of thesaurus phrase rejection.
		 */
		ResultStorageAdd(&ld->delayedResults, token, res);
		if (accepted)
			ResultStorageMoveToAccepted(&ld->delayedResults);

		/*
		 * Current value of res should not be cleared, because it is stored in
		 * LexemesBuffer
		 */
		res = NULL;
	}
	else
	{
		if (ld->towork.head == NULL)
		{
			TSLexeme   *oldAccepted = ld->delayedResults.accepted;

			ld->delayedResults.accepted = TSLexemeUnionOpt(ld->delayedResults.accepted, ld->delayedResults.lexemes, true);
			if (oldAccepted)
				pfree(oldAccepted);
		}

		/*
		 * Add accepted delayed results to the output of the parsing. All
		 * lexemes returned during thesaurus phrase processing should be
		 * returned simultaneously, since all phrase tokens are processed as
		 * one.
		 */
		if (ld->delayedResults.accepted != NULL)
		{
			/*
			 * Previous value of res should not be cleared, because it is
			 * stored in LexemesBuffer
			 */
			res = TSLexemeUnionOpt(ld->delayedResults.accepted, res, prevIterationResult == NULL);

			ResultStorageClearLexemes(&ld->delayedResults);
			ResultStorageClearAccepted(&ld->delayedResults);
		}
		setCorrLex(ld, correspondLexem);
	}

	if (resetSkipDictionary)
		ld->skipDictionary = InvalidOid;

	res = TSLexemeFilterMulti(res);
	if (res)
		res = TSLexemeRemoveDuplications(res);

	/*
	 * Copy result since it may be stored in LexemesBuffere and removed at the
	 * next step.
	 */
	if (res)
	{
		TSLexeme   *oldRes = res;
		int			resSize = TSLexemeGetSize(res);

		res = palloc0(sizeof(TSLexeme) * (resSize + 1));
		memcpy(res, oldRes, sizeof(TSLexeme) * resSize);
	}

	LexemesBufferClear(&ld->buffer);
	return res;
}

/*-------------------
 * ts_parse API functions
 *-------------------
 */

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

/*-------------------
 * ts_debug and helper functions
 *-------------------
 */

/*
 * Free memory occupied by temporary TSMapElement
 */

static void
ts_debug_free_rule(TSMapElement *element)
{
	if (element != NULL && element->type == TSMAP_EXPRESSION)
	{
		ts_debug_free_rule(element->value.objectExpression->left);
		ts_debug_free_rule(element->value.objectExpression->right);
		pfree(element->value.objectExpression);
		pfree(element);
	}
}

/*
 * Initialize SRF context and text parser for ts_debug execution.
 */
static void
ts_debug_init(Oid cfgId, text *inputText, FunctionCallInfo fcinfo)
{
	TupleDesc	tupdesc;
	char	   *buf;
	int			buflen;
	FuncCallContext *funcctx;
	MemoryContext oldcontext;
	TSDebugContext *context;

	funcctx = SRF_FIRSTCALL_INIT();
	oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

	buf = text_to_cstring(inputText);
	buflen = strlen(buf);

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("function returning record called in context "
						"that cannot accept type record")));

	funcctx->user_fctx = palloc0(sizeof(TSDebugContext));
	funcctx->attinmeta = TupleDescGetAttInMetadata(tupdesc);

	context = funcctx->user_fctx;
	context->cfg = lookup_ts_config_cache(cfgId);
	context->prsobj = lookup_ts_parser_cache(context->cfg->prsId);

	context->tokenTypes = (LexDescr *) DatumGetPointer(OidFunctionCall1(context->prsobj->lextypeOid,
																		(Datum) 0));

	context->prsdata = (void *) DatumGetPointer(FunctionCall2(&context->prsobj->prsstart,
															  PointerGetDatum(buf),
															  Int32GetDatum(buflen)));
	LexizeInit(&context->ldata, context->cfg);
	context->ldata.debugContext = true;
	context->tokentype = 1;

	MemoryContextSwitchTo(oldcontext);
}

/*
 * Get one token from input text and add it to processing queue.
 */
static void
ts_debug_get_token(FuncCallContext *funcctx)
{
	TSDebugContext *context;
	MemoryContext oldcontext;
	int			lenlemm;
	char	   *lemm = NULL;

	context = funcctx->user_fctx;

	oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);
	context->tokentype = DatumGetInt32(FunctionCall3(&(context->prsobj->prstoken),
													 PointerGetDatum(context->prsdata),
													 PointerGetDatum(&lemm),
													 PointerGetDatum(&lenlemm)));

	if (context->tokentype > 0 && lenlemm >= MAXSTRLEN)
	{
#ifdef IGNORE_LONGLEXEME
		ereport(NOTICE,
				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
				 errmsg("word is too long to be indexed"),
				 errdetail("Words longer than %d characters are ignored.",
						   MAXSTRLEN)));
#else
		ereport(ERROR,
				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
				 errmsg("word is too long to be indexed"),
				 errdetail("Words longer than %d characters are ignored.",
						   MAXSTRLEN)));
#endif
	}

	LexizeAddLemm(&context->ldata, context->tokentype, lemm, lenlemm);
	MemoryContextSwitchTo(oldcontext);
}

/*
 * Parse text and print debug information, such as token type, dictionary map
 * configuration, selected command and lexemes for each token.
 * Arguments: regconfiguration(Oid) cfgId, text *inputText
 */
Datum
ts_debug(PG_FUNCTION_ARGS)
{
	FuncCallContext *funcctx;
	TSDebugContext *context;
	MemoryContext oldcontext;

	if (SRF_IS_FIRSTCALL())
	{
		Oid			cfgId = PG_GETARG_OID(0);
		text	   *inputText = PG_GETARG_TEXT_P(1);

		ts_debug_init(cfgId, inputText, fcinfo);
	}

	funcctx = SRF_PERCALL_SETUP();
	context = funcctx->user_fctx;

	while (context->tokentype > 0 && context->leftTokens == NULL)
	{
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);
		ts_debug_get_token(funcctx);

		context->savedLexemes = LexizeExec(&context->ldata, &(context->leftTokens));

		MemoryContextSwitchTo(oldcontext);
	}

	while (context->leftTokens == NULL && context->ldata.towork.head != NULL)
		context->savedLexemes = LexizeExec(&context->ldata, &(context->leftTokens));

	if (context->leftTokens && context->leftTokens && context->leftTokens->type > 0)
	{
		HeapTuple	tuple;
		Datum		result;
		char	  **values;
		ParsedLex  *lex = context->leftTokens;
		StringInfo	str = NULL;
		TSLexeme   *ptr;

		values = palloc0(sizeof(char *) * 7);
		str = makeStringInfo();
		initStringInfo(str);

		values[0] = context->tokenTypes[lex->type - 1].alias;
		values[1] = context->tokenTypes[lex->type - 1].descr;

		values[2] = palloc0(sizeof(char) * (lex->lenlemm + 1));
		memcpy(values[2], lex->lemm, sizeof(char) * lex->lenlemm);

		initStringInfo(str);
		appendStringInfoChar(str, '{');
		if (lex->type < context->ldata.cfg->lenmap && context->ldata.cfg->map[lex->type])
		{
			Oid *dictionaries = TSMapGetDictionaries(context->ldata.cfg->map[lex->type]);
			Oid *currentDictionary = NULL;
			for (currentDictionary = dictionaries; *currentDictionary != InvalidOid; currentDictionary++)
			{
				if (currentDictionary != dictionaries)
					appendStringInfoChar(str, ',');

				TSMapPrintDictName(*currentDictionary, str);
			}
		}
		appendStringInfoChar(str, '}');
		values[3] = str->data;

		if (lex->type < context->ldata.cfg->lenmap && context->ldata.cfg->map[lex->type])
		{
			initStringInfo(str);
			TSMapPrintElement(context->ldata.cfg->map[lex->type], str);
			values[4] = str->data;

			initStringInfo(str);
			if (lex->relatedRule)
			{
				TSMapPrintElement(lex->relatedRule, str);
				values[5] = str->data;
				str = makeStringInfo();
				initStringInfo(str);
				ts_debug_free_rule(lex->relatedRule);
				lex->relatedRule = NULL;
			}
		}

		initStringInfo(str);
		ptr = context->savedLexemes;
		if (context->savedLexemes)
			appendStringInfoChar(str, '{');

		while (ptr && ptr->lexeme)
		{
			if (ptr != context->savedLexemes)
				appendStringInfoString(str, ", ");
			appendStringInfoString(str, ptr->lexeme);
			ptr++;
		}
		if (context->savedLexemes)
			appendStringInfoChar(str, '}');
		if (context->savedLexemes)
			values[6] = str->data;
		else
			values[6] = NULL;

		tuple = BuildTupleFromCStrings(funcctx->attinmeta, values);
		result = HeapTupleGetDatum(tuple);

		context->leftTokens = lex->next;
		pfree(lex);
		if (context->leftTokens == NULL && context->savedLexemes)
			pfree(context->savedLexemes);

		SRF_RETURN_NEXT(funcctx, result);
	}

	FunctionCall1(&(context->prsobj->prsend), PointerGetDatum(context->prsdata));
	SRF_RETURN_DONE(funcctx);
}

/*-------------------
 * Headline framework
 *-------------------
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
	ParsedLex  *lexs = NULL;
	TSConfigCacheEntry *cfg;
	TSParserCacheEntry *prsobj;
	void	   *prsdata;

	cfg = lookup_ts_config_cache(cfgId);
	prsobj = lookup_ts_parser_cache(cfg->prsId);

	prsdata = (void *) DatumGetPointer(FunctionCall2(&(prsobj->prsstart),
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

		do
		{
			if ((norms = LexizeExec(&ldata, &lexs)) != NULL)
			{
				prs->vectorpos++;
				addHLParsedLex(prs, query, lexs, norms);
			}
			else
				addHLParsedLex(prs, query, lexs, NULL);
			lexs = NULL;
		} while (norms);

	} while (type > 0 || ldata.towork.head);

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
				if (wrd->selected && (wrd == prs->words || !(wrd - 1)->selected))
				{
					memcpy(ptr, prs->startsel, prs->startsellen);
					ptr += prs->startsellen;
				}
				memcpy(ptr, wrd->word, wrd->len);
				ptr += wrd->len;
				if (wrd->selected && ((wrd + 1 - prs->words) == prs->curwords || !(wrd + 1)->selected))
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
