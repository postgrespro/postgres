/*-------------------------------------------------------------------------
 *
 * jsonb_toast_array.c
 *		JSONB array logically toasted into chunks.
 *
 * Portions Copyright (c) 2014-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 2021-2022, PostgrePro
 *
 * IDENTIFICATION
 *	  contrib/jsonb_toaster/jsonb_toast_array.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"
#include "jsonb_toaster.h"
#include "access/heapam.h"
#include "access/heaptoast.h"
#include "access/table.h"
#include "access/tableam.h"
#include "catalog/toasting.h"

typedef struct JsonxaState
{
	JsonxArray *jxa;
	bool		need_free;
} JsonxaState;

#define JsonxaStateGet(jc) ((JsonxaState *) &(jc)->_data)
#define JsonxaArrayGet(jc) (((JsonxaState *) &(jc)->_data)->jxa)

typedef struct JsonxaArrayIterator
{
	JsonxArray *array;
	int			cur_chunk;
	int			cur_index;
	JsonxArrayChunkPtr *chunk_ptrs;
	char	   *inline_chunks;
	Json	   *cur_chunk_js;
	JsonIterator *cur_chunk_iter;
	int			cur_chunk_idx;

	Relation toastrel;
	MemoryContext mcxt;
	struct TupleTableSlot *slot;
	struct IndexFetchTableData *heapfetch;
	SnapshotData snapshot;

	MemoryContextCallback free_cb;
} JsonxaArrayIterator;

static void
jsonxaArrayIteratorClose(JsonxaArrayIterator *iter)
{
	if (iter->toastrel)
	{
		table_close(iter->toastrel, AccessShareLock);
		iter->toastrel = NULL;
	}

	if (iter->heapfetch)
	{
		table_index_fetch_end(iter->heapfetch);
		iter->heapfetch = NULL;
	}

	if (iter->slot)
	{
		ExecDropSingleTupleTableSlot(iter->slot);
		iter->slot = NULL;
	}
}

static void
jsonxaArrayIteratorFree(JsonxaArrayIterator *it)
{
	jsonxaArrayIteratorClose(it);

	if (it->cur_chunk_iter)
		JsonIteratorFree(it->cur_chunk_iter);
}

static Datum
jsonxaArrayIteratorFetchChunk(JsonxaArrayIterator *it, JsonxArrayChunkPtr ptr)
{
	bool		all_dead = false;
	bool		heap_continue = false;
	bool		shouldFree = false;
	bool		found;
	HeapTuple	ttup;
	Pointer		chunk;
	int32		seqno PG_USED_FOR_ASSERTS_ONLY;
	bool		isnull;

	if (!it->slot)
	{
		MemoryContext oldcxt = MemoryContextSwitchTo(it->mcxt);

		if (!it->toastrel)
		{
			it->toastrel = table_open(it->array->toastrelid, AccessShareLock);
			init_toast_snapshot(&it->snapshot);
		}

		it->slot = table_slot_create(it->toastrel, NULL);
		it->heapfetch = table_index_fetch_begin(it->toastrel);

		MemoryContextSwitchTo(oldcxt);
	}

	//if (iter->compressed_chunk_tids)
	//	jsonx_toast_decompress_tid(it->compressed_chunk_tids, iter->chunk_tids, iter->nextidx);

	found = table_index_fetch_tuple(it->heapfetch, &ptr,
									&it->snapshot, it->slot,
									&heap_continue, &all_dead);
	//Assert(!heap_continue);

	if (!found)
	{
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg_internal("missing jsonb array chunk: %d:%d",
								 ItemPointerGetBlockNumber(&ptr),
								 ItemPointerGetOffsetNumber(&ptr))));

		return (Datum) 0;
	}

	ttup = ExecFetchSlotHeapTuple(it->slot, false, &shouldFree);
	Assert(!shouldFree);

	/*
	 * Have a chunk, extract the sequence number and the data
	 */
	seqno = DatumGetInt32(fastgetattr(ttup, 2, it->toastrel->rd_att, &isnull));
	Assert(!isnull);
	Assert(seqno == 0);

	chunk = DatumGetPointer(fastgetattr(ttup, 3, it->toastrel->rd_att, &isnull));
	Assert(!isnull);

	return PointerGetDatum(chunk);
}

static void
jsonxaArrayIteratorInit(JsonxaArrayIterator *it, JsonxArray *jxa, bool autofree)
{
	memset(it, 0, sizeof(*it));

	it->array = jxa;
	it->cur_chunk = 0;
	it->cur_index = -1;
	it->cur_chunk_idx = -1;
	it->cur_chunk_iter = NULL;
	it->chunk_ptrs = JSONX_ARRAY_CHUNK_PTRS(jxa);
	it->inline_chunks = (char *) INTALIGN((Pointer) &it->chunk_ptrs[jxa->n_chunks]);
	it->mcxt = CurrentMemoryContext;

	if (autofree)
	{
		it->free_cb.func = (void (*)(void *)) jsonxaArrayIteratorFree;
		it->free_cb.arg = it;
		MemoryContextRegisterResetCallback(CurrentMemoryContext, &it->free_cb);
	}
}

static bool
jsonxaArrayIteratorNextFromChunk(JsonxaArrayIterator *it, JsonValue *jv)
{
	JsonIteratorToken tok;

	if (!it->cur_chunk_iter)
		return false;

	tok = JsonIteratorNext(&it->cur_chunk_iter, jv, true);
	if (tok == WJB_ELEM)
	{
		it->cur_chunk_idx++;
		it->cur_index++;
		return true;
	}

	Assert(tok == WJB_END_ARRAY);
	tok = JsonIteratorNext(&it->cur_chunk_iter, jv, true);
	Assert(tok == WJB_DONE);
	Assert(!it->cur_chunk_iter);

	return false;
}

static void
jsonxaArrayIteratorLoadCurrentChunk(JsonxaArrayIterator *it)
{
	JsonxArrayChunkPtr ptr = it->chunk_ptrs[it->cur_chunk];
	Datum		data;

	if (ItemPointerIsValid(&ptr))
		data = jsonxaArrayIteratorFetchChunk(it, ptr);
	else
	{
		int			inline_offset = ItemPointerGetBlockNumberNoCheck(&ptr);

		data = PointerGetDatum(it->inline_chunks + inline_offset);
	}

	it->cur_chunk_js = DatumGetJsonbP(data);
}

static bool
jsonxaArrayIteratorNext(JsonxaArrayIterator *it, JsonValue *jv)
{
	for (;;)
	{
		if (!it->cur_chunk_iter)
		{
			JsonIteratorToken tok PG_USED_FOR_ASSERTS_ONLY;

			if (it->cur_chunk >= it->array->n_chunks)
			{
				it->cur_chunk = it->array->n_chunks;
				it->cur_chunk_js = NULL;
				jsonxaArrayIteratorClose(it);
				return false;
			}

			jsonxaArrayIteratorLoadCurrentChunk(it);

			it->cur_chunk_iter = JsonIteratorInit(JsonRoot(it->cur_chunk_js));
			tok = JsonIteratorNext(&it->cur_chunk_iter, jv, true);
			Assert(tok == WJB_BEGIN_ARRAY);
		}

		if (jsonxaArrayIteratorNextFromChunk(it, jv))
			return true;

		it->cur_chunk_js = NULL;
		it->cur_chunk_iter = NULL;
		it->cur_chunk_idx = -1;
		it->cur_chunk++;
	}
}

typedef struct JsonxaIterator
{
	JsonIterator jit;
	JsonxaArrayIterator *jxait;
	enum { JXAITER_BEGIN, JXAITER_ELEM, JXAITER_END } state;
} JsonxaIterator;

static JsonIteratorToken
jsonxaIteratorNext(JsonIterator **jsit, JsonValue *jbv, bool skipNested)
{
	JsonxaIterator *it = *(JsonxaIterator **) jsit;
	JsonIterator *child_it;

	if (!it)
		return WJB_DONE;

	if (it->state == JXAITER_BEGIN)
	{
		it->state = JXAITER_ELEM;
		JsonValueInitArray(jbv, it->jxait->array->n_elems, 0, false);
		return WJB_BEGIN_ARRAY;
	}

	Assert(it->state == JXAITER_ELEM);

	if (!jsonxaArrayIteratorNext(it->jxait, jbv))
	{
		*jsit = JsonIteratorFreeAndGetParent(*jsit);
		return WJB_END_ARRAY;
	}

	if (skipNested || jbv->type != jbvBinary)
		return WJB_ELEM;

	child_it = JsonIteratorInit(jbv->val.binary.data);
	child_it->parent = *jsit;
	*jsit = child_it;

	return JsonIteratorNext(&child_it, jbv, true);
}

static JsonIterator *
jsonxaIteratorInit(JsonContainer *jc)
{
	JsonxArray *jxa = JsonxaArrayGet(jc);
	JsonxaIterator *it = palloc(sizeof(*it));

	it->jit.next = jsonxaIteratorNext;
	it->jit.container = jc;
	it->jit.parent = NULL;

	it->state = JXAITER_BEGIN;

	it->jxait = palloc(sizeof(*it->jxait));
	jsonxaArrayIteratorInit(it->jxait, jxa, true);

	return &it->jit;
}

static JsonbValue *
jsonxaFindKeyInObject(JsonContainer *jsc,
					 const char *keyVal, int keyLen, JsonbValue *res,
					 JsonFieldPtr *ptr)
{
	elog(ERROR, "cannot find object key in jsonb array");
	return NULL;
}

static int
jsonxaFindChunkByIndex(JsonxArray *jxa, int index, JsonxArrayChunkPtr *chunk_ptr)
{
	JsonxArrayChunkPtr *chunk_ptrs = JSONX_ARRAY_CHUNK_PTRS(jxa);
	int			lo = 0;
	int			hi = jxa->n_chunks - 1;

	if (index < 0 || index >= jxa->n_elems)
		return -1;

	while (lo < hi)
	{
		int			mid = lo + (hi - lo + 1) / 2;
		JsonxArrayChunkOffset offs = jxa->chunk_offsets[mid];

		if (offs == index)
		{
			lo = hi = mid;
			break;
		}

		if (offs > index)
			hi = mid - 1;
		else
			lo = mid;
	}

	Assert(lo == hi);
	Assert(index >= jxa->chunk_offsets[lo]);
	Assert(lo >= jxa->n_chunks - 1 || index < jxa->chunk_offsets[lo + 1]);

	ItemPointerCopy(&chunk_ptrs[lo], chunk_ptr);

	return lo;
}

static JsonbValue *
jsonxaGetArrayElement(JsonContainer *jc, uint32 index, JsonFieldPtr *ptr)
{
	JsonxArray *jxa = JsonxaArrayGet(jc);
	JsonxArrayChunkPtr chunk_ptr;
	JsonxaArrayIterator it;
	int			i = jsonxaFindChunkByIndex(jxa, index, &chunk_ptr);

	if (i < 0)
		return NULL;

	jsonxaArrayIteratorInit(&it, jxa, false);
	it.cur_chunk = i;
	jsonxaArrayIteratorLoadCurrentChunk(&it);
	jsonxaArrayIteratorFree(&it);

	return JsonGetArrayElement(JsonRoot(it.cur_chunk_js),
							   index - jxa->chunk_offsets[i]);
}

static JsonbValue *
jsonxaFindValueInArray(const JsonContainer *jc, const JsonValue *key)
{
	JsonxaArrayIterator it;
	JsonxArray *jxa = JsonxaArrayGet(jc);
	JsonValue	elem;
	JsonValue  *result = NULL;

	jsonxaArrayIteratorInit(&it, jxa, false);

	while (jsonxaArrayIteratorNext(&it, &elem))
	{
		if (key->type == elem.type &&
			equalsJsonbScalarValue(key, &elem))
		{
			result = palloc(sizeof(*result));
			*result = elem;
			break;
		}
	}

	jsonxaArrayIteratorFree(&it);

	return result;
}

static void
jsonxaInitContainer(JsonContainerData *jc, JsonxArray *jxa, int len,
					Oid toasterid, bool need_free)
{
	JsonxaState *state = JsonxaStateGet(jc);

	state->jxa = jxa;
	state->need_free = need_free;

	jc->ops = &jsonxaContainerOps;
	jc->len = len;
	jc->toasterid = toasterid;
	jc->type = jbvArray;
	jc->size = jxa->n_elems;
}

static JsonxArray *
jsonxaGetArray(Datum value)
{
	uint32		header PG_USED_FOR_ASSERTS_ONLY;

	Assert(VARATT_IS_CUSTOM(value));

	header = JSONX_CUSTOM_PTR_GET_HEADER(value);
	Assert((header & JSONX_POINTER_TYPE_MASK) == JSONX_CHUCKED_ARRAY);

	return (void *) JSONX_CUSTOM_PTR_GET_DATA(value);
}

void
jsonxaInit(JsonContainerData *jc, Datum value)
{
	JsonxArray *jxa = jsonxaGetArray(value);

	jsonxaInitContainer(jc, jxa,
						VARSIZE_ANY(value) - JSONX_CUSTOM_PTR_HEADER_SIZE, // FIXME
						VARATT_CUSTOM_GET_TOASTERID(value),
						false);
}

static JsonContainer *
jsonxaCopy(JsonContainer *jc)
{
	JsonContainer *jc_copy = JsonContainerAlloc(&jsonxaContainerOps);
	JsonxaState *state = JsonxaStateGet(jc_copy);

	memcpy((JsonContainerData *) jc_copy, jc, JsonContainerAllocSize(jsonxaContainerOps.data_size));

	state->jxa = memcpy(palloc(jc->len), state->jxa, jc->len);
	state->need_free = true;

	return jc_copy;
}

static void
jsonxaFree(JsonContainer *jc)
{
	JsonxaState *state = JsonxaStateGet(jc);

	if (state->need_free)
		pfree(state->jxa);
}

static JsonObjectMutator *
jsonxaObjectMutatorInit(JsonContainer *jc, JsonMutator *parent)
{
	elog(ERROR, "cannot create object mutator for jsonb array");
	return NULL;
}

typedef struct JsonxaMutator
{
	JsonArrayMutator array;
	JsonxaArrayIterator iter;

	JsonxArrayChunkInfo	*chunks;

	JsonbParseState *chunk_mut;
	int			mut_chunk_offset;
	int			mut_chunk_no;
	int			cur_chunk_offset;
	int			last_copied_chunk;

	Oid			toasterid;
	int			n_elems;
	int			n_chunks;
	int			offset_diff;
	bool		changed;
} JsonxaMutator;

static void
jsonxaMutatorFinishMutatedChunk(JsonxaMutator *jxamut)
{
	JsonValue  *jbv_arr;
	JsonxaArrayIterator *iter = &jxamut->iter;
	int			i = jxamut->n_chunks;

	if (jxamut->mut_chunk_no == iter->cur_chunk)
	{
		if (jxamut->array.mutator.cur_exists)
			pushJsonbValue(&jxamut->chunk_mut, WJB_ELEM, &jxamut->array.mutator.cur_val);

		if (iter->cur_chunk_iter)
		{
			JsonIteratorToken tok;
			JsonValue	elem;

			while ((tok = JsonIteratorNext(&iter->cur_chunk_iter, &elem, true)) == WJB_ELEM)
				pushJsonbValue(&jxamut->chunk_mut, WJB_ELEM, &elem);

			Assert(tok == WJB_END_ARRAY);
			tok = JsonIteratorNext(&iter->cur_chunk_iter, &elem, true);
			Assert(tok == WJB_DONE);
			iter->cur_chunk_iter = NULL;
		}
	}

	jbv_arr = pushJsonbValue(&jxamut->chunk_mut, WJB_END_ARRAY, NULL);

	jxamut->chunks[i].jb = JsonValueToJsonbDatum(jbv_arr);
	jxamut->chunks[i].offset = JSONXA_INLINE_CHUNK | jxamut->mut_chunk_offset;
	ItemPointerSetInvalid(&jxamut->chunks[i].ptr);

	jxamut->n_chunks++;
	jxamut->last_copied_chunk = jxamut->mut_chunk_no;
	jxamut->chunk_mut = NULL;
}

static void
jsonxaMutatorCopyChunk(JsonxaMutator *jxamut, int i)
{
	JsonxaArrayIterator *iter = &jxamut->iter;
	int			n_chunks = jxamut->n_chunks;

	Assert(i >= 0);

	jxamut->chunks[jxamut->n_chunks].offset = iter->array->chunk_offsets[i] + jxamut->offset_diff;
	ItemPointerCopy(&iter->chunk_ptrs[i], &jxamut->chunks[n_chunks].ptr);

	if (!ItemPointerIsValid(&jxamut->chunks[n_chunks].ptr))
	{
		int			offset = ItemPointerGetBlockNumberNoCheck(&jxamut->chunks[n_chunks].ptr);

		jxamut->chunks[n_chunks].offset |= JSONXA_INLINE_CHUNK;
		jxamut->chunks[n_chunks].jb = PointerGetDatum(iter->inline_chunks + offset);
	}

	jxamut->n_chunks = ++n_chunks;
	jxamut->last_copied_chunk = i;
}

static bool
jsonxaMutatorNext(JsonArrayMutator *mut)
{
	JsonxaMutator *jxamut = (JsonxaMutator *) mut;

	if (jxamut->chunk_mut && mut->mutator.cur_exists &&
		jxamut->mut_chunk_no == jxamut->iter.cur_chunk)
		pushJsonbValue(&jxamut->chunk_mut, WJB_ELEM, &mut->mutator.cur_val);

	mut->mutator.cur_exists = jsonxaArrayIteratorNext(&jxamut->iter, &mut->mutator.cur_val);

	return mut->mutator.cur_exists;
}

static bool
jsonxaMutatorFindIndex(JsonArrayMutator *mut, int index)
{
	JsonxaMutator *jxamut = (JsonxaMutator *) mut;
	JsonxArray *jxa = jxamut->iter.array;
	JsonxArrayChunkPtr chunk_ptr;
	int			chunk_no;
	int			chunk_offs;
	JsonValue   *elem;

	if (jxamut->chunk_mut)
		elog(ERROR, "jsonb array already modified by iteration");

	chunk_no = jsonxaFindChunkByIndex(jxa, index, &chunk_ptr);
	chunk_offs = jxa->chunk_offsets[chunk_no];

	if (chunk_no < 0)
	{
		mut->mutator.cur_exists = false;
		mut->cur_index = index;
		return false;
	}

	if (jxamut->iter.cur_chunk_iter)
	{
		JsonIteratorFree(jxamut->iter.cur_chunk_iter);
		jxamut->iter.cur_chunk_iter = NULL;
	}

	if (chunk_no != jxamut->iter.cur_chunk ||
		!jxamut->iter.cur_chunk_js)
	{
		jxamut->iter.cur_chunk = chunk_no;
		jsonxaArrayIteratorLoadCurrentChunk(&jxamut->iter);
	}

	elem = JsonGetArrayElement(JsonRoot(jxamut->iter.cur_chunk_js),
							   index - chunk_offs);

	if (!elem)
		elog(ERROR, "missing element in jsonb array chunk");

	mut->mutator.cur_val = *elem;
	mut->mutator.cur_exists = true;
	mut->cur_index = index;
	jxamut->iter.cur_chunk_idx = index - chunk_offs;

	pfree(elem);

	return true;
}

static void
jsonxaMutatorFindLast(JsonArrayMutator *mut)
{
	JsonxaMutator *jxamut = (JsonxaMutator *) mut;
	JsonxArray *jxa = jxamut->iter.array;

	if (jxamut->chunk_mut)
		elog(ERROR, "jsonb array already modified by iteration");

	jxamut->iter.cur_chunk = jxa->n_chunks;
	mut->mutator.cur_exists = false;
	mut->cur_index = jxa->n_elems;
}

static void
jsonxaMutatorCreateCurChunkMutator(JsonxaMutator *jxamut)
{
	int			cur_chunk = jxamut->iter.cur_chunk;
	JsonIteratorToken tok;
	JsonValue	elem;

	Assert(cur_chunk >= 0);

	if (jxamut->chunk_mut &&
		jxamut->mut_chunk_no == cur_chunk)
		return;

	if (!jxamut->chunk_mut ||
		jxamut->mut_chunk_no != cur_chunk - 1)
	{
		if (jxamut->chunk_mut)
			jsonxaMutatorFinishMutatedChunk(jxamut);

		for (int i = jxamut->last_copied_chunk + 1; i < cur_chunk; i++)
			jsonxaMutatorCopyChunk(jxamut, i);

		if (jxamut->iter.cur_chunk >= jxamut->iter.array->n_chunks)
		{
			Assert(jxamut->iter.cur_chunk_idx == -1);
			jxamut->mut_chunk_offset = jxamut->n_elems;
		}
		else
		{
			/* save current chunk offset before modification of offset_diff */
			jxamut->mut_chunk_offset =
				jxamut->iter.array->chunk_offsets[cur_chunk] + jxamut->offset_diff;
		}

		jxamut->chunk_mut = NULL;
		pushJsonbValue(&jxamut->chunk_mut, WJB_BEGIN_ARRAY, NULL);
	}

	jxamut->mut_chunk_no = cur_chunk;

	if (jxamut->iter.cur_chunk_idx < 0 ||
		(jxamut->iter.cur_chunk_idx == 0 && jxamut->iter.cur_chunk_iter))
		return;

	Assert(jxamut->iter.cur_chunk_js);

	if (jxamut->iter.cur_chunk_iter)
		JsonIteratorFree(jxamut->iter.cur_chunk_iter);

	jxamut->iter.cur_chunk_iter =
		JsonIteratorInit(JsonRoot(jxamut->iter.cur_chunk_js));

	tok = JsonIteratorNext(&jxamut->iter.cur_chunk_iter, &elem, true);
	Assert(tok == WJB_BEGIN_ARRAY);

	for (int i = 0; i < jxamut->iter.cur_chunk_idx; i++)
	{
		tok = JsonIteratorNext(&jxamut->iter.cur_chunk_iter, &elem, true);

		if (tok != WJB_ELEM)
			break;

		pushJsonbValue(&jxamut->chunk_mut, WJB_ELEM, &elem);
	}

	if (jxamut->iter.cur_chunk_idx >= 0)
	{
		tok = JsonIteratorNext(&jxamut->iter.cur_chunk_iter, &jxamut->array.mutator.cur_val, true);
		jxamut->array.mutator.cur_exists = tok == WJB_ELEM;
	}
}

static void
jsonxaMutatorInsert(JsonArrayMutator *mut, JsonValue *val)
{
	JsonxaMutator *jxamut = (JsonxaMutator *) mut;

	jsonxaMutatorCreateCurChunkMutator(jxamut);

	pushJsonbValue(&jxamut->chunk_mut, WJB_ELEM, val);

	jxamut->n_elems++;
	jxamut->offset_diff++;
}

static JsonValue *
jsonxaMutatorReplaceCurrent(JsonMutator *mut, JsonValue *val)
{
	JsonxaMutator *jxamut = (JsonxaMutator *) mut;

	jsonxaMutatorCreateCurChunkMutator(jxamut);

	if (mut->cur_exists && !val)
	{
		mut->cur_exists = false;
		jxamut->n_elems--;
		jxamut->offset_diff--;
	}
	else if (!mut->cur_exists && val)
	{
		pushJsonbValue(&jxamut->chunk_mut, WJB_ELEM, val);
		jxamut->n_elems++;
		jxamut->offset_diff++;
	}
	else if (mut->cur_exists)
	{
		pushJsonbValue(&jxamut->chunk_mut, WJB_ELEM, val);
		mut->cur_exists = false;
	}

	return NULL;
}

static Datum
jsonx_toast_array_chunks(Relation rel, Oid toastrelid, Oid toasterid,
						 int options, int n_elems, int n_chunks,
						 JsonxArrayChunkInfo *chunks)
{
	JsonxArrayChunkOffset *p_chunk_offs;
	JsonxArrayChunkPtr *p_chunk_ptrs;
	JsonxArray *array;
	JsonbParseState *ps = NULL;
	struct varlena *res;
	int			inline_chunks_size = 0;
	char	   *p_inline_chunks;
	int			inline_offset = 0;
	int			merged_offset = 0;
	int			n_merged_chunks = 0;
	int			allocated_inline_chunks_size PG_USED_FOR_ASSERTS_ONLY;
	int			chunk_no = 0;

	for (int i = 0; i < n_chunks; i++)
	{
		if (chunks[i].jb && (chunks[i].offset & JSONXA_INLINE_CHUNK))
		{
			inline_chunks_size += INTALIGN(VARSIZE_ANY(chunks[i].jb));

			if (i > 0 && chunks[i - 1].jb && (chunks[i - 1].offset & JSONXA_INLINE_CHUNK))
				n_merged_chunks++;
		}
	}

	allocated_inline_chunks_size = inline_chunks_size;
	res = jsonx_toast_make_pointer_array(toasterid, n_chunks - n_merged_chunks, inline_chunks_size, &array);

	array->n_elems = n_elems;
	array->n_chunks = n_chunks - n_merged_chunks;
	array->toastrelid = toastrelid;

	p_chunk_offs = &array->chunk_offsets[0];
	p_chunk_ptrs = JSONX_ARRAY_CHUNK_PTRS(array);
	p_inline_chunks = (char *) INTALIGN((Pointer) &p_chunk_ptrs[array->n_chunks]);

	for (int i = 0; i < n_chunks; i++)
	{
		Datum		jb = chunks[i].jb;
		JsonxArrayChunkOffset offs = chunks[i].offset;

		if (jb == (Datum) 0)
		{
			Assert(!(offs & JSONXA_INLINE_CHUNK));
			Assert(ItemPointerIsValid(&chunks[i].ptr));
			ItemPointerCopy(&chunks[i].ptr, &p_chunk_ptrs[chunk_no]);
		}
		else
		{
			if (offs & JSONXA_INLINE_CHUNK)
			{
				int			size;

				/* start merge of consecutive inline chunks */
				if (!ps &&
					i + 1 < n_chunks &&
					chunks[i + 1].jb &&
					(chunks[i + 1].offset & JSONXA_INLINE_CHUNK))
				{
					merged_offset = offs;
					pushJsonbValue(&ps, WJB_BEGIN_ARRAY, NULL);
				}

				/* merge current chunk */
				if (ps)
				{
					Json	   *js = DatumGetJsonbP(jb);
					JsonIterator *it = JsonIteratorInit(JsonRoot(js));
					JsonIteratorToken tok;
					JsonValue	elem;
					JsonValue  *jbv_arr;

					/* copy current chunk's array */
					tok = JsonIteratorNext(&it, &elem, true);
					Assert(tok == WJB_BEGIN_ARRAY);

					while ((tok = JsonIteratorNext(&it, &elem, true)) == WJB_ELEM)
						pushJsonbValue(&ps, WJB_ELEM, &elem);

					Assert(tok == WJB_END_ARRAY);
					tok = JsonIteratorNext(&it, &elem, true);
					Assert(tok == WJB_DONE);

					/* continue merge if not last inline chunk in sequence */
					if (i + 1 < n_chunks &&
						chunks[i + 1].jb &&
						(chunks[i + 1].offset & JSONXA_INLINE_CHUNK))
						continue;

					/* finish merge */
					jbv_arr = pushJsonbValue(&ps, WJB_END_ARRAY, NULL);
					jb = JsonValueToJsonbDatum(jbv_arr);
					ps = NULL;
					offs = merged_offset;
				}

				ItemPointerSet(&p_chunk_ptrs[chunk_no], inline_offset, InvalidOffsetNumber);

				size = VARSIZE_ANY(DatumGetPointer(jb));
				memcpy(p_inline_chunks, DatumGetPointer(jb), size);

				p_inline_chunks += INTALIGN(size);
				inline_offset += INTALIGN(size);

				offs &= ~JSONXA_INLINE_CHUNK;
			}
			else
			{
				Datum		chunk;
				ItemPointerData chunk_tids[1];
				struct varatt_external toast_ptr;

				Assert(rel);
				Assert(VARSIZE_ANY(DatumGetPointer(jb)) <= TOAST_MAX_CHUNK_SIZE);

				chunk =	jsonx_toast_save_datum_ext(rel, toasterid, jb,
												   NULL, options, NULL, chunk_tids,
												   false /* compress_chunks*/);

				Assert(VARATT_IS_EXTERNAL(chunk));
				VARATT_EXTERNAL_GET_POINTER(toast_ptr, chunk);
				Assert(toastrelid == toast_ptr.va_toastrelid);

				ItemPointerCopy(&chunk_tids[0], &p_chunk_ptrs[chunk_no]);
			}
		}

		p_chunk_offs[chunk_no] = offs;
		chunk_no++;
	}

	Assert(chunk_no = array->n_chunks);
	Assert(inline_chunks_size <= allocated_inline_chunks_size);

	return PointerGetDatum(res);
}

static JsonValue *
jsonxaMutatorClose(JsonArrayMutator *mut)
{
	JsonxaMutator *jxamut = (JsonxaMutator *) mut;
	JsonxaArrayIterator *iter = &jxamut->iter;
	JsonxArray *jxa = iter->array;
	JsonContainerData *jc;
	JsonValue  *jbv;
	Datum		res;

	if (!jxamut->changed)
	{
		/* TODO */
	}

	/* finish current inline chunk, if changed */
	if (jxamut->chunk_mut)
		jsonxaMutatorFinishMutatedChunk(jxamut);

	/* copy remaining chunk pointers */
	for (int i = jxamut->last_copied_chunk + 1; i < jxa->n_chunks; i++)
		jsonxaMutatorCopyChunk(jxamut, i);

	/* make resulting datum */
	res = jsonx_toast_array_chunks(NULL, jxa->toastrelid,
								   jxamut->toasterid, 0,
								   jxamut->n_elems, jxamut->n_chunks,
								   jxamut->chunks);

	jc = JsonContainerAlloc(&jsonxaContainerOps);
	jsonxaInit(jc, res);

	jbv = palloc(sizeof(*jbv));
	JsonValueInitBinary(jbv, jc);

	jsonxaArrayIteratorFree(&jxamut->iter);

	for (int i = 0; i < jxamut->n_chunks; i++)
	{
		if (jxamut->chunks[i].jb != (Datum) 0 &&
			!(jxamut->chunks[i].offset & JSONXA_INLINE_CHUNK))
			pfree(DatumGetPointer(jxamut->chunks[i].jb));
	}

	pfree(jxamut->chunks);

	if (mut->mutator.parent)
		JsonMutatorReplaceCurrent(mut->mutator.parent, jbv);

	return jbv;
}

static JsonObjectMutator *
jsonxaObjectMutatorOpen(JsonMutator *mut)
{
	if (mut->cur_exists && mut->cur_val.type != jbvBinary)
	{
		Assert(mut->cur_val.type != jbvObject);
		elog(ERROR, "invalid jsonb object value type: %d", mut->cur_val.type);
	}

	if (mut->cur_exists)
		return JsonObjectMutatorInit(mut->cur_val.val.binary.data, mut);
	else
		return JsonObjectMutatorInitGeneric(NULL, mut);
}

static JsonArrayMutator *
jsonxaArrayMutatorOpen(JsonMutator *mut)
{
	if (mut->cur_exists && mut->cur_val.type != jbvBinary)
	{
		Assert(mut->cur_val.type != jbvArray);
		elog(ERROR, "invalid array object value type: %d", mut->cur_val.type);
	}

	if (mut->cur_exists)
		return JsonArrayMutatorInit(mut->cur_val.val.binary.data, mut);
	else
		return JsonArrayMutatorInitGeneric(NULL, mut);
}

static JsonArrayMutator *
jsonxaArrayMutatorInit(JsonContainer *jc, JsonMutator *parent)
{
	JsonxArray *jxa = JsonxaArrayGet(jc);
	JsonxaMutator *mut = palloc(sizeof(*mut));

	mut->array.mutator.parent = parent;
	mut->array.mutator.type = jbvArray;
	mut->array.mutator.cur_key = NULL;
	mut->array.mutator.cur_exists = false;
	mut->array.mutator.replace = jsonxaMutatorReplaceCurrent;
	mut->array.mutator.openObject = jsonxaObjectMutatorOpen;
	mut->array.mutator.openArray = jsonxaArrayMutatorOpen;

	mut->array.next = jsonxaMutatorNext;
	mut->array.find = jsonxaMutatorFindIndex;
	mut->array.last = jsonxaMutatorFindLast;
	mut->array.insert = jsonxaMutatorInsert;
	mut->array.close = jsonxaMutatorClose;
	mut->array.cur_index = -1;

	jsonxaArrayIteratorInit(&mut->iter, jxa, false);

	mut->n_elems = jxa->n_elems;
	mut->n_chunks = 0;
	mut->toasterid = jc->toasterid;
	mut->changed = false;

	mut->chunk_mut = NULL;
	mut->mut_chunk_offset = 0;
	mut->mut_chunk_no = 0;
	mut->last_copied_chunk = -1;
	mut->offset_diff = 0;

	mut->chunks = palloc0(sizeof(*mut->chunks) * (jxa->n_chunks + 1));

	return &mut->array;
}

static void *
jsonxaEncode(JsonValue *jv, JsonContainerOps *ops, Oid toasterid)
{
	if (ops == &jsonbContainerOps && jv->type == jbvBinary &&
		jv->val.binary.data->ops == &jsonxaContainerOps)
	{
		JsonContainer *jc = jv->val.binary.data;
		JsonxArray *jxa = JsonxaArrayGet(jc);

		return jsonx_toast_wrap_array_into_pointer(toasterid, jxa, jc->len);
	}

	return NULL;
}

JsonContainerOps
jsonxaContainerOps =
{
	sizeof(JsonxaState),
	jsonxaInit,
	jsonxaIteratorInit,
	jsonxaFindKeyInObject,
	jsonxaFindValueInArray,
	jsonxaGetArrayElement,
	NULL,
	JsonbToCStringRaw,
	jsonxaCopy,
	jsonxaFree,
	jsonxaEncode,
	//JsonObjectMutatorInitGeneric,
	//JsonArrayMutatorInitGeneric,
	jsonxaObjectMutatorInit,
	jsonxaArrayMutatorInit
};

static int
jsonxaSliceArray(JsonContainer *root, Size max_size,
				 JsonxArrayChunkInfo **p_chunks)
{
	JsonIterator *it = JsonIteratorInit(root);
	JsonIteratorToken tok;
	int			max_chunk_size = TOAST_MAX_CHUNK_SIZE;
	int			chunk_hdr_size = offsetof(JsonbDatum, root.children);
	int			chunk_size = chunk_hdr_size;
	int			max_chunks = (max_size - JSONX_ARRAY_HDR_SIZE) /
		(sizeof(JsonxArrayChunkPtr) + sizeof(JsonxArrayChunkOffset));
	JsonValue	jbv;
	JsonValue	jbv_chunk;
	JsonValue  *jbv_elems = palloc(sizeof(*jbv_elems) * (max_chunk_size / sizeof(JEntry)));
	JsonxArrayChunkInfo *chunks = palloc(sizeof(*chunks) * max_chunks);
	int			n_elems = 0;
	int			n_chunks = 0;

	jbv_chunk.type = jbvArray;
	jbv_chunk.val.array.elems = jbv_elems;
	jbv_chunk.val.array.nElems = 0;
	jbv_chunk.val.array.rawScalar = false;

	tok = JsonIteratorNext(&it, &jbv, true);
	Assert(tok == WJB_BEGIN_ARRAY);

	chunks[0].offset = 0;

	while ((tok = JsonIteratorNext(&it, &jbv, true)) == WJB_ELEM)
	{
		int			size = chunk_size;
		bool		align4 = false;

		switch (jbv.type)
		{
			case jbvNull:
				size = 0;
				break;
			case jbvBool:
				size = 1;
				break;
			case jbvString:
				size = jbv.val.string.len;
				break;
			case jbvNumeric:
				size = VARSIZE_ANY(jbv.val.numeric);
				align4 = true;
				break;
			case jbvBinary:
				Assert(jbv.val.binary.data->ops == &jsonbContainerOps);
				size = jbv.val.binary.data->len;
				align4 = true;
				break;
			default:
				elog(ERROR, "jsonb value type: %d", jbv.type);
				break;
		}

		if (chunk_hdr_size + size + sizeof(JEntry) > max_chunk_size)
			goto end;	// TODO toast long elements separately

		chunk_size = (align4 ? INTALIGN(chunk_size) : chunk_size) + size + sizeof(JEntry);

		if (chunk_size > max_chunk_size)
		{
			if (n_chunks + 1 >= max_chunks)
				goto end;

			chunks[n_chunks].jb = JsonValueToJsonbDatum(&jbv_chunk);
			ItemPointerSetInvalid(&chunks[n_chunks].ptr);

			chunk_size = chunk_hdr_size;
			chunk_size = (align4 ? INTALIGN(chunk_size) : chunk_size) + size + sizeof(JEntry);

			chunks[++n_chunks].offset = n_elems;
			jbv_chunk.val.array.nElems = 0;
		}

		jbv_elems[jbv_chunk.val.array.nElems++] = jbv;
		n_elems++;
	}

	Assert(tok == WJB_END_ARRAY);
	tok = JsonIteratorNext(&it, &jbv, true);
	Assert(tok == WJB_DONE);

	ItemPointerSetInvalid(&chunks[n_chunks].ptr);
	chunks[n_chunks++].jb = JsonValueToJsonbDatum(&jbv_chunk);

	*p_chunks = chunks;
	Assert(JsonContainerSize(root) == n_elems);

	return n_chunks;

end:
	for (int i = 0; i < n_chunks; i++)
	{
		if (chunks[i].jb == (Datum) 0)
			break;
		pfree(DatumGetPointer(chunks[i].jb));
	}

	pfree(jbv_elems);
	pfree(chunks);

	return -1;
}

static int
jsonxaResliceArray(JsonxArray *jxa, Size max_size, JsonxArrayChunkInfo **p_chunks)
{
	JsonxArrayChunkInfo *chunks;
	JsonxArrayChunkPtr *ptrs = JSONX_ARRAY_CHUNK_PTRS(jxa);
	char	   *inline_chunks = (void *)(INTALIGN((Pointer) &ptrs[jxa->n_chunks]));
	int			max_chunks = (max_size - JSONX_ARRAY_HDR_SIZE) /
		(sizeof(JsonxArrayChunkPtr) + sizeof(JsonxArrayChunkOffset));
	int			inline_size = 0;
	int			n_chunks = 0;
	int			n_chunks_allocated;
	bool		toast_chunks = true;

	if (jxa->n_chunks > max_chunks)
		return -1;

	for (int i = 0; i < jxa->n_chunks; i++)
	{
		if (ItemPointerIsValid(&ptrs[i]))
			n_chunks++;
		else
		{
			int			offset = ItemPointerGetBlockNumberNoCheck(&ptrs[i]);
			Datum		jb = PointerGetDatum(&inline_chunks[offset]);
			int			size = VARSIZE_ANY(jb);

			inline_size += INTALIGN(size);

			n_chunks += (size + TOAST_MAX_CHUNK_SIZE - 1) / TOAST_MAX_CHUNK_SIZE;
		}

		if (n_chunks > max_chunks)
			return -1;
	}

	n_chunks_allocated = n_chunks;
	chunks = palloc(sizeof(*chunks) * n_chunks_allocated);

	n_chunks = 0;

	for (int i = 0; i < jxa->n_chunks; i++)
	{
		Datum		jb_datum;
		JsonxArrayChunkInfo *jb_chunks = NULL;
		int			n_jb_chunks;

		if (n_chunks >= max_chunks)
			goto err;

		if (ItemPointerIsValid(&ptrs[i]))
		{
			n_jb_chunks = 1;
			jb_datum = (Datum) 0;
		}
		else
		{
			int			offset = ItemPointerGetBlockNumberNoCheck(&ptrs[i]);

			jb_datum = PointerGetDatum(&inline_chunks[offset]);

			if (toast_chunks)
			{
				Json	   *jb = DatumGetJsonbP(jb_datum);

				n_jb_chunks = jsonxaSliceArray(JsonRoot(jb), max_size, &jb_chunks);

				if (n_jb_chunks < 0)
					goto err;
			}
			else
			{
				n_jb_chunks = 1;
			}
		}

		if (n_chunks + n_jb_chunks > max_chunks)
			goto err;

		if (n_chunks + n_jb_chunks >= n_chunks_allocated)
		{
			n_chunks_allocated = Max(n_chunks_allocated * 2, n_chunks + n_jb_chunks);
			chunks = repalloc(chunks, sizeof(*chunks) * n_chunks_allocated);
		}

		if (jb_chunks)
		{
			int			chunk_offs = jxa->chunk_offsets[i];

			for (int j = 0; j < n_jb_chunks; j++)
			{
				ItemPointerSetInvalid(&chunks[n_chunks].ptr);
				chunks[n_chunks].offset = jb_chunks[j].offset + chunk_offs;
				chunks[n_chunks].jb = jb_chunks[j].jb;

				n_chunks++;
			}

			inline_size -= INTALIGN(VARSIZE_ANY(jb_datum));

			if (JSONX_ARRAY_SIZE(n_chunks + (jxa->n_chunks - i + 1)) + inline_size <= max_size)
				toast_chunks = false;
		}
		else
		{
			chunks[n_chunks].jb = jb_datum;

			if (jb_datum == (Datum) 0)
			{
				ItemPointerCopy(&ptrs[i], &chunks[n_chunks].ptr);
				chunks[n_chunks].offset = jxa->chunk_offsets[i];
			}
			else
			{
				ItemPointerSetInvalid(&chunks[n_chunks].ptr);
				chunks[n_chunks].offset = jxa->chunk_offsets[i] | JSONXA_INLINE_CHUNK;
			}

			n_chunks++;
		}
	}

	*p_chunks = chunks;

	return n_chunks;

err:
	for (int i = 0; i < n_chunks; i++)
	{
		if (chunks[i].jb != (Datum) 0 &&
			!(chunks[i].offset & JSONXA_INLINE_CHUNK))
			pfree(DatumGetPointer(chunks[i].jb));
	}

	pfree(chunks);

	return -1;
}

bool
jsonb_toaster_save_array(Relation rel, Oid toasterid, JsonContainer *root,
						 Size max_size, char cmethod, int options, Datum *res)
{
	JsonxArrayChunkInfo *chunks;
	int			n_chunks;
	int			n_elems;
	Oid			toastrelid;

	*res = (Datum) 0;

	if (root->ops == &jsonxaContainerOps)
	{
		JsonxArray *jxa = JsonxaArrayGet(root);

		n_elems = jxa->n_elems;
		n_chunks = jsonxaResliceArray(jxa, max_size, &chunks);
	}
	else
	{
		n_elems = JsonContainerSize(root);
		n_chunks = jsonxaSliceArray(root, max_size, &chunks);
	}

	if (n_chunks < 0)
		return false;

	if (OidIsValid(rel->rd_toastoid))
		toastrelid = rel->rd_toastoid;
	else
		toastrelid = rel->rd_rel->reltoastrelid;

	*res = jsonx_toast_array_chunks(rel, toastrelid, toasterid,
								    options, n_elems, n_chunks, chunks);

	Assert(VARSIZE_ANY(*res) <= max_size);

	for (int i = 0; i < n_chunks; i++)
	{
		if (chunks[i].jb != (Datum) 0 &&
			!(chunks[i].offset & JSONXA_INLINE_CHUNK))
			pfree(DatumGetPointer(chunks[i].jb));
	}

	pfree(chunks);

	return true;
}

void
jsonxa_toaster_delete(JsonContainer *jc, bool is_speculative)
{
	JsonxArray *jxa = JsonxaArrayGet(jc);
	JsonxArrayChunkPtr *ptrs = JSONX_ARRAY_CHUNK_PTRS(jxa);
	Relation	toastrel;

	toastrel = table_open(jxa->toastrelid, RowExclusiveLock);

	for (int i = 0; i < jxa->n_chunks; i++)
	{
		if (ItemPointerIsValid(&ptrs[i]))
		{
			if (is_speculative)
				heap_abort_speculative(toastrel, &ptrs[i]);
			else
				simple_heap_delete(toastrel, &ptrs[i]);
		}
	}

	/*
	 * End scan and close relations but keep the lock until commit, so
	 * as a concurrent reindex done directly on the toast relation
	 * would be able to wait for this transaction.
	 */
	table_close(toastrel, NoLock);
}

static Datum
jsonxa_toaster_copy_chunks(Relation rel, Oid toasterid, int options,
						   JsonxArray *jxa, int len, int start_chunk)
{
	JsonxaArrayIterator iter;
	JsonxArrayChunkPtr *ptrs = JSONX_ARRAY_CHUNK_PTRS(jxa);
	struct varlena *res = NULL;

	for (int i = start_chunk; i < jxa->n_chunks; i++)
	{
		Datum		chunk;
		ItemPointerData chunk_tids[1];

		if (!ItemPointerIsValid(&ptrs[i]))
			continue;

		if (!res)
		{
			res = jsonx_toast_wrap_array_into_pointer(toasterid, jxa, len);
			jxa = jsonxaGetArray(PointerGetDatum(res));
			ptrs = JSONX_ARRAY_CHUNK_PTRS(jxa);

			jsonxaArrayIteratorInit(&iter, jxa, false);

			if (jxa->toastrelid == RelationGetRelid(rel))
				iter.toastrel = rel;
		}

		chunk = jsonxaArrayIteratorFetchChunk(&iter, ptrs[i]);

		Assert(VARSIZE_ANY(DatumGetPointer(chunk)) <= TOAST_MAX_CHUNK_SIZE);

		chunk =	jsonx_toast_save_datum_ext(rel, toasterid, chunk,
										   NULL, options, NULL, chunk_tids,
										   false /* compress_chunks*/);

		ItemPointerCopy(&chunk_tids[0], &ptrs[i]);
	}

	if (res)
	{
		if (jxa->toastrelid == RelationGetRelid(rel))
			iter.toastrel = NULL;

		jsonxaArrayIteratorFree(&iter);

		if (OidIsValid(rel->rd_toastoid))
			jxa->toastrelid = rel->rd_toastoid;
		else
			jxa->toastrelid = rel->rd_rel->reltoastrelid;
	}

	return PointerGetDatum(res);
}

Datum
jsonxa_toaster_copy(Relation rel, Oid toasterid, JsonContainer *jc, char cmethod)
{
	JsonxArray *jxa = JsonxaArrayGet(jc);

	return jsonxa_toaster_copy_chunks(rel, toasterid, 0 /* FIXME options */,
									  jxa, jc->len, 0);
}

Datum
jsonxa_toaster_cmp(Relation rel, Oid toasterid, JsonContainer *new_jc,
				   JsonContainer *old_jc, char cmethod)
{
	JsonxArray *old_jxa = JsonxaArrayGet(old_jc);
	JsonxArray *new_jxa = JsonxaArrayGet(new_jc);
	JsonxArrayChunkPtr *old_ptrs = JSONX_ARRAY_CHUNK_PTRS(old_jxa);
	JsonxArrayChunkPtr *new_ptrs = JSONX_ARRAY_CHUNK_PTRS(new_jxa);
	int			new_i;
	int			old_n_chunks = old_jxa->n_chunks;
	int			new_n_chunks = new_jxa->n_chunks;
	bool		is_speculative = false; /* FIXME */
	int			options = 0; /* FIXME */
	Datum		res = (Datum) 0;
	Oid			toastrelid = rel->rd_rel->reltoastrelid;
	Relation	toastrel = NULL;

	if (old_jxa->toastrelid != toastrelid ||
		new_jxa->toastrelid != toastrelid)
	{
		Datum		res = jsonxa_toaster_copy(rel, toasterid, new_jc, cmethod);

		jsonxa_toaster_delete(old_jc, is_speculative);
		return res;
	}

	/* delete old removed chunks */
	for (int old_i = new_i = 0; old_i < old_n_chunks; old_i++)
	{
		if (!ItemPointerIsValid(&old_ptrs[old_i]))
			continue;

		while (new_i < new_n_chunks &&
			   !ItemPointerIsValid(&new_ptrs[new_i]))
			new_i++;

		if (new_i < new_n_chunks &&
			ItemPointerEquals(&old_ptrs[old_i], &new_ptrs[new_i]))
			new_i++;
		else
		{
			if (!toastrel)
				toastrel = table_open(toastrelid, RowExclusiveLock);

			if (is_speculative)
				heap_abort_speculative(toastrel, &old_ptrs[old_i]);
			else
				simple_heap_delete(toastrel, &old_ptrs[old_i]);
		}
	}

	if (toastrel)
		table_close(toastrel, NoLock);

	/* copy remaining new chunks */
	if (new_i < new_n_chunks)
		res = jsonxa_toaster_copy_chunks(rel, toasterid, options,
										 new_jxa, new_jc->len, new_i);

	return res;
}
