#include "postgres.h"
#include "fmgr.h"
#include "funcapi.h"
#include "catalog/pg_type.h"
#include "port/atomics.h"
#include "storage/wait.h"
#include "storage/spin.h"
#include "storage/ipc.h"
#include "storage/shm_mq.h"
#include "storage/shm_toc.h"
#include "access/htup_details.h"
#include "pg_stat_wait.h"
#include "miscadmin.h"
#include "utils/guc.h"

PG_MODULE_MAGIC;

void		_PG_init(void);
void		_PG_fini(void);

extern shm_toc			   *toc;

static shmem_startup_hook_type prev_shmem_startup_hook = NULL;
static PGPROC * search_proc(int backendPid);
static TupleDesc get_history_item_tupledesc();
static HeapTuple get_history_item_tuple(HistoryItem *item, TupleDesc tuple_desc);

static void
pgsw_shmem_startup(void)
{

	if (WaitsHistoryOn)
	{
		if (prev_shmem_startup_hook)
			prev_shmem_startup_hook();

		GetCollectorMem(true);
	}
}

/*
 * Module load callback
 */
void
_PG_init(void)
{
	if (!process_shared_preload_libraries_in_progress)
		return;

	DefineCustomBoolVariable("pg_stat_wait.history", "Collect waits history",
			NULL, &WaitsHistoryOn, false, PGC_POSTMASTER, 0, NULL, NULL, NULL);

	if (WaitsHistoryOn)
	{
		/*
		 * Request additional shared resources.  (These are no-ops if we're not in
		 * the postmaster process.)  We'll allocate or attach to the shared
		 * resources in pgsw_shmem_startup().
		 */
		RequestAddinShmemSpace(CollectorShmemSize());
		RegisterWaitsCollector();

		/*
		 * Install hooks.
		 */
		prev_shmem_startup_hook = shmem_startup_hook;
		shmem_startup_hook = pgsw_shmem_startup;
	}
}

/*
 * Module unload callback
 */
void
_PG_fini(void)
{
	/* Uninstall hooks. */
	shmem_startup_hook = prev_shmem_startup_hook;
}

PG_FUNCTION_INFO_V1(pg_wait_class_list);
Datum
pg_wait_class_list(PG_FUNCTION_ARGS)
{
	FuncCallContext *funcctx;

	if (SRF_IS_FIRSTCALL())
	{
		MemoryContext		oldcontext;
		TupleDesc			tupdesc;

		funcctx = SRF_FIRSTCALL_INIT();
		funcctx->max_calls = WAITS_COUNT;

		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		tupdesc = CreateTemplateTupleDesc(2, false);
		TupleDescInitEntry(tupdesc, (AttrNumber) 1, "class_id",
						   INT4OID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 2, "name",
						   CSTRINGOID, -1, 0);

		funcctx->tuple_desc = BlessTupleDesc(tupdesc);
		MemoryContextSwitchTo(oldcontext);
	}

	/* stuff done on every call of the function */
	funcctx = SRF_PERCALL_SETUP();

	if (funcctx->call_cntr < funcctx->max_calls)
	{
		/* for each row */
		Datum		values[2];
		bool		nulls[2];
		HeapTuple	tuple;
		int idx;

		MemSet(values, 0, sizeof(values));
		MemSet(nulls, 0, sizeof(nulls));

		idx = funcctx->call_cntr;
		values[0] = Int32GetDatum(idx);
		values[1] = CStringGetDatum(WAIT_CLASSES[idx]);

		tuple = heap_form_tuple(funcctx->tuple_desc, values, nulls);
		SRF_RETURN_NEXT(funcctx, HeapTupleGetDatum(tuple));
	}
	else
	{
		/* nothing left */
		SRF_RETURN_DONE(funcctx);
	}
}

PG_FUNCTION_INFO_V1(pg_wait_event_list);
Datum
pg_wait_event_list(PG_FUNCTION_ARGS)
{
	FuncCallContext *funcctx;
	WaitEventContext *ctx;

	if (SRF_IS_FIRSTCALL())
	{
		MemoryContext		oldcontext;
		TupleDesc			tupdesc;

		funcctx = SRF_FIRSTCALL_INIT();
		/* 4 arrays length and WAIT_LATCH + WAIT_CPU */
		funcctx->max_calls = 2 + WAIT_LWLOCKS_COUNT + WAIT_LOCKS_COUNT +
								 WAIT_IO_EVENTS_COUNT + WAIT_NETWORK_EVENTS_COUNT;

		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		tupdesc = CreateTemplateTupleDesc(3, false);
		TupleDescInitEntry(tupdesc, (AttrNumber) 1, "class_id",
						   INT4OID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 2, "event_id",
						   INT4OID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 3, "name",
						   CSTRINGOID, -1, 0);

		funcctx->tuple_desc = BlessTupleDesc(tupdesc);
		funcctx->user_fctx = palloc0(sizeof(WaitEventContext));

		MemoryContextSwitchTo(oldcontext);
	}

	/* stuff done on every call of the function */
	funcctx = SRF_PERCALL_SETUP();
	ctx = (WaitEventContext *)funcctx->user_fctx;

	if (ctx->class_cnt < WAITS_COUNT)
	{
		/* for each row */
		Datum		values[3];
		bool		nulls[3];
		HeapTuple	tuple;

		MemSet(values, 0, sizeof(values));
		MemSet(nulls, 0, sizeof(nulls));

		values[0] = Int32GetDatum(ctx->class_cnt);
		values[1] = Int32GetDatum(ctx->event_cnt);
		values[2] = CStringGetDatum(WaitsEventName(ctx->class_cnt, ctx->event_cnt));

		if (ctx->class_cnt == WAIT_CPU && ctx->event_cnt < (WAIT_CPU_EVENTS_COUNT-1))
			ctx->event_cnt++;
		else if (ctx->class_cnt == WAIT_LWLOCK && ctx->event_cnt < (LWLockTranchesCount()-1))
			ctx->event_cnt++;
		else if (ctx->class_cnt == WAIT_LOCK && ctx->event_cnt < (WAIT_LOCKS_COUNT-1))
			ctx->event_cnt++;
		else if (ctx->class_cnt == WAIT_IO && ctx->event_cnt < (WAIT_IO_EVENTS_COUNT-1))
			ctx->event_cnt++;
		else if (ctx->class_cnt == WAIT_NETWORK && ctx->event_cnt < (WAIT_NETWORK_EVENTS_COUNT-1))
			ctx->event_cnt++;
		else
		{
			ctx->event_cnt = 0;
			ctx->class_cnt++;
		}

		tuple = heap_form_tuple(funcctx->tuple_desc, values, nulls);
		SRF_RETURN_NEXT(funcctx, HeapTupleGetDatum(tuple));
	}
	else
	{
		/* nothing left */
		SRF_RETURN_DONE(funcctx);
	}
}

static TupleDesc
get_history_item_tupledesc()
{
	int i;
	TupleDesc tupdesc;
	tupdesc = CreateTemplateTupleDesc(HISTORY_COLUMNS_COUNT, false);
	TupleDescInitEntry(tupdesc, (AttrNumber) 1, "pid",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 2, "sample_ts",
					   TIMESTAMPTZOID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 3, "class_id",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 4, "event_id",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 5, "wait_time",
					   INT8OID, -1, 0);

	for (i=0; i < WAIT_PARAMS_COUNT; i++)
	{
		TupleDescInitEntry(tupdesc, (AttrNumber) (6 + i), "p",
						   INT4OID, -1, 0);
	}

	return BlessTupleDesc(tupdesc);
}

static HeapTuple
get_history_item_tuple(HistoryItem *item, TupleDesc tuple_desc)
{
	int       i;
	HeapTuple tuple;
	Datum     values[HISTORY_COLUMNS_COUNT];
	bool      nulls[HISTORY_COLUMNS_COUNT];

	MemSet(values, 0, sizeof(values));
	MemSet(nulls, 0, sizeof(nulls));

	/* Values available to all callers */
	values[0] = Int32GetDatum(item->backendPid);
	values[1] = TimestampTzGetDatum(item->ts);
	values[2] = Int32GetDatum(item->classId);
	values[3] = Int32GetDatum(item->eventId);
	values[4] = Int64GetDatum(item->waitTime);

	for (i=0; i < WAIT_PARAMS_COUNT; i++)
		values[5 + i] = Int32GetDatum(item->params[i]);

	tuple = heap_form_tuple(tuple_desc, values, nulls);
	return tuple;
}

PG_FUNCTION_INFO_V1(pg_stat_wait_get_current);
Datum
pg_stat_wait_get_current(PG_FUNCTION_ARGS)
{
	FuncCallContext 	*funcctx;
	WaitCurrentContext 	*params;
	HistoryItem 		*currentState;

	if (SRF_IS_FIRSTCALL())
	{
		MemoryContext		oldcontext;
		WaitCurrentContext 	*params;

		funcctx = SRF_FIRSTCALL_INIT();

		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);
		params = (WaitCurrentContext *)palloc0(sizeof(WaitCurrentContext));
		params->ts = GetCurrentTimestamp();

		funcctx->user_fctx = params;
		funcctx->max_calls = ProcGlobal->allProcCount;
		funcctx->tuple_desc = get_history_item_tupledesc();

		if (!PG_ARGISNULL(0))
		{
			HistoryItem item;
			PGPROC *proc = search_proc(PG_GETARG_UINT32(0));
			int stateOk = GetCurrentWaitsState(proc, &item,
				proc->waits.writeIdx);

			if (stateOk)
			{
				params->state = (HistoryItem *)palloc0(sizeof(HistoryItem));
				funcctx->max_calls = 1;
				*params->state = item;
			}
			else
				params->done = true;
		}

		MemoryContextSwitchTo(oldcontext);
	}

	/* stuff done on every call of the function */
	funcctx = SRF_PERCALL_SETUP();
	params = (WaitCurrentContext *)funcctx->user_fctx;
	currentState = NULL;

	if (!params->done)
	{
		if (params->state != NULL)
		{
			currentState = params->state;
			params->done = true;
			params->state = NULL;
		}
		else
		{
			while (funcctx->call_cntr <= funcctx->max_calls)
			{
				PGPROC *proc;
				HistoryItem item;

				if (funcctx->call_cntr == funcctx->max_calls
					|| params->idx >= ProcGlobal->allProcCount)
				{
					params->done = true;
					break;
				}

				LWLockAcquire(ProcArrayLock, LW_SHARED);
				proc = &ProcGlobal->allProcs[params->idx];
				if (proc != NULL && proc->pid)
				{
					int stateOk = GetCurrentWaitsState(proc, &item,
						proc->waits.writeIdx);
					if (stateOk)
					{
						currentState = &item;
						LWLockRelease(ProcArrayLock);
						params->idx++;
						break;
					}
				}

				LWLockRelease(ProcArrayLock);
				params->idx++;
			}
		}
	}

	if (currentState)
	{
		HeapTuple tuple;

		currentState->ts = params->ts;
		tuple = get_history_item_tuple(currentState, funcctx->tuple_desc);
		SRF_RETURN_NEXT(funcctx, HeapTupleGetDatum(tuple));
	}
	else if (params->done)
		SRF_RETURN_DONE(funcctx);

	PG_RETURN_VOID();
}

PG_FUNCTION_INFO_V1(pg_stat_wait_get_profile);
Datum
pg_stat_wait_get_profile(PG_FUNCTION_ARGS)
{
	WaitProfileContext *params;
	FuncCallContext *funcctx;
	BackendWaitCells *shmemCells;

	if (SRF_IS_FIRSTCALL())
	{
		MemoryContext		oldcontext;
		TupleDesc			tupdesc;

		funcctx = SRF_FIRSTCALL_INIT();

		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);
		params = (WaitProfileContext *)palloc0(sizeof(WaitProfileContext));

		if (!PG_ARGISNULL(0))
			params->backendPid = PG_GETARG_UINT32(0);

		if (!PG_ARGISNULL(1))
			params->reset = PG_GETARG_BOOL(1);

		funcctx->user_fctx = params;
		funcctx->max_calls = MaxBackends * WAIT_EVENTS_COUNT;

		tupdesc = CreateTemplateTupleDesc(5, false);
		TupleDescInitEntry(tupdesc, (AttrNumber) 1, "pid",
						   INT4OID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 2, "class_id",
						   INT4OID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 3, "event_id",
						   INT4OID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 4, "wait_time",
						   INT8OID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 5, "wait_count",
						   INT4OID, -1, 0);

		funcctx->tuple_desc = BlessTupleDesc(tupdesc);

		MemoryContextSwitchTo(oldcontext);
	}

	/* stuff done on every call of the function */
	funcctx = SRF_PERCALL_SETUP();

	params = (WaitProfileContext *)funcctx->user_fctx;
	shmemCells = (BackendWaitCells *)((char *)WaitShmem
			+ sizeof(int) +  /* counter */
			+ MAXALIGN(sizeof(slock_t))); /* lock */

	while (params->backendIdx <= MaxBackends)
	{
		Datum		values[5];
		bool		nulls[5];
		HeapTuple	tuple;
		int count;
		BackendWaitCells bcells, *item;

		if (params->backendIdx == MaxBackends)
		{
			SRF_RETURN_DONE(funcctx);
			break;
		}

		item = &shmemCells[params->backendIdx];

		do
		{
			/* wait until backend is updating this block */
		} while (!pg_atomic_test_set_flag(&item->isBusy));

		memcpy(&bcells, item, sizeof(BackendWaitCells));
		if (params->reset)
		{
			item->cells[params->eventIdx].interval = 0;
			item->cells[params->eventIdx].count = 0;
		}
		pg_atomic_clear_flag(&item->isBusy);

		/* filtering */
		if (bcells.backendPid == 0 ||
				(params->backendPid && params->backendPid != bcells.backendPid))
		{
			params->backendIdx++;
			continue;
		}

		if (params->eventIdx == WAIT_EVENTS_COUNT)
		{
			params->classIdx = 0;
			params->eventIdx = 0;
			params->backendIdx++;
			Assert(params->backendIdx <= MaxBackends);
			continue;
		}

		MemSet(values, 0, sizeof(values));
		MemSet(nulls, 0, sizeof(nulls));

		if ((params->classIdx+1) < WAITS_COUNT &&
				(params->eventIdx == WAIT_OFFSETS[params->classIdx+1]))
			params->classIdx++;

		count = bcells.cells[params->eventIdx].count;
		if (count == 0)
		{
			params->eventIdx++;
			continue;
		}

		values[0] = Int32GetDatum(bcells.backendPid);
		values[1] = Int32GetDatum(params->classIdx);
		values[2] = Int32GetDatum(params->eventIdx - WAIT_OFFSETS[params->classIdx]);
		values[3] = Int64GetDatum(bcells.cells[params->eventIdx].interval);
		values[4] = Int32GetDatum(bcells.cells[params->eventIdx].count);
		params->eventIdx += 1;
		tuple = heap_form_tuple(funcctx->tuple_desc, values, nulls);

		SRF_RETURN_NEXT(funcctx, HeapTupleGetDatum(tuple));
		break;
	}

	PG_RETURN_VOID();
}

PG_FUNCTION_INFO_V1(pg_stat_wait_reset_profile);
Datum
pg_stat_wait_reset_profile(PG_FUNCTION_ARGS)
{
	int i, j;
	BackendWaitCells *cells = (BackendWaitCells *)((char *)WaitShmem
			+ sizeof(int) +  /* counter */
			+ MAXALIGN(sizeof(slock_t))); /* lock */

	for(i = 0; i < MaxBackends; i++)
	{
		BackendWaitCells *item = cells + i;
		do
		{
			/* wait until backend is updating this block */
		} while (!pg_atomic_test_set_flag(&item->isBusy));

		for (j = 0; j < WAIT_EVENTS_COUNT; j++)
		{
			item->cells[j].interval = 0;
			item->cells[j].count = 0;
		}
		pg_atomic_clear_flag(&item->isBusy);
	}

	PG_RETURN_VOID();
}

static void
initLockTag(LOCKTAG *tag)
{
	tag->locktag_field1 = PG_STAT_WAIT_MAGIC;
	tag->locktag_field2 = 0;
	tag->locktag_field3 = 0;
	tag->locktag_field4 = 0;
	tag->locktag_type = LOCKTAG_USERLOCK;
	tag->locktag_lockmethodid = USER_LOCKMETHOD;
}

static History *
receive_observations(shm_mq_handle *mqh)
{
	Size len;
	void *data;
	History *result;
	int	count, i;
	shm_mq_result res;

	res = shm_mq_receive(mqh, &len, &data, false);
	if (res != SHM_MQ_SUCCESS)
		elog(ERROR, "Error reading mq.");
	if (len != sizeof(count))
		elog(ERROR, "Invalid message length.");
	memcpy(&count, data, sizeof(count));

	result = (History *)palloc(sizeof(History));
	AllocHistory(result, count);

	for (i = 0; i < count; i++)
	{
		res = shm_mq_receive(mqh, &len, &data, false);
		if (res != SHM_MQ_SUCCESS)
			elog(ERROR, "Error reading mq.");
		if (len != sizeof(HistoryItem))
			elog(ERROR, "Invalid message length.");
		memcpy(&result->items[i], data, sizeof(HistoryItem));
	}

	return result;
}

PG_FUNCTION_INFO_V1(pg_stat_wait_get_history);
Datum
pg_stat_wait_get_history(PG_FUNCTION_ARGS)
{
	History				*observations;
	FuncCallContext		*funcctx;
	CollectorShmqHeader	*hdr;

	if (!WaitsHistoryOn)
		ereport(ERROR, (errcode(ERRCODE_CONFIG_FILE_ERROR),
						errmsg("Waits history turned off")));

	hdr = GetCollectorMem(false);

	if (SRF_IS_FIRSTCALL())
	{
		shm_mq	   *mq;
		shm_mq_handle *mqh;
		LOCKTAG		tag;
		MemoryContext		oldcontext;

		funcctx = SRF_FIRSTCALL_INIT();
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		initLockTag(&tag);
		LockAcquire(&tag, ExclusiveLock, false, false);

		mq = shm_mq_create(shm_toc_lookup(toc, 1), COLLECTOR_QUEUE_SIZE);
		hdr->request = HISTORY_REQUEST;

		SetLatch(hdr->latch);

		shm_mq_set_receiver(mq, MyProc);
		mqh = shm_mq_attach(mq, NULL, NULL);

		observations = receive_observations(mqh);
		funcctx->user_fctx = observations;
		funcctx->max_calls = observations->count;

		shm_mq_detach(mq);
		LockRelease(&tag, ExclusiveLock, false);

		funcctx->tuple_desc = get_history_item_tupledesc();
		MemoryContextSwitchTo(oldcontext);
	}

	/* stuff done on every call of the function */
	funcctx = SRF_PERCALL_SETUP();

	observations = (History *)funcctx->user_fctx;

	if (observations->index < observations->count)
	{
		HeapTuple	tuple;
		HistoryItem *observation;

		observation = &observations->items[observations->index];
		tuple = get_history_item_tuple(observation, funcctx->tuple_desc);
		observations->index++;
		SRF_RETURN_NEXT(funcctx, HeapTupleGetDatum(tuple));
	}
	else
	{
		/* nothing left */
		SRF_RETURN_DONE(funcctx);
	}

	PG_RETURN_VOID();
}

static PGPROC *
search_proc(int backendPid)
{
	int i;
	if (backendPid == 0)
		return MyProc;

	LWLockAcquire(ProcArrayLock, LW_SHARED);
	for (i = 0; i < ProcGlobal->allProcCount; ++i)
	{
		PGPROC	*proc = &ProcGlobal->allProcs[i];
		if (proc->pid && proc->pid == backendPid)
		{
			LWLockRelease(ProcArrayLock);
			return proc;
		}
	}

	LWLockRelease(ProcArrayLock);
	ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
				errmsg("backend with pid=%d not found", backendPid)));
	return NULL;
}

PG_FUNCTION_INFO_V1(pg_start_trace);
Datum
pg_start_trace(PG_FUNCTION_ARGS)
{
	PGPROC *proc;
	char *filename = PG_GETARG_CSTRING(1);

	if (strlen(filename) >= WAIT_TRACE_FN_LEN)
		ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
					errmsg("length of filename limited to %d", (WAIT_TRACE_FN_LEN-1))));

	if (!is_absolute_path(filename))
		ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
					errmsg("path must be absolute")));

	proc = NULL;
	if (PG_ARGISNULL(0))
		proc = MyProc;
	else
		proc = search_proc(PG_GETARG_INT32(0));

	if (proc != NULL)
	{
		if (proc->waits.traceOn)
			ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
						errmsg("trace is already working in backend")));

		strcpy(proc->waits.traceFn, filename);
		proc->waits.traceOn = true;
	}

	PG_RETURN_VOID();
}

PG_FUNCTION_INFO_V1(pg_is_in_trace);
Datum
pg_is_in_trace(PG_FUNCTION_ARGS)
{
	PGPROC *proc = NULL;

	if (PG_ARGISNULL(0))
		proc = MyProc;
	else
		proc = search_proc(PG_GETARG_INT32(0));

	if (proc)
		PG_RETURN_BOOL(proc->waits.traceOn);

	PG_RETURN_BOOL(false);
}

PG_FUNCTION_INFO_V1(pg_stop_trace);
Datum
pg_stop_trace(PG_FUNCTION_ARGS)
{
	PGPROC *proc = NULL;
	if (PG_ARGISNULL(0))
		proc = MyProc;
	else
		proc = search_proc(PG_GETARG_INT32(0));

	if (proc != NULL)
	{
		if (!proc->waits.traceOn)
			ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
						errmsg("trace is not started")));

		proc->waits.traceOn = false;
	}

	PG_RETURN_VOID();
}

PG_FUNCTION_INFO_V1(pg_stat_wait_start_wait);

Datum
pg_stat_wait_start_wait(PG_FUNCTION_ARGS)
{
	int classId = PG_GETARG_INT32(0);
	int eventId = PG_GETARG_INT32(1);
	int p1 = PG_GETARG_INT32(2);
	int p2 = PG_GETARG_INT32(3);
	int p3 = PG_GETARG_INT32(4);
	int p4 = PG_GETARG_INT32(5);
	int p5 = PG_GETARG_INT32(6);

	WAIT_START(classId, eventId, p1, p2, p3, p4, p5);
	PG_RETURN_VOID();
}

PG_FUNCTION_INFO_V1(pg_stat_wait_stop_wait);

Datum
pg_stat_wait_stop_wait(PG_FUNCTION_ARGS)
{
	WAIT_STOP();
	PG_RETURN_VOID();
}
