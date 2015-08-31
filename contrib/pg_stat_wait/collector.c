#include "postgres.h"

#include "access/htup_details.h"
#include "catalog/pg_type.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "postmaster/bgworker.h"
#include "storage/ipc.h"
#include "storage/pg_shmem.h"
#include "storage/procarray.h"
#include "storage/procsignal.h"
#include "storage/s_lock.h"
#include "storage/shm_mq.h"
#include "storage/shm_toc.h"
#include "storage/spin.h"
#include "storage/wait.h"
#include "utils/guc.h"
#include "utils/memutils.h"
#include "utils/resowner.h"
#include "portability/instr_time.h"

#include "pg_stat_wait.h"

CollectorShmqHeader *hdr = NULL;

static void *pgsw;
shm_toc *toc;
shm_mq *mq;
static volatile sig_atomic_t shutdown_requested = false;

static void handle_sigterm(SIGNAL_ARGS);
static void collector_main(Datum main_arg);

/*
 * Estimate shared memory space needed.
 */
Size
CollectorShmemSize(void)
{
	shm_toc_estimator e;
	Size size;

	shm_toc_initialize_estimator(&e);
	shm_toc_estimate_chunk(&e, sizeof(CollectorShmqHeader));
	shm_toc_estimate_chunk(&e, (Size) COLLECTOR_QUEUE_SIZE);
	shm_toc_estimate_keys(&e, 2);
	size = shm_toc_estimate(&e);

	return size;
}

static bool
shmem_int_guc_check_hook(int *newval, void **extra, GucSource source)
{
	if (UsedShmemSegAddr == NULL)
		return false;
	return true;
}

static bool
shmem_bool_guc_check_hook(bool *newval, void **extra, GucSource source)
{
	if (UsedShmemSegAddr == NULL)
		return false;
	return true;
}

CollectorShmqHeader *
GetCollectorMem(bool init)
{
	bool found;
	Size segsize = CollectorShmemSize();

	pgsw = ShmemInitStruct("pg_stat_wait", segsize, &found);
	if (!init && !found)
	{
		ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
						errmsg("A collector memory wasn't initialized yet")));
	}

	if (!found)
	{
		void *mq_mem;

		toc = shm_toc_create(PG_STAT_WAIT_MAGIC, pgsw, segsize);
		hdr = shm_toc_allocate(toc, sizeof(CollectorShmqHeader));
		shm_toc_insert(toc, 0, hdr);

		mq_mem = shm_toc_allocate(toc, COLLECTOR_QUEUE_SIZE);
		shm_toc_insert(toc, 1, mq_mem);

		DefineCustomIntVariable("pg_stat_wait.history_size",
				"Sets size of waits history.", NULL,
				&hdr->historySize, 5000, 100, INT_MAX,
				PGC_SUSET, 0, shmem_int_guc_check_hook, NULL, NULL);

		DefineCustomIntVariable("pg_stat_wait.history_period",
				"Sets period of waits history sampling.", NULL,
				&hdr->historyPeriod, 10, 1, INT_MAX,
				PGC_SUSET, 0, shmem_int_guc_check_hook, NULL, NULL);

		DefineCustomBoolVariable("pg_stat_wait.history_skip_latch",
				"Skip latch events in waits history", NULL,
				&hdr->historySkipLatch, false,
				PGC_SUSET, 0, shmem_bool_guc_check_hook, NULL, NULL);
	}
	else
	{
		toc = shm_toc_attach(PG_STAT_WAIT_MAGIC, pgsw);
		hdr = shm_toc_lookup(toc, 0);
	}
	return hdr;
}

void
RegisterWaitsCollector(void)
{
	BackgroundWorker worker;

	/* set up common data for all our workers */
	worker.bgw_flags = BGWORKER_SHMEM_ACCESS |
		BGWORKER_BACKEND_DATABASE_CONNECTION;
	worker.bgw_start_time = BgWorkerStart_ConsistentState;
	worker.bgw_restart_time = BGW_NEVER_RESTART;
	worker.bgw_main = collector_main;
	worker.bgw_notify_pid = 0;
	snprintf(worker.bgw_name, BGW_MAXLEN, "pg_stat_wait collector");
	worker.bgw_main_arg = (Datum)0;
	RegisterBackgroundWorker(&worker);
}

void
AllocHistory(History *observations, int count)
{
	observations->items = (HistoryItem *) palloc0(sizeof(HistoryItem) * count);
	observations->index = 0;
	observations->count = count;
	observations->wraparound = false;
}

static void
ReallocHistory(History *observations, int count)
{
	HistoryItem	   *newitems;
	int				copyCount;
	int				i, j;

	newitems = (HistoryItem *) palloc0(sizeof(HistoryItem) * count);

	if (observations->wraparound)
		copyCount = observations->count;
	else
		copyCount = observations->index;

	copyCount = Min(copyCount, count);

	i = 0;
	j = observations->index;
	while (i < copyCount)
	{
		j--;
		if (j < 0)
			j = observations->count - 1;
		memcpy(&newitems[i], &observations->items[j], sizeof(HistoryItem));
		i++;
	}

	pfree(observations->items);
	observations->items = newitems;

	observations->index = copyCount;
	observations->count = count;
	observations->wraparound = false;
}

/* Read current wait information from proc, if readCurrent is true,
 * then it reads from currently going wait, and can be inconsistent
 */
int
GetCurrentWaitsState(PGPROC *proc, HistoryItem *item, int idx)
{
	instr_time	currentTime;
	ProcWait	*wait;

	if (idx == -1)
		return 0;

	INSTR_TIME_SET_CURRENT(currentTime);
	wait = &proc->waits.waitsBuf[idx];
	item->backendPid = proc->pid;
	item->classId = (int)wait->classId;
	if (item->classId == 0)
		return 0;

	item->eventId = (int)wait->eventId;

	INSTR_TIME_SUBTRACT(currentTime, wait->startTime);
	item->waitTime = INSTR_TIME_GET_MICROSEC(currentTime);
	memcpy(item->params, wait->params, sizeof(item->params));
	return 1;
}

static void
handle_sigterm(SIGNAL_ARGS)
{
	int save_errno = errno;
	shutdown_requested = true;
	if (MyProc)
		SetLatch(&MyProc->procLatch);
	errno = save_errno;
}

/* Circulation in history */
static HistoryItem *
get_next_observation(History *observations)
{
	HistoryItem *result;

	result = &observations->items[observations->index];
	observations->index++;
	if (observations->index >= observations->count)
	{
		observations->index = 0;
		observations->wraparound = true;
	}
	return result;
}

/* Gets current waits from backends */
static void
write_waits_history(History *observations, TimestampTz current_ts)
{
	int i, newSize;

	newSize = hdr->historySize;
	if (observations->count != newSize)
		ReallocHistory(observations, newSize);

	LWLockAcquire(ProcArrayLock, LW_SHARED);
	for (i = 0; i < ProcGlobal->allProcCount; ++i)
	{
		HistoryItem item, *observation;
		PGPROC	*proc = &ProcGlobal->allProcs[i];
		int stateOk = GetCurrentWaitsState(proc, &item, proc->waits.readIdx);

		/* mark waits as read */
		proc->waits.readIdx = -1;

		if (stateOk)
		{
			if (hdr->historySkipLatch && item.classId == WAIT_LATCH)
				continue;

			item.ts = current_ts;
			observation = get_next_observation(observations);
			*observation = item;
		}
	}
	LWLockRelease(ProcArrayLock);
}

static void
send_history(History *observations, shm_mq_handle *mqh)
{
	int	count, i;

	if (observations->wraparound)
		count = observations->count;
	else
		count = observations->index;

	shm_mq_send(mqh, sizeof(count), &count, false);
	for (i = 0; i < count; i++)
		shm_mq_send(mqh, sizeof(HistoryItem), &observations->items[i], false);
}

static void
collector_main(Datum main_arg)
{
	shm_mq	   *mq;
	shm_mq_handle *mqh;
	History observations;
	MemoryContext old_context, collector_context;

	/*
	 * Establish signal handlers.
	 *
	 * We want CHECK_FOR_INTERRUPTS() to kill off this worker process just as
	 * it would a normal user backend.  To make that happen, we establish a
	 * signal handler that is a stripped-down version of die().  We don't have
	 * any equivalent of the backend's command-read loop, where interrupts can
	 * be processed immediately, so make sure ImmediateInterruptOK is turned
	 * off.
	 */
	pqsignal(SIGTERM, handle_sigterm);
	BackgroundWorkerUnblockSignals();

	hdr->latch = &MyProc->procLatch;

	CurrentResourceOwner = ResourceOwnerCreate(NULL, "pg_stat_wait collector");
	collector_context = AllocSetContextCreate(TopMemoryContext,
			"pg_stat_wait context",
			ALLOCSET_DEFAULT_MINSIZE,
			ALLOCSET_DEFAULT_INITSIZE,
			ALLOCSET_DEFAULT_MAXSIZE);
	old_context = MemoryContextSwitchTo(collector_context);
	AllocHistory(&observations, hdr->historySize);
	MemoryContextSwitchTo(old_context);

	while (1)
	{
		int rc;
		TimestampTz current_ts;

		ResetLatch(&MyProc->procLatch);
		current_ts = GetCurrentTimestamp();
		write_waits_history(&observations, current_ts);

		if (shutdown_requested)
			break;

		rc = WaitLatch(&MyProc->procLatch,
			WL_LATCH_SET | WL_TIMEOUT | WL_POSTMASTER_DEATH,
			hdr->historyPeriod);

		if (rc & WL_POSTMASTER_DEATH)
			exit(1);

		if (hdr->request == HISTORY_REQUEST)
		{
			hdr->request = NO_REQUEST;

			mq = (shm_mq *)shm_toc_lookup(toc, 1);
			shm_mq_set_sender(mq, MyProc);
			mqh = shm_mq_attach(mq, NULL, NULL);
			shm_mq_wait_for_attach(mqh);

			if (shm_mq_get_receiver(mq) != NULL)
				send_history(&observations, mqh);

			shm_mq_detach(mq);
		}
	}

	MemoryContextReset(collector_context);

	/*
	 * We're done.  Explicitly detach the shared memory segment so that we
	 * don't get a resource leak warning at commit time.  This will fire any
	 * on_dsm_detach callbacks we've registered, as well.  Once that's done,
	 * we can go ahead and exit.
	 */
	proc_exit(0);
}
