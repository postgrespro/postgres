#include "postgres.h"
#include "storage/wait.h"
#include "utils/datetime.h"
#include "utils/memutils.h"
#include "port/atomics.h"
#include <inttypes.h>

extern int max_replication_slots;
extern int *main_lwlock_groups;
static slock_t *WaitCounterLock;
static bool lwlock_group_notified = false;

void *WaitShmem;
bool WaitsOn;
bool WaitsHistoryOn;
int WaitsFlushPeriod;

#define SHMEM_WAIT_CELLS ((BackendWaitCells *)((char *)WaitCounterLock \
			+ MAXALIGN(sizeof(slock_t))))

const char *WAIT_CLASSES[WAITS_COUNT] =
{
	"CPU",
	"LWLocks",
	"Locks",
	"Storage",
	"Latch",
	"Network"
};

const char *WAIT_LOCK_NAMES[WAIT_LOCKS_COUNT] =
{
	"Relation",
	"RelationExtend",
	"Page",
	"Tuple",
	"Transaction",
	"VirtualTransaction",
	"SpeculativeToken",
	"Object",
	"Userlock",
	"Advisory",
};

/* We keep all LWLock names here. Order is very important here.
 * Index is equal to lwlock group field
 */
const char *WAIT_LWLOCK_NAMES[WAIT_LWLOCKS_COUNT] =
{
	"", /* formely was BufFreelistLock */
	"ShmemIndexLock",
	"OidGenLock",
	"XidGenLock",
	"ProcArrayLock",
	"SInvalReadLock",
	"SInvalWriteLock",
	"WALBufMappingLock",
	"WALWriteLock",
	"ControlFileLock",
	"CheckpointLock",
	"CLogControlLock",
	"SubtransControlLock",
	"MultiXactGenLock",
	"MultiXactOffsetControlLock",
	"MultiXactMemberControlLock",
	"RelCacheInitLock",
	"CheckpointerCommLock",
	"TwoPhaseStateLock",
	"TablespaceCreateLock",
	"BtreeVacuumLock",
	"AddinShmemInitLock",
	"AutovacuumLock",
	"AutovacuumScheduleLock",
	"SyncScanLock",
	"RelationMappingLock",
	"AsyncCtlLock",
	"AsyncQueueLock",
	"SerializableXactHashLock",
	"SerializableFinishedListLock",
	"SerializablePredicateLockListLock",
	"OldSerXidLock",
	"SyncRepLock",
	"BackgroundWorkerLock",
	"DynamicSharedMemoryControlLock",
	"AutoFileLock",
	"ReplicationSlotAllocationLock",
	"ReplicationSlotControlLock",
	"CommitTsControlLock",
	"CommitTsLock",
	"ReplicationOriginLock",
	"BufferPartitionLock",
	"LockManagerPartitionLock",
	"PredicatePartitionLock",
	"SharedBufferLocks",
	"ProcessLock",
	"CLogBufferLock",
	"CommitTsBufferLock",
	"SubtransBufferLock",
	"MultixactBufferLock",
	"AsyncBufferLock",
	"OldSerializalbeXidBufferLock",
	"ReplicationSlotLock",
	"UserDefinedLock",
	"WALInsertLocks",
	"ReplicationOriginLocks",
};

const char *WAIT_IO_NAMES[WAIT_IO_EVENTS_COUNT] =
{
	"READ",
	"WRITE",
};

const char *WAIT_NETWORK_NAMES[WAIT_NETWORK_EVENTS_COUNT] =
{
	"READ",
	"WRITE"
};

const int WAIT_OFFSETS[] =
{
	0, /* skip */
	WAIT_LWLOCKS_OFFSET,
	WAIT_LOCKS_OFFSET,
	WAIT_IO_OFFSET,
	WAIT_LATCH_OFFSET,
	WAIT_NETWORK_OFFSET
};

/* Returns event name for wait. All names defined in arrays above */
const char *
WaitsEventName(int classId, int eventId)
{
	switch (classId)
	{
		case WAIT_LOCK: return WAIT_LOCK_NAMES[eventId];
		case WAIT_LWLOCK: return WAIT_LWLOCK_NAMES[eventId];
		case WAIT_IO: return WAIT_IO_NAMES[eventId];
		case WAIT_NETWORK: return WAIT_NETWORK_NAMES[eventId];
		case WAIT_LATCH: return WAIT_CLASSES[WAIT_LATCH];
		case WAIT_CPU: return WAIT_CLASSES[WAIT_CPU];
	};
	return NULL;
}

/*
 * Gets lwlock group. If this lwlock from main tranche, returns index
 * from `main_lwlock_groups`, for other tranches that group must be
 * defined manually (by define in wait.h, and then assigning group in 
 * tranche lwlocks creation)
 */
static int
get_lwlock_group(volatile LWLock *lock)
{
	int group = -1;
	if (lock->tranche == 0)
	{
		int numLocks, i;
		int idx = (union LWLockPadded *)lock - MainLWLockArray;

		if (idx < NUM_INDIVIDUAL_LWLOCKS)
			group = idx;

		numLocks = NUM_INDIVIDUAL_LWLOCKS;
		for (i=0; i < NUM_ADD_LWLOCK_GROUPS; i++)
		{
			numLocks += main_lwlock_groups[i*2];
			if (idx < numLocks)
			{
				group = main_lwlock_groups[i*2+1];
				break;
			}
		}
	}
	else if (!lwlock_group_notified)
	{
		elog(INFO, "LWLock with tranche id #%d not monitored", lock->tranche);
		lwlock_group_notified = true;
	}

	return group;
}

static void
write_trace_start(FILE *fd, int classId, int eventId,
		int p1, int p2, int p3, int p4, int p5)
{
	TimestampTz current_ts;
	int n;

	/* Buffer calculation:
	 * 4 integers
	 * timestamp (MAXDATELEN)
	 * 33 for max name (SerializablePredicateLockListLock at this time)
	 * 7 for max wait class (Storage or Network)
	 * and spaces
	 * format like: start 2015-05-18 06:52:03.244103-04 LWlocks SerializablePredicateLockListLock 0 0 0 0
	 */

	char buf[10 * 4 + MAXDATELEN + 33 + 7 + 10];
	const char *event_name;

	Assert(fd != NULL);
	current_ts = GetCurrentTimestamp();
	event_name = WaitsEventName(classId, eventId);
	n = snprintf(buf, sizeof(buf), "start %s %s %s %d %d %d %d %d\n",
			DatumGetCString(DirectFunctionCall1(timestamptz_out, current_ts)),
			WAIT_CLASSES[classId],
			event_name == NULL? "" : event_name,
			p1, p2, p3, p4, p5);

	if (n != -1)
	{
		fwrite(buf, sizeof(char), n, fd);
		fflush(fd);
	}
	else
		elog(INFO, "Wait trace formatting error");
}

static void
write_trace_stop(FILE *fd, int classId)
{
	TimestampTz current_ts;
	int n;
	char buf[MAXDATELEN + 33 + 5];

	Assert(fd != NULL);
	current_ts = GetCurrentTimestamp();
	n = snprintf(buf, sizeof(buf), "stop %s %s\n",
			DatumGetCString(DirectFunctionCall1(timestamptz_out, current_ts)),
			WAIT_CLASSES[classId]);

	if (n != -1)
	{
		fwrite(buf, sizeof(char), n, fd);
		fflush(fd);
	}
}

/* Flushes all waits from backend local memory to shared memory block */
static void
flush_waits(ProcWaits *waits)
{
	int offset;
	bool flushed;
	BackendWaitCells *sh_cells;

	if (waits->smWaitCells == NULL)
		return;

	sh_cells = (BackendWaitCells *)(waits->smWaitCells);

	for (offset=0; offset < WAIT_EVENTS_COUNT; offset++)
	{
		WaitCell *cell = ((WaitCell *)waits->waitCells) + offset;
		if (cell->count == 0)
			continue;

		/* If TAS ok we can update data in shared memory,
		 * if not then we skip this time 
		 */
		if (pg_atomic_test_set_flag(&sh_cells->isBusy))
		{
			sh_cells->cells[offset].interval += cell->interval;
			sh_cells->cells[offset].count += cell->count;
			cell->count = cell->interval = 0;
			pg_atomic_clear_flag(&sh_cells->isBusy);
			flushed = true;
		}
	}

	if (flushed)
		INSTR_TIME_SET_CURRENT(waits->flushTime);
}

/* Init backend's block in shared memory
 * Backends will flush data to this block by some interval
 */
static void
init_backend_shmem_cells(PGPROC *proc)
{
	int *counter;
	bool counter_was_restarted = false;
	BackendWaitCells *cells, *curcells;

	// init variables
	counter = (int *)WaitShmem;
	// start of cells
	cells = SHMEM_WAIT_CELLS;

	Assert(proc->waits.smWaitCells == NULL);
	SpinLockAcquire(WaitCounterLock);

	do
	{
		if (*counter >= MaxBackends)
		{
			if (counter_was_restarted)
			{
				elog(INFO, "No available wait cells for backend: %d", proc->pid);
				break;
			}
			*counter = 0;
			counter_was_restarted = true;
		}

		curcells = cells + (*counter)++;
		if (pg_atomic_test_set_flag(&curcells->isTaken))
		{
			do
			{
				/* Wait until block is certainly free */
			} while (!pg_atomic_unlocked_test_flag(&curcells->isBusy));

			pg_atomic_init_flag(&curcells->isBusy);
			curcells->backendPid = proc->pid;
			MemSet(curcells->cells, 0, sizeof(WaitCell) * WAIT_EVENTS_COUNT);
			proc->waits.smWaitCells = (void *) curcells;
			break;
		}
	} while (1);

	SpinLockRelease(WaitCounterLock);
}

/* Sets current wait in backend, it fills current buffer and remembers 
 * time when wait is started. Current buffer is opposite of current
 * reading buffer. When collector reads data from its buffer, it sets
 * -1 to reading index and backend can switch buffers
 */
void
StartWait(int classId, int eventId, int p1, int p2, int p3, int p4, int p5)
{
	ProcWaits		*waits;
	ProcWait		*curwait;

	Assert(classId > 0 && classId < WAITS_COUNT);

	if (!MyProc)
		return;

	/* preventing nested waits */
	waits = &MyProc->waits;
	if (waits->nested++ > 0) return;
	Assert(waits->nested == 1);

	/* if tracing was started with `pg_start_trace`,
	 * we initialize it here
	 */
	if (waits->traceOn && waits->traceFd == NULL)
	{
		waits->traceFd = fopen(waits->traceFn, "w");
		if (waits->traceFd == NULL)
		{
			waits->traceOn = false;
			elog(WARNING, "could not open trace file \"%s\": %m",
					waits->traceFn);
		}
		else
			elog(INFO, "Trace was started to: %s", waits->traceFn);
	}
	else if (!waits->traceOn && waits->traceFd != NULL)
	{
		fclose(waits->traceFd);
		waits->traceFd = NULL;
		elog(INFO, "Trace was stopped");
	}

	if (waits->traceFd != NULL)
		write_trace_start(waits->traceFd, classId, eventId,
				p1, p2, p3, p4, p5);

	/* switching buffers */
	waits->writeIdx = !waits->readIdx;
	curwait = &waits->waitsBuf[waits->writeIdx];
	curwait->classId = classId;
	curwait->eventId = eventId;
	curwait->params[0] = p1;
	curwait->params[1] = p2;
	curwait->params[2] = p3;
	curwait->params[3] = p4;
	curwait->params[4] = p5;
	INSTR_TIME_SET_CURRENT(curwait->startTime);

	/* we don't care about result, if reader didn't changed it index,
		then keep the value */
	if (waits->readIdx == -1)
		waits->readIdx = waits->writeIdx;
}

/* Special function for lwlock waits, because we need to determine lwlock
 * group
 */
void
StartLWLockWait(volatile LWLock *lock, LWLockMode mode)
{
	if (lock->group == -1)
		lock->group = get_lwlock_group(lock);

	if (lock->group >= 0)
		WAIT_START(WAIT_LWLOCK, lock->group, mode, 0, 0, 0, 0);
}

/* Stops current wait, calculates interval of wait, and flushes
 * collected waits info to shared memory if last flush has been more than
 * WaitsFlushPeriod milliseconds ago
 */
void
StopWait()
{
	int offset;
	WaitCell *waitCell;
	instr_time currentTime, currentTimeCopy;
	ProcWaits *waits;
	ProcWait  *curwait;

	if (!MyProc)
		return;

	waits = &MyProc->waits;

	/* prevent nested waits */
	if ((--waits->nested) > 0) return;
	Assert(waits->nested == 0);

	/* first thing we save the time after wait */
	INSTR_TIME_SET_CURRENT(currentTime);
	currentTimeCopy = currentTime;
	curwait = &waits->waitsBuf[waits->writeIdx];

	/* file tracing */
	if (waits->traceFd != NULL)
		write_trace_stop(waits->traceFd, curwait->classId);

	/* determine offset of current wait in proc wait cells */
	offset = WAIT_OFFSETS[(int)curwait->classId] + curwait->eventId;
	Assert(offset <= WAIT_EVENTS_COUNT);

	waitCell = &((WaitCell *)waits->waitCells)[offset];
	INSTR_TIME_SUBTRACT(currentTime, curwait->startTime);
	waitCell->interval += INSTR_TIME_GET_MICROSEC(currentTime);
	waitCell->count++;

	/* determine difference between last flush time, and write
	 * current profile to cells in shared memory if needed
	 */
	INSTR_TIME_SUBTRACT(currentTimeCopy, waits->flushTime);
	if ((long) INSTR_TIME_GET_MICROSEC(currentTimeCopy) >= (1000L * WaitsFlushPeriod))
		flush_waits(waits);
}


/* Returns size in shared memory enough to hold data of all procs */
Size
WaitsShmemSize()
{
	int size;

	size = mul_size(MaxBackends, sizeof(BackendWaitCells));
	size = add_size(size, sizeof(int)); // for counter
	size = add_size(size, MAXALIGN(sizeof(slock_t))); //for counter lock
	return size;
}

/* Allocate space in shared memory */
void
WaitsAllocateShmem()
{
	BackendWaitCells *cells;
	int i;

	Size size = WaitsShmemSize();
	WaitShmem = ShmemAlloc(size);
	MemSet(WaitShmem, 0, size);
	WaitCounterLock = (slock_t *)((char *)WaitShmem + sizeof(int));

	cells = SHMEM_WAIT_CELLS;
	for (i=0; i < MaxBackends; i++) 
		pg_atomic_init_flag(&cells->isTaken);

	SpinLockInit(WaitCounterLock);
}

/* Marks reserved block in shared memory used by process as free, so new
 * processes can take it
 */
void
WaitsFreeBackendCells(PGPROC *proc)
{
	// deattach backend from waits shared memory
	if (proc->waits.smWaitCells != NULL)
	{
		BackendWaitCells *cells;

		flush_waits(&proc->waits);
		cells = ((BackendWaitCells *)proc->waits.smWaitCells);

		/* Stop writing to shmem */
		proc->waits.smWaitCells = NULL;

		/* Mark shmem block as free */
		pg_atomic_clear_flag(&cells->isTaken);
	}
}

/* Init fields needed by monitoring in PGPROC structure. Also it reserves
 * block in shared memory
 */
void
WaitsInitProcessFields(PGPROC *proc)
{
	MemSet(&proc->waits, 0, sizeof(ProcWaits));
	MemSet(proc->waits.traceFn, 0, WAIT_TRACE_FN_LEN);
	proc->waits.waitCells = MemoryContextAllocZero(TopMemoryContext,
			sizeof(WaitCell) * WAIT_EVENTS_COUNT);
	proc->waits.readIdx = -1;
	init_backend_shmem_cells(proc);
}
