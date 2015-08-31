#ifndef __PG_STAT_WAIT_H__
#define __PG_STAT_WAIT_H__

#include <postgres.h>
#include "storage/proc.h"
#include "utils/timestamp.h"

#define	PG_STAT_WAIT_MAGIC		0xca94b107
#define COLLECTOR_QUEUE_SIZE	16384
#define HISTORY_TIME_MULTIPLIER	10
#define HISTORY_COLUMNS_COUNT	(5 + WAIT_PARAMS_COUNT)

typedef struct
{
	uint32	backendPid;
	bool	reset;
	int		backendIdx;
	int		classIdx;
	int		eventIdx;
} WaitProfileContext;

typedef struct
{
	int		class_cnt;
	int		event_cnt;
} WaitEventContext;

typedef struct
{
	int		classId;
	int		eventId;
	int		params[WAIT_PARAMS_COUNT];
	int		backendPid;
	uint64	waitTime;

	TimestampTz	ts;
} HistoryItem;

typedef struct
{
	int				idx;
	HistoryItem	   *state;
	bool			done;
	TimestampTz		ts;
} WaitCurrentContext;

typedef struct
{
	bool			wraparound;
	int				index;
	int				count;
	HistoryItem	   *items;
} History;

typedef enum
{
	NO_REQUEST,
	HISTORY_REQUEST
} SHMRequest;

typedef struct
{
	Latch	   *latch;
	SHMRequest	request;
	int			historySize;
	int			historyPeriod;
	bool		historySkipLatch;
} CollectorShmqHeader;

extern PGDLLIMPORT char *WAIT_LOCK_NAMES[];
extern PGDLLIMPORT char *WAIT_LWLOCK_NAMES[];
extern PGDLLIMPORT char *WAIT_IO_NAMES[];
extern PGDLLIMPORT char *WAIT_NETWORK_NAMES[];
extern PGDLLIMPORT const int WAIT_OFFSETS[];

Size CollectorShmemSize(void);
CollectorShmqHeader *GetCollectorMem(bool init);
void RegisterWaitsCollector(void);
void AllocHistory(History *, int);
int GetCurrentWaitsState(PGPROC *, HistoryItem *, int);

#endif
