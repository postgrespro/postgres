/*-------------------------------------------------------------------------
 *
 * jsonb.h
 *	  Declarations for jsonb data type support.
 *
 * Copyright (c) 1996-2023, PostgreSQL Global Development Group
 *
 * src/include/utils/jsonb.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef __JSONB_H__
#define __JSONB_H__

#include "lib/stringinfo.h"
#include "utils/array.h"
#include "utils/numeric.h"
#include "access/detoast.h"

/* Tokens used when sequentially processing a jsonb value */
typedef enum
{
	WJB_DONE,
	WJB_KEY,
	WJB_VALUE,
	WJB_ELEM,
	WJB_BEGIN_ARRAY,
	WJB_END_ARRAY,
	WJB_BEGIN_OBJECT,
	WJB_END_OBJECT,
	WJB_RECURSE
} JsonbIteratorToken;

/* Strategy numbers for GIN index opclasses */
#define JsonbContainsStrategyNumber		7
#define JsonbExistsStrategyNumber		9
#define JsonbExistsAnyStrategyNumber	10
#define JsonbExistsAllStrategyNumber	11
#define JsonbJsonpathExistsStrategyNumber		15
#define JsonbJsonpathPredicateStrategyNumber	16


/*
 * In the standard jsonb_ops GIN opclass for jsonb, we choose to index both
 * keys and values.  The storage format is text.  The first byte of the text
 * string distinguishes whether this is a key (always a string), null value,
 * boolean value, numeric value, or string value.  However, array elements
 * that are strings are marked as though they were keys; this imprecision
 * supports the definition of the "exists" operator, which treats array
 * elements like keys.  The remainder of the text string is empty for a null
 * value, "t" or "f" for a boolean value, a normalized print representation of
 * a numeric value, or the text of a string value.  However, if the length of
 * this text representation would exceed JGIN_MAXLENGTH bytes, we instead hash
 * the text representation and store an 8-hex-digit representation of the
 * uint32 hash value, marking the prefix byte with an additional bit to
 * distinguish that this has happened.  Hashing long strings saves space and
 * ensures that we won't overrun the maximum entry length for a GIN index.
 * (But JGIN_MAXLENGTH is quite a bit shorter than GIN's limit.  It's chosen
 * to ensure that the on-disk text datum will have a short varlena header.)
 * Note that when any hashed item appears in a query, we must recheck index
 * matches against the heap tuple; currently, this costs nothing because we
 * must always recheck for other reasons.
 */
#define JGINFLAG_KEY	0x01	/* key (or string array element) */
#define JGINFLAG_NULL	0x02	/* null value */
#define JGINFLAG_BOOL	0x03	/* boolean value */
#define JGINFLAG_NUM	0x04	/* numeric value */
#define JGINFLAG_STR	0x05	/* string value (if not an array element) */
#define JGINFLAG_HASHED 0x10	/* OR'd into flag if value was hashed */
#define JGIN_MAXLENGTH	125		/* max length of text part before hashing */

typedef struct JsonbPair JsonbPair;
typedef struct JsonbValue JsonbValue;

/* flags for findJsonbValueFromContainer() */
#define JB_FSCALAR				0x10000000	/* flag bits */
#define JB_FOBJECT				0x20000000
#define JB_FARRAY				0x40000000

typedef enum jbvType
{
	/* Scalar types */
	jbvNull = 0x0,
	jbvString,
	jbvNumeric,
	jbvBool,
	/* Composite types */
	jbvArray = 0x10,
	jbvObject,
	/* Binary (i.e. struct Jsonb) jbvArray/jbvObject */
	jbvBinary,

	/*
	 * Virtual types.
	 *
	 * These types are used only for in-memory JSON processing and serialized
	 * into JSON strings when outputted to json/jsonb.
	 */
	jbvDatetime = 0x20,
	jbvScalar = 0x100
} JsonbValueType;

/*
 * JsonbValue:	In-memory representation of Jsonb.  This is a convenient
 * deserialized representation, that can easily support using the "val"
 * union across underlying types during manipulation.  The Jsonb on-disk
 * representation has various alignment considerations.
 */
struct JsonbValue
{
	enum jbvType type;			/* Influences sort order */

	union
	{
		Numeric numeric;
		bool		boolean;
		struct
		{
			int			len;
			const char  *val;	/* Not necessarily null-terminated */
		}			string;		/* String primitive type */

		struct
		{
			int			nElems;
			JsonbValue *elems;
			bool		rawScalar;	/* Top-level "raw scalar" array? */
		}			array;		/* Array container type */

		struct
		{
			int			nPairs; /* 1 pair, 2 elements */
			JsonbPair  *pairs;
		}			object;		/* Associative container type */

		struct
		{
			const struct JsonContainerData *data;
		}			binary;		/* Array or object, in on-disk format */

		struct
		{
			Datum		value;
			Oid			typid;
			int32		typmod;
			int			tz;		/* Numeric time zone, in seconds, for
								 * TimestampTz data type */
		}			datetime;
	}			val;
};

#define IsAJsonbScalar(jsonbval)	(((jsonbval)->type >= jbvNull && \
									  (jsonbval)->type <= jbvBool) || \
									  (jsonbval)->type == jbvDatetime)

/*
 * Key/value pair within an Object.
 *
 * This struct type is only used briefly while constructing a Jsonb; it is
 * *not* the on-disk representation.
 *
 * Pairs with duplicate keys are de-duplicated.  We store the originally
 * observed pair ordering for the purpose of removing duplicates in a
 * well-defined way (which is "last observed wins").
 */
struct JsonbPair
{
	JsonbValue	key;			/* Must be a jbvString */
	JsonbValue	value;			/* May be of any type */
	uint32		order;			/* Pair's index in original sequence */
};

/* Conversion state used when parsing Jsonb from text, or for type coercion */
typedef struct JsonbParseState JsonbParseState;

/*
 * JsonbIterator holds details of the type for each iteration. It also stores a
 * Jsonb varlena buffer, which can be directly accessed in some contexts.
 */
typedef enum
{
	JBI_ARRAY_START,
	JBI_ARRAY_ELEM,
	JBI_OBJECT_START,
	JBI_OBJECT_KEY,
	JBI_OBJECT_VALUE
} JsonbIterState;

typedef struct JsonbIterator JsonbIterator;


#include "utils/json_generic.h"

/* Support functions */
extern int	compareJsonbContainers(JsonbContainer *a, JsonbContainer *b);
extern JsonbValue *findJsonbValueFromContainer(const JsonbContainer *container,
											   uint32 flags,
											   JsonbValue *key);
extern JsonbValue *pushJsonbValueExt(JsonbParseState **pstate,
									 JsonbIteratorToken seq,
									 const JsonbValue *jbVal,
									 bool unpackBinary);
#define pushJsonbValue(pstate, seq, jv) pushJsonbValueExt(pstate, seq, jv, true)
extern JsonbValue *pushJsonbValueScalar(JsonbParseState **pstate,
										JsonbIteratorToken seq,
										const JsonbValue *scalarVal);
extern JsonbValue *pushScalarJsonbValue(JsonbParseState **pstate,
										const JsonbValue *jbval, bool isKey,
										bool unpackBinary);
extern JsonbParseState *JsonbParseStateClone(JsonbParseState *state);
#if 0 /* XXX SQL/JSON */
extern void JsonbParseStateSetUniqueKeys(JsonbParseState *state, bool unique_keys);
extern void JsonbParseStateSetSkipNulls(JsonbParseState *state, bool skip_nulls);
#endif
typedef struct JsonIteratorData JsonIterator;
extern JsonbIteratorToken JsonbIteratorNext(JsonIterator **it, JsonbValue *val,
											bool skipNested);
extern void JsonbHashScalarValue(const JsonbValue *scalarVal, uint32 *hash);
extern void JsonbHashScalarValueExtended(const JsonbValue *scalarVal,
										 uint64 *hash, uint64 seed);

extern int reserveFromBuffer(StringInfo buffer, int len);
extern void appendToBuffer(StringInfo buffer, const char *data, int len);

extern bool jsonb_sort_field_values;		/* GUC */
extern bool jsonb_partial_decompression;	/* GUC */
extern bool jsonb_partial_detoast;			/* GUC */

//#define JSONB_FREE_ITERATORS
#ifdef JSONB_FREE_ITERATORS
extern void jsonbInitIterators(void);
extern void jsonbFreeIterators(void);
extern MemoryContext jsonbGetIteratorContext(void);
#else
# define jsonbInitIterators() ((void) 0)
# define jsonbFreeIterators() ((void) 0)
#endif
extern void jsonbRegisterIterator(GenericDetoastIterator iter);

#endif							/* __JSONB_H__ */
