/*-------------------------------------------------------------------------
 *
 * jsonb_internals.h
 *	  Internal structure of jsonb data type.
 *
 * Copyright (c) 1996-2022, PostgreSQL Global Development Group
 *
 * src/include/utils/jsonb_internals.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef __JSONB_INTERNALS_H__
#define __JSONB_INTERNALS_H__

#include "postgres.h"

/*
 * Jsonbs are varlena objects, so must meet the varlena convention that the
 * first int32 of the object contains the total object size in bytes.  Be sure
 * to use VARSIZE() and SET_VARSIZE() to access it, though!
 *
 * Jsonb is the on-disk representation, in contrast to the in-memory JsonbValue
 * representation.  Often, JsonbValues are just shims through which a Jsonb
 * buffer is accessed, but they can also be deep copied and passed around.
 *
 * Jsonb is a tree structure. Each node in the tree consists of a JEntry
 * header and a variable-length content (possibly of zero size).  The JEntry
 * header indicates what kind of a node it is, e.g. a string or an array,
 * and provides the length of its variable-length portion.
 *
 * The JEntry and the content of a node are not stored physically together.
 * Instead, the container array or object has an array that holds the JEntrys
 * of all the child nodes, followed by their variable-length portions.
 *
 * The root node is an exception; it has no parent array or object that could
 * hold its JEntry. Hence, no JEntry header is stored for the root node.  It
 * is implicitly known that the root node must be an array or an object,
 * so we can get away without the type indicator as long as we can distinguish
 * the two.  For that purpose, both an array and an object begin with a uint32
 * header field, which contains an JB_FOBJECT or JB_FARRAY flag.  When a naked
 * scalar value needs to be stored as a Jsonb value, what we actually store is
 * an array with one element, with the flags in the array's header field set
 * to JB_FSCALAR | JB_FARRAY.
 *
 * Overall, the Jsonb struct requires 4-bytes alignment. Within the struct,
 * the variable-length portion of some node types is aligned to a 4-byte
 * boundary, while others are not. When alignment is needed, the padding is
 * in the beginning of the node that requires it. For example, if a numeric
 * node is stored after a string node, so that the numeric node begins at
 * offset 3, the variable-length portion of the numeric node will begin with
 * one padding byte so that the actual numeric data is 4-byte aligned.
 */

/*
 * JEntry format.
 *
 * The least significant 28 bits store either the data length of the entry,
 * or its end+1 offset from the start of the variable-length portion of the
 * containing object.  The next three bits store the type of the entry, and
 * the high-order bit tells whether the least significant bits store a length
 * or an offset.
 *
 * The reason for the offset-or-length complication is to compromise between
 * access speed and data compressibility.  In the initial design each JEntry
 * always stored an offset, but this resulted in JEntry arrays with horrible
 * compressibility properties, so that TOAST compression of a JSONB did not
 * work well.  Storing only lengths would greatly improve compressibility,
 * but it makes random access into large arrays expensive (O(N) not O(1)).
 * So what we do is store an offset in every JB_OFFSET_STRIDE'th JEntry and
 * a length in the rest.  This results in reasonably compressible data (as
 * long as the stride isn't too small).  We may have to examine as many as
 * JB_OFFSET_STRIDE JEntrys in order to find out the offset or length of any
 * given item, but that's still O(1) no matter how large the container is.
 *
 * We could avoid eating a flag bit for this purpose if we were to store
 * the stride in the container header, or if we were willing to treat the
 * stride as an unchangeable constant.  Neither of those options is very
 * attractive though.
 */
typedef uint32 JEntry;

#define JENTRY_OFFLENMASK		0x0FFFFFFF
#define JENTRY_TYPEMASK			0x70000000
#define JENTRY_HAS_OFF			0x80000000

/* values stored in the type bits */
#define JENTRY_ISSTRING			0x00000000
#define JENTRY_ISNUMERIC		0x10000000
#define JENTRY_ISBOOL_FALSE		0x20000000
#define JENTRY_ISBOOL_TRUE		0x30000000
#define JENTRY_ISNULL			0x40000000
#define JENTRY_ISCONTAINER		0x50000000	/* array or object */

/* Access macros.  Note possible multiple evaluations */
#define JBE_OFFLENFLD(je_)		((je_) & JENTRY_OFFLENMASK)
#define JBE_HAS_OFF(je_)		(((je_) & JENTRY_HAS_OFF) != 0)
#define JBE_ISSTRING(je_)		(((je_) & JENTRY_TYPEMASK) == JENTRY_ISSTRING)
#define JBE_ISNUMERIC(je_)		(((je_) & JENTRY_TYPEMASK) == JENTRY_ISNUMERIC)
#define JBE_ISCONTAINER(je_)	(((je_) & JENTRY_TYPEMASK) == JENTRY_ISCONTAINER)
#define JBE_ISNULL(je_)			(((je_) & JENTRY_TYPEMASK) == JENTRY_ISNULL)
#define JBE_ISBOOL_TRUE(je_)	(((je_) & JENTRY_TYPEMASK) == JENTRY_ISBOOL_TRUE)
#define JBE_ISBOOL_FALSE(je_)	(((je_) & JENTRY_TYPEMASK) == JENTRY_ISBOOL_FALSE)
#define JBE_ISBOOL(je_)			(JBE_ISBOOL_TRUE(je_) || JBE_ISBOOL_FALSE(je_))

/* Macro for advancing an offset variable to the next JEntry */
#define JBE_ADVANCE_OFFSET(offset, je) \
	do { \
		JEntry	je_ = (je); \
		if (JBE_HAS_OFF(je_)) \
			(offset) = JBE_OFFLENFLD(je_); \
		else \
			(offset) += JBE_OFFLENFLD(je_); \
	} while(0)

/*
 * We store an offset, not a length, every JB_OFFSET_STRIDE children.
 * Caution: this macro should only be referenced when creating a JSONB
 * value.  When examining an existing value, pay attention to the HAS_OFF
 * bits instead.  This allows changes in the offset-placement heuristic
 * without breaking on-disk compatibility.
 */
#define JB_OFFSET_STRIDE		32

typedef uint32 JsonbContainerHdr;

/*
 * A jsonb array or object node, within a Jsonb Datum.
 *
 * An array has one child for each element, stored in array order.
 *
 * An object has two children for each key/value pair.  The keys all appear
 * first, in key sort order; then the values appear, in an order matching the
 * key order.  This arrangement keeps the keys compact in memory, making a
 * search for a particular key more cache-friendly.
 */
typedef struct JsonbContainerHeader
{
	JsonbContainerHdr header;	/* number of elements or key/value
								 * pairs, and flags */
	JEntry		children[FLEXIBLE_ARRAY_MEMBER];

	/* the data for each child node follows. */
} JsonbContainerHeader;

/* flags for the header-field in JsonbContainer */
#define JBC_CMASK				0x0FFFFFFF	/* mask for count field */
#define JBC_TMASK				0x70000000	/* mask for container type */
/* container types */
#define JBC_TOBJECT				0x20000000	/* object with key-value pairs
											 * sorted by key length-alpha */
#define JBC_TOBJECT_SORTED		0x30000000	/* object with keys sorted by
											 * length-alpha; values sorted by
											 * length */
#define JBC_TARRAY				0x40000000	/* array */
#define JBC_TSCALAR				0x50000000	/* scalar pseudo-array */

/* The top-level on-disk format for a jsonb datum. */
typedef struct
{
	int32		vl_len_;		/* varlena header (do not touch directly!) */
	JsonbContainerHeader root;
} JsonbDatum;

#endif							/* __JSONB_INTERNALS_H__ */
