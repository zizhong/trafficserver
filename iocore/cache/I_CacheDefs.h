/** @file

  A brief file description

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#include <vector>

#ifndef _I_CACHE_DEFS_H__
#define _I_CACHE_DEFS_H__

#define CACHE_INIT_FAILED           -1
#define CACHE_INITIALIZING          0
#define CACHE_INITIALIZED           1

#define CACHE_ALT_INDEX_DEFAULT     -1
#define CACHE_ALT_REMOVED           -2

#define CACHE_DB_MAJOR_VERSION      24
#define CACHE_DB_MINOR_VERSION      0

#define CACHE_DIR_MAJOR_VERSION     18
#define CACHE_DIR_MINOR_VERSION     0

#define CACHE_DB_FDS                128

// opcodes
#define CACHE_OPEN_READ			1
#define CACHE_OPEN_READ_BUFFER		2
#define CACHE_OPEN_READ_LONG		3
#define CACHE_OPEN_READ_BUFFER_LONG	4
#define CACHE_OPEN_WRITE		5
#define CACHE_OPEN_WRITE_BUFFER		6
#define CACHE_OPEN_WRITE_LONG		7
#define CACHE_OPEN_WRITE_BUFFER_LONG	8
#define CACHE_UPDATE			9
#define CACHE_REMOVE			10
#define CACHE_LINK			11
#define CACHE_DEREF			12
#define CACHE_LOOKUP_OP			13

enum CacheType {
  CACHE_NONE_TYPE = 0,  // for empty disk fragments
  CACHE_HTTP_TYPE = 1,
  CACHE_RTSP_TYPE = 2
};

// NOTE: All the failures are ODD, and one greater than the success
//       Some of these must match those in <ts/ts.h>
enum CacheEventType
{
  CACHE_EVENT_LOOKUP = CACHE_EVENT_EVENTS_START + 0,
  CACHE_EVENT_LOOKUP_FAILED = CACHE_EVENT_EVENTS_START + 1,
  CACHE_EVENT_OPEN_READ = CACHE_EVENT_EVENTS_START + 2,
  CACHE_EVENT_OPEN_READ_FAILED = CACHE_EVENT_EVENTS_START + 3,
  // 4-7 unused
  CACHE_EVENT_OPEN_WRITE = CACHE_EVENT_EVENTS_START + 8,
  CACHE_EVENT_OPEN_WRITE_FAILED = CACHE_EVENT_EVENTS_START + 9,
  CACHE_EVENT_REMOVE = CACHE_EVENT_EVENTS_START + 12,
  CACHE_EVENT_REMOVE_FAILED = CACHE_EVENT_EVENTS_START + 13,
  CACHE_EVENT_UPDATE,
  CACHE_EVENT_UPDATE_FAILED,
  CACHE_EVENT_LINK,
  CACHE_EVENT_LINK_FAILED,
  CACHE_EVENT_DEREF,
  CACHE_EVENT_DEREF_FAILED,
  CACHE_EVENT_SCAN = CACHE_EVENT_EVENTS_START + 20,
  CACHE_EVENT_SCAN_FAILED = CACHE_EVENT_EVENTS_START + 21,
  CACHE_EVENT_SCAN_OBJECT = CACHE_EVENT_EVENTS_START + 22,
  CACHE_EVENT_SCAN_OPERATION_BLOCKED = CACHE_EVENT_EVENTS_START + 23,
  CACHE_EVENT_SCAN_OPERATION_FAILED = CACHE_EVENT_EVENTS_START + 24,
  CACHE_EVENT_SCAN_DONE = CACHE_EVENT_EVENTS_START + 25,
  //////////////////////////
  // Internal error codes //
  //////////////////////////
  CACHE_EVENT_RESPONSE = CACHE_EVENT_EVENTS_START + 50,
  CACHE_EVENT_RESPONSE_MSG,
  CACHE_EVENT_RESPONSE_RETRY
};

enum CacheScanResult
{
  CACHE_SCAN_RESULT_CONTINUE = EVENT_CONT,
  CACHE_SCAN_RESULT_DONE = EVENT_DONE,
  CACHE_SCAN_RESULT_DELETE = 10,
  CACHE_SCAN_RESULT_DELETE_ALL_ALTERNATES,
  CACHE_SCAN_RESULT_UPDATE,
  CACHE_SCAN_RESULT_RETRY
};

enum CacheDataType
{
  CACHE_DATA_HTTP_INFO = VCONNECTION_CACHE_DATA_BASE,
  CACHE_DATA_KEY,
  CACHE_DATA_RAM_CACHE_HIT_FLAG
};

enum CacheFragType
{
  CACHE_FRAG_TYPE_NONE,
  CACHE_FRAG_TYPE_HTTP_V23, ///< DB version 23 or prior.
  CACHE_FRAG_TYPE_RTSP, ///< Should be removed once Cache Toolkit is implemented.
  CACHE_FRAG_TYPE_HTTP,
  NUM_CACHE_FRAG_TYPES
};

typedef CryptoHash CacheKey;
#define CACHE_ALLOW_MULTIPLE_WRITES 1
#define CACHE_EXPECTED_SIZE 32768

/* uses of the CacheKey
   word(0) - cache partition segment
   word(1) - cache partition bucket
   word(2) - tag (lower bits), hosttable hash (upper bits)
   word(3) - ram cache hash, lookaside cache
 */


/** A range specification.

    This represents the data for an HTTP range specification.
*/
struct RangeSpec {
  typedef RangeSpec self;

  /** A range of bytes in an object.

      If @a _min > 0 and @a _max == 0 the range is backwards and counts from the
      end of the object. That is (100,0) means the last 100 bytes of content.
  */
  struct Range {
    uint64_t _min;
    uint64_t _max;

    /// Default constructor - invalid range.
    Range() : _min(UINT64_MAX), _max(1) { }
    /// Construct as the range ( @a low .. @a high )
    Range(uint64_t low, uint64_t high) : _min(low), _max(high) {}

    /// Test if this range is a trailing (terminal) range.
    bool isSuffix() const;
    /// Test if this range is a valid range.
    bool isValid() const;
    /// Adjust the range values based on content size @a len.
    bool finalize(uint64_t len);
    /// Force the range to an invalid state.
    Range& invalidate();
  };

  /// Current state of the overall specification.
  /// @internal We can distinguish between @c SINGLE and @c MULTI by looking at the
  /// size of @a _ranges but we need this to mark @c EMPTY vs. not.
  enum State {
    EMPTY, ///< No range.
    INVALID, ///< Range parsing failed.
    SINGLE, ///< Single range.
    MULTI, ///< Multiple ranges.
  } _state;

  /// The first range value.
  /// By separating this out we can avoid allocation in the case of a single
  /// range value, which is by far the most common ( > 99% in my experience).
  Range _single;
  /// Storage for range values.
  typedef std::vector<Range> RangeBox;
  /// The first range is copied here if there is more than one (to simplify).
  RangeBox _ranges;

  /// Default constructor - invalid range
  RangeSpec();

  /** Parse a range field and update @a this with the results.
      @return @c true if @a v was a valid range specifier, @c false otherwise.
  */
  bool parse(char const* v, int len);

  /** Validate and convert for a specific content @a length.

      @return @c true if the range is satisfiable per the HTTP spec, @c false otherwise.
      Note a range spec with no ranges is always satisfiable.
   */
  bool finalize(uint64_t length);

  /** Number of distinct ranges.
      @return Number of ranges.
  */
  size_t count() const;

  /// If this is a valid  single range specification.
  bool isSingle() const;

  /// If this is a valid multi range specification.
  bool isMulti() const;

  /// Test if this contains at least one valid range.
  bool isValid() const;

  /// Test if this is a valid but empty range spec.
  bool isEmpty() const;

protected:
  self& add(uint64_t low, uint64_t high);
};

inline
RangeSpec::RangeSpec() : _state(EMPTY)
{
}

inline bool
RangeSpec::isSingle() const
{
  return SINGLE == _state;
}

inline bool
RangeSpec::isMulti() const
{
  return MULTI == _state;
}

inline bool
RangeSpec::isEmpty() const
{
  return EMPTY == _state;
}

inline size_t
RangeSpec::count() const
{
  return SINGLE == _state ? 1 : _ranges.size();
}

inline bool
RangeSpec::isValid() const
{
  return SINGLE == _state || MULTI == _state;
}

inline RangeSpec::Range&
RangeSpec::Range::invalidate()
{
  _min = UINT64_MAX;
  _max = 1;
  return *this;
}

inline bool
RangeSpec::Range::isSuffix() const
{
  return 0 == _max && _min > 0;
}

inline bool
RangeSpec::Range::isValid() const
{
  return _min <= _max || this->isSuffix();
}

inline bool
RangeSpec::Range::finalize(uint64_t len)
{
  ink_assert(len > 0);
  bool zret = true; // is this range satisfiable for @a len?
  if (this->isSuffix()) {
    _max = len - 1;
    _min = _min > len ? 0 : len - _min;
  } else if (_min < len) {
    _max = MIN(_max,len);
  } else {
    this->invalidate();
    zret = false;
  }
  return zret;
}
#endif // __CACHE_DEFS_H__
