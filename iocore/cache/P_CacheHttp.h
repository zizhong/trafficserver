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

#ifndef __CACHE_HTTP_H__
#define __CACHE_HTTP_H__

#include "P_CacheArray.h"
#ifdef HTTP_CACHE
#include "HTTP.h"
#include "URL.h"


typedef URL CacheURL;
typedef HTTPHdr CacheHTTPHdr;
typedef HTTPInfo CacheHTTPInfo;

#define OFFSET_BITS 24
enum
{
  OWNER_NONE = 0,
  OWNER_CACHE = 1,
  OWNER_HTTP = 2
};

#else
struct CacheHTTPInfo
{
};

#endif //HTTP_CACHE

struct vec_info
{
  CacheHTTPInfo alternate;
};

struct CacheHTTPInfoVector
{
  void *magic;

    CacheHTTPInfoVector();
   ~CacheHTTPInfoVector();

  int count()
  {
    return xcount;
  }
  int insert(CacheHTTPInfo * info, int id = -1);
  CacheHTTPInfo *get(int idx);
  void detach(int idx, CacheHTTPInfo * r);
  void remove(int idx, bool destroy);
  void clear(bool destroy = true);
  void reset()
  {
    xcount = 0;
    data.clear();
  }
  void print(char *buffer, size_t buf_size, bool temps = true);

  int marshal_length();
  int marshal(char *buf, int length);
  uint32_t get_handles(const char *buf, int length, RefCountObj * block_ptr = NULL);
  int unmarshal(const char *buf, int length, RefCountObj * block_ptr);

  CacheArray<vec_info> data;
  int xcount;
  Ptr<RefCountObj> vector_buf;
};

/** Range operation tracking.

    This holds a range specification. It also tracks the current object offset and the individual range.

    For simplification of the logic that uses this class it will pretend to be a single range of
    the object size if it is empty. To return the correct response we still need to distinuish
    those two cases.
*/
class CacheRange
{
 public:
  typedef CacheRange self; ///< Self reference type.

  /// Default constructor
 CacheRange() : _offset(0), _idx(-1), _r(NULL), _ct_field(NULL) { }

  /// Set the internal range spec pointer to @a src.
  self& setRangeSpec(HTTPRangeSpec* src);

  /// Test if the range should be active (used).
  /// @internal This means it has ranges and should be used to do seeks on the content.
  bool isActive() const;

  /// Test for multiple ranges.
  bool isMulti() const;

  /// Get the current object offset
  uint64_t getOffset() const;

  /// Get the current range index.
  int getIdx() const;

  /// Get the remaining contiguous bytes for the current range.
  uint64_t getRemnantSize() const;

  /** Advance @a size bytes in the range spec.

      @return The resulting offset in the object.
  */
  uint64_t consume(uint64_t size);

  /** Apply a @a src range and content @a len to the contained range spec.

      @return @c true if successfully applied, @c false otherwise.
  */
  bool apply(HTTPRangeSpec const& src, uint64_t len);

  /** Get the range boundary string.
      @a len if not @c NULL receives the length of the string.
  */
  char const* getBoundaryStr(int* len) const;

  /** Generate the range boundary string */
  void generateBoundaryStr(CacheKey const& key);

  /** Stash the Content-Type field pointer from a @a header.

      @return @c true if a Content-Type field was found in @a header, @c false if not.
  */
  bool setContentType(HTTPHdr* header);

  /** Calculate the effective HTTP content length value.
   */
  uint64_t calcContentLength() const;

 protected:
  uint64_t _len; ///< Total object length.
  uint64_t _offset; ///< Offset in content.
  int _idx; ///< Current range index. (< 0 means not in a range)
  HTTPRangeSpec* _r; ///< The actual ranges.
  MIMEField* _ct_field; ///< Content-Type field.
  char _boundary[HTTP_RANGE_BOUNDARY_LEN];
};

TS_INLINE CacheHTTPInfo *
CacheHTTPInfoVector::get(int idx)
{
  ink_assert(idx >= 0);
  ink_assert(idx < xcount);
  return &data[idx].alternate;
}

inline CacheRange&
CacheRange::setRangeSpec(HTTPRangeSpec* src)
{
  _r = src;
  return *this;
}

inline bool
CacheRange::apply(HTTPRangeSpec const& src, uint64_t len)
{
  return _r && _r->apply(src, len);
}

inline bool
CacheRange::isActive() const
{
  return _r && (_r->isSingle() || _r->isMulti());
}

inline uint64_t
CacheRange::getOffset() const
{
  return _offset;
}

inline int
CacheRange::getIdx() const
{
  return _idx;
}

inline uint64_t
CacheRange::getRemnantSize() const
{
  uint64_t zret = 0;

  if (!_r || _r->isEmpty())
    zret = _len - _offset;
  else if (_r->isValid() && 0 <= _idx && _idx < static_cast<int>(_r->count()))
    zret = ((*_r)[_idx]._max - _offset) + 1;

  return zret;
}

inline char const*
CacheRange::getBoundaryStr(int* len) const
{
  if (len) *len = sizeof(_boundary);
  return _boundary;
}

inline bool
CacheRange::isMulti() const
{
  return _r && _r->isMulti();
}

#endif /* __CACHE_HTTP_H__ */
