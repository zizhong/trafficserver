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

#include "ink_config.h"
#include <string.h>
#include "P_Cache.h"


/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/

static vec_info default_vec_info;

#ifdef HTTP_CACHE
static CacheHTTPInfo default_http_info;

CacheHTTPInfoVector::CacheHTTPInfoVector()
:magic(NULL), data(&default_vec_info, 4), xcount(0)
{
}

/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/

CacheHTTPInfoVector::~CacheHTTPInfoVector()
{
  int i;

  for (i = 0; i < xcount; i++) {
    data[i].alternate.destroy();
  }
  vector_buf.clear();
  magic = NULL;
}

/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/

int
CacheHTTPInfoVector::insert(CacheHTTPInfo * info, int index)
{
  if (index == CACHE_ALT_INDEX_DEFAULT)
    index = xcount++;

  data(index).alternate.copy_shallow(info);
  return index;
}

/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/


void
CacheHTTPInfoVector::detach(int idx, CacheHTTPInfo * r)
{
  int i;

  ink_assert(idx >= 0);
  ink_assert(idx < xcount);

  r->copy_shallow(&data[idx].alternate);
  data[idx].alternate.destroy();

  for (i = idx; i < (xcount - 1); i++) {
    data[i] = data[i + i];
  }

  xcount -= 1;
}

/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/

void
CacheHTTPInfoVector::remove(int idx, bool destroy)
{
  if (destroy)
    data[idx].alternate.destroy();

  for (; idx < (xcount - 1); idx++)
    data[idx] = data[idx + 1];

  xcount--;
}

/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/

void
CacheHTTPInfoVector::clear(bool destroy)
{
  int i;

  if (destroy) {
    for (i = 0; i < xcount; i++) {
      data[i].alternate.destroy();
    }
  }
  xcount = 0;
  data.clear();
  vector_buf.clear();
}

/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/

void
CacheHTTPInfoVector::print(char *buffer, size_t buf_size, bool temps)
{
  char buf[33], *p;
  int purl;
  int i, tmp;

  p = buffer;
  purl = 1;

  for (i = 0; i < xcount; i++) {
    if (data[i].alternate.valid()) {
      if (purl) {
        Arena arena;
        char *url;

        purl = 0;
        URL u;
        data[i].alternate.request_url_get(&u);
        url = u.string_get(&arena);
        if (url) {
          snprintf(p, buf_size, "[%s] ", url);
          tmp = strlen(p);
          p += tmp;
          buf_size -= tmp;
        }
      }

      if (temps || !(data[i].alternate.object_key_get() == zero_key)) {
        snprintf(p, buf_size, "[%d %s]", data[i].alternate.id_get(),
                     CacheKey(data[i].alternate.object_key_get()).toHexStr(buf));
        tmp = strlen(p);
        p += tmp;
        buf_size -= tmp;
      }
    }
  }
}

/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/

int
CacheHTTPInfoVector::marshal_length()
{
  int length = 0;

  for (int i = 0; i < xcount; i++) {
    length += data[i].alternate.marshal_length();
  }

  return length;
}

/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/
int
CacheHTTPInfoVector::marshal(char *buf, int length)
{
  char *start = buf;
  int count = 0;

  ink_assert(!(((intptr_t) buf) & 3));      // buf must be aligned

  for (int i = 0; i < xcount; i++) {
    int tmp = data[i].alternate.marshal(buf, length);
    length -= tmp;
    buf += tmp;
    count++;
  }

  GLOBAL_CACHE_SUM_GLOBAL_DYN_STAT(cache_hdr_vector_marshal_stat, 1);
  GLOBAL_CACHE_SUM_GLOBAL_DYN_STAT(cache_hdr_marshal_stat, count);
  GLOBAL_CACHE_SUM_GLOBAL_DYN_STAT(cache_hdr_marshal_bytes_stat, buf - start);
  return buf - start;
}

int
CacheHTTPInfoVector::unmarshal(const char *buf, int length, RefCountObj * block_ptr)
{
  ink_assert(!(((intptr_t) buf) & 3));      // buf must be aligned

  const char *start = buf;
  CacheHTTPInfo info;
  xcount = 0;

  while (length - (buf - start) > (int) sizeof(HTTPCacheAlt)) {

    int tmp = HTTPInfo::unmarshal((char *) buf, length - (buf - start), block_ptr);
    if (tmp < 0) {
      return -1;
    }
    info.m_alt = (HTTPCacheAlt *) buf;
    buf += tmp;

    data(xcount).alternate = info;
    xcount++;
  }

  return ((caddr_t) buf - (caddr_t) start);
}


/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/
uint32_t
CacheHTTPInfoVector::get_handles(const char *buf, int length, RefCountObj * block_ptr)
{
  ink_assert(!(((intptr_t) buf) & 3));      // buf must be aligned

  const char *start = buf;
  CacheHTTPInfo info;
  xcount = 0;

  vector_buf = block_ptr;

  while (length - (buf - start) > (int) sizeof(HTTPCacheAlt)) {

    int tmp = info.get_handle((char *) buf, length - (buf - start));
    if (tmp < 0) {
      ink_assert(!"CacheHTTPInfoVector::unmarshal get_handle() failed");
      return (uint32_t) -1;
    }
    buf += tmp;

    data(xcount).alternate = info;
    xcount++;
  }

  return ((caddr_t) buf - (caddr_t) start);
}

/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/

void
CacheRange::clear()
{
  _offset = 0;
  _idx = -1;
  _pending_range_shift_p = false;
  _ct_field = NULL; // need to do real cleanup at some point.
  _r.clear();
}

bool
CacheRange::init(HTTPHdr* req)
{
  bool zret = true;
  MIMEField* rf = req->field_find(MIME_FIELD_RANGE, MIME_LEN_RANGE);
  if (rf) {
    int len;
    char const* val = rf->value_get(&len);
    zret = _r.parse(val, len);
  }
  return zret;
}

bool
CacheRange::apply(uint64_t len)
{
  bool zret = _r.apply(len);
  if (zret) {
    _len = len;
    if (_r.hasRanges()) {
      _offset = _r[_idx = 0]._min;
      if (_r.isMulti()) _pending_range_shift_p = true;
    }
  }
  return zret;
}

uint64_t
CacheRange::consume(uint64_t size)
{
  switch (_r._state) {
  case HTTPRangeSpec::EMPTY: _offset += size; break;
  case HTTPRangeSpec::SINGLE: _offset += std::min(size, (_r._single._max - _offset) + 1 ); break;
  case HTTPRangeSpec::MULTI:
    ink_assert(_idx < static_cast<int>(_r.count()));
    // Must not consume more than 1 range or the boundary strings won't get sent.
    ink_assert(!_pending_range_shift_p);
    ink_assert(size <= (_r[_idx]._max - _offset) + 1);
    _offset += size;
    if (_offset > _r[_idx]._max && ++_idx < static_cast<int>(_r.count())) {
      _offset = _r[_idx]._min;
      _pending_range_shift_p = true;
    }
    break;
  default: break;
  }

  return _offset;
}

CacheRange&
CacheRange::generateBoundaryStr(CacheKey const& key)
{
  uint64_t rnd = this_ethread()->generator.random();
  snprintf(_boundary, sizeof(_boundary), "%016" PRIx64 "%016" PRIx64 "..%016" PRIx64, key.slice64(0), key.slice64(1), rnd);
  // GAH! snprintf null terminates so we can't actually print the last nybble that way and all of
  // the internal hex converters do the same thing. This is crazy code I need to fix at some point.
  // It is critical to print every nybble or the content lengths won't add up.
  _boundary[HTTP_RANGE_BOUNDARY_LEN-1] = "0123456789abcdef"[rnd & 0xf];
  return *this;
}

uint64_t
CacheRange::calcContentLength() const
{
  return _r.calcContentLength(_len, _ct_field ? _ct_field->m_len_value : 0);
}

/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/

#else //HTTP_CACHE

CacheHTTPInfoVector::CacheHTTPInfoVector()
:data(&default_vec_info, 4), xcount(0)
{
}

/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/

CacheHTTPInfoVector::~CacheHTTPInfoVector()
{
}

/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/

int
CacheHTTPInfoVector::insert(CacheHTTPInfo */* info ATS_UNUSED */, int index)
{
  ink_assert(0);
  return index;
}

/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/


void
CacheHTTPInfoVector::detach(int /* idx ATS_UNUSED */, CacheHTTPInfo */* r ATS_UNUSED */)
{
  ink_assert(0);
}

/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/

void
CacheHTTPInfoVector::remove(int /* idx ATS_UNUSED */, bool /* destroy ATS_UNUSED */)
{
  ink_assert(0);
}

/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/

void
CacheHTTPInfoVector::clear(bool /* destroy ATS_UNUSED */)
{
}

/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/

void
CacheHTTPInfoVector::print(char */* buffer ATS_UNUSED */, size_t /* buf_size ATS_UNUSED */, bool /* temps ATS_UNUSED */)
{
  ink_assert(0);
}

/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/

int
CacheHTTPInfoVector::marshal_length()
{
  ink_assert(0);
  return 0;
}

/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/
int
CacheHTTPInfoVector::marshal(char */* buf ATS_UNUSED */, int length)
{
  ink_assert(0);
  return length;
}

int
CacheHTTPInfoVector::unmarshal(const char */* buf ATS_UNUSED */, int /* length ATS_UNUSED */, RefCountObj */* block_ptr ATS_UNUSED */)
{
  ink_assert(0);
  return 0;
}


/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/
uint32_t
CacheHTTPInfoVector::get_handles(const char */* buf ATS_UNUSED */, int /* length ATS_UNUSED */, RefCountObj */* block_ptr ATS_UNUSED */)
{
  ink_assert(0);
  return 0;
}
/*-------------------------------------------------------------------------
  -------------------------------------------------------------------------*/

#endif //HTTP_CACHE
