
/*
 * class.h - skeleton vpp engine plug-in header file 
 *
 * Copyright (c) <current-year> <your-organization>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __included_class_h__
#define __included_class_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <math.h>

//#include <vnet/classify/vnet_classify.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

struct _vnet_classify_main;
typedef struct _class_main class_main_t;

typedef struct {
    /* API message ID base */
    u16 msg_id_base;

    /* convenience */
    vlib_main_t * vlib_main;
    vnet_main_t * vnet_main;
    ethernet_main_t * ethernet_main;
} class_main2_t;

extern vlib_node_registration_t ip4_classify_node;
extern vlib_node_registration_t ip6_classify_node;
//extern vlib_node_registration_t ip4_pop_hop_by_hop_node;
//extern vlib_node_registration_t ip4_add_hop_by_hop_node;
//extern vlib_node_registration_t ip4_hop_by_hop_node;
extern vlib_node_registration_t ip4_lookup_node;


#define CLASS_TRACE 0

#if !defined( __aarch64__) && !defined(__arm__)
#define CLASS_USE_SSE //Allow usage of SSE operations
#endif

#define U32X4_ALIGNED(p) PREDICT_TRUE((((intptr_t)p) & 0xf) == 0)

#define foreach_size_in_u32x4                   \
_(1)                                            \
_(2)                                            \
_(3)                                            \
_(4)                                            \
_(5)

typedef CLIB_PACKED(struct _class_entry {
  u32 next_index;

  union {
    struct {
      u32 opaque_index;
      i32 advance;
    };
    u64 opaque_count;
    u32 next;
    struct {
        u8 src;
        u8 dst;
        u8 proto;
        u8 id;
    };
  };

  u32 flags;
#define CLASS_ENTRY_FREE	(1<<0)

  union {
    u64 hits;
    struct _class_entry * next_free;
  };

  f64 last_heard;

  u32x4 key[0];
}) class_entry_t;

static inline int class_entry_is_free (class_entry_t * e)
{
  return e->flags & CLASS_ENTRY_FREE;
}

static inline int class_entry_is_busy (class_entry_t * e)
{
  return ((e->flags & CLASS_ENTRY_FREE) == 0);
}

#define _(size)                                 \
typedef CLIB_PACKED(struct {                    \
  u32 pad0[4];                                  \
  u64 pad1[2];                                  \
  u32x4 key[size];                              \
}) class_entry_##size##_t;
foreach_size_in_u32x4;
#undef _

/*typedef struct {
  union {
    struct {
      u32 offset;
      u8 pad[3];
      u8 log2_pages;
    };
    u64 as_u64;
  };
} class_bucket_t;*/

typedef struct {
	u32 src;
	u32 dst;
	u32 proto;
	u32 total;
} class_check_input_t;

typedef struct {
	u32 index;
	u32 src;
	u32 dst;
	u32 proto;
	u32 action;
} class_next_t;

typedef struct {
	u32 srcid;
	u32 dstid;
	u32 proto;
} class_temp_t;

class_check_input_t class_check_input;
class_temp_t class_temp;
class_next_t class_next;

typedef struct {
  /* Mask to apply after skipping N vectors */
  u32x4 *mask;
  /* Buckets and entries */
  vnet_classify_bucket_t * buckets;
  class_entry_t * entries;

  /* Config parameters */
  u32 match_n_vectors;
  u32 skip_n_vectors;
  u32 nbuckets;
  u32 log2_nbuckets;
  int entries_per_page;
  u32 active_elements;
  /* Index of next table to try */
  u32 next_table_index;

  /* Miss next index, return if next_table_index = 0 */
  u32 miss_next_index;

  /* Per-bucket working copies, one per thread */
  class_entry_t ** working_copies;
  vnet_classify_bucket_t saved_bucket;

  /* Free entry freelists */
  class_entry_t **freelists;

  u8 * name;

  /* Private allocation arena, protected by the writer lock */
  void * mheap;
  u32 table_index;

  /* Writer (only) lock for this table */
  volatile u32 * writer_lock;

} class_table_t;

struct _class_main {
  /* Table pool */
  class_table_t * tables;
  class_next_t * next;

  /* Registered next-index, opaque unformat fcns */
  unformat_function_t ** unformat_l2_next_index_fns;
  unformat_function_t ** unformat_ip_next_index_fns;
  unformat_function_t ** unformat_acl_next_index_fns;
  unformat_function_t ** unformat_opaque_index_fns;

  /* convenience variables */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
};

class_main_t class_main;
class_main2_t class_main2;

vlib_node_registration_t class_node;

u64 class_hash_packet (class_table_t * t, u8 * h);

static inline u64
class_hash_packet_inline (class_table_t * t,
                                  u8 * h)
{
  u32x4 *mask;

  union {
    u32x4 as_u32x4;
    u64 as_u64[2];
  } xor_sum __attribute__((aligned(sizeof(u32x4))));

  ASSERT(t);
  mask = t->mask;
#ifdef CLASS_USE_SSE
  if (U32X4_ALIGNED(h)) {  //SSE can't handle unaligned data
    u32x4 *data = (u32x4 *)h;
    xor_sum.as_u32x4  = data[0 + t->skip_n_vectors] & mask[0];
    switch (t->match_n_vectors)
    {
      case 5:
        xor_sum.as_u32x4 ^= data[4 + t->skip_n_vectors] & mask[4];
        /* FALLTHROUGH */
      case 4:
        xor_sum.as_u32x4 ^= data[3 + t->skip_n_vectors] & mask[3];
        /* FALLTHROUGH */
      case 3:
        xor_sum.as_u32x4 ^= data[2 + t->skip_n_vectors] & mask[2];
        /* FALLTHROUGH */
      case 2:
        xor_sum.as_u32x4 ^= data[1 + t->skip_n_vectors] & mask[1];
        /* FALLTHROUGH */
      case 1:
        break;
      default:
        abort();
    }
  } else
#endif /* CLASSIFY_USE_SSE */
  {
    u32 skip_u64 = t->skip_n_vectors * 2;
    u64 *data64 = (u64 *)h;
    xor_sum.as_u64[0] = data64[0 + skip_u64] & ((u64 *)mask)[0];
    xor_sum.as_u64[1] = data64[1 + skip_u64] & ((u64 *)mask)[1];
    switch (t->match_n_vectors)
    {
      case 5:
        xor_sum.as_u64[0]  ^= data64[8 + skip_u64] & ((u64 *)mask)[8];
        xor_sum.as_u64[1]  ^= data64[9 + skip_u64] & ((u64 *)mask)[9];
        /* FALLTHROUGH */
      case 4:
        xor_sum.as_u64[0]  ^= data64[6 + skip_u64] & ((u64 *)mask)[6];
        xor_sum.as_u64[1]  ^= data64[7 + skip_u64] & ((u64 *)mask)[7];
        /* FALLTHROUGH */
      case 3:
        xor_sum.as_u64[0]  ^= data64[4 + skip_u64] & ((u64 *)mask)[4];
        xor_sum.as_u64[1]  ^= data64[5 + skip_u64] & ((u64 *)mask)[5];
        /* FALLTHROUGH */
      case 2:
        xor_sum.as_u64[0]  ^= data64[2 + skip_u64] & ((u64 *)mask)[2];
        xor_sum.as_u64[1]  ^= data64[3 + skip_u64] & ((u64 *)mask)[3];
        /* FALLTHROUGH */
      case 1:
        break;

      default:
        abort();
    }
  }

  return clib_xxhash (xor_sum.as_u64[0] ^ xor_sum.as_u64[1]);
}

static inline void
class_prefetch_bucket (class_table_t * t, u64 hash)
{
  u32 bucket_index;

  ASSERT (is_pow2(t->nbuckets));

  bucket_index = hash & (t->nbuckets - 1);

  CLIB_PREFETCH(&t->buckets[bucket_index], CLIB_CACHE_LINE_BYTES, LOAD);
}

static inline class_entry_t *
class_get_entry (class_table_t * t, uword offset)
{
  u8 * hp = t->mheap;
  u8 * vp = hp + offset;

  return (void *) vp;
}

static inline uword class_get_offset (class_table_t * t,
                                              class_entry_t * v)
{
  u8 * hp, * vp;

  hp = (u8 *) t->mheap;
  vp = (u8 *) v;

  ASSERT((vp - hp) < 0x100000000ULL);
  return vp - hp;
}

static inline class_entry_t *
class_entry_at_index (class_table_t * t,
                              class_entry_t * e,
                              u32 index)
{
  u8 * eu8;

  eu8 = (u8 *)e;

  eu8 += index * (sizeof (class_entry_t) +
                  (t->match_n_vectors * sizeof (u32x4)));

  return (class_entry_t *) eu8;
}

static inline void
class_prefetch_entry (class_table_t * t,
                              u64 hash)
{
  u32 bucket_index;
  u32 value_index;
  vnet_classify_bucket_t * b;
  class_entry_t * e;

  bucket_index = hash & (t->nbuckets - 1);

  b = &t->buckets[bucket_index];

  if (b->offset == 0)
    return;

  hash >>= t->log2_nbuckets;

  e = class_get_entry (t, b->offset);
  value_index = hash & ((1<<b->log2_pages)-1);

  e = class_entry_at_index (t, e, value_index);

  CLIB_PREFETCH(e, CLIB_CACHE_LINE_BYTES, LOAD);
}

class_entry_t *
class_find_entry (class_table_t * t,
                          u8 * h, u64 hash, f64 now);

static inline class_entry_t *
class_find_entry_inline (class_table_t * t,
                                 u8 * h, u64 hash, f64 now)
  {
  class_entry_t * v;
  u32x4 *mask, *key;
  union {
    u32x4 as_u32x4;
    u64 as_u64[2];
  } result __attribute__((aligned(sizeof(u32x4))));
  vnet_classify_bucket_t * b;
  u32 value_index;
  u32 bucket_index;
  int i;

  bucket_index = hash & (t->nbuckets-1);
  b = &t->buckets[bucket_index];
  mask = t->mask;

  if (b->offset == 0)
    return 0;

  hash >>= t->log2_nbuckets;

  v = class_get_entry (t, b->offset);
  value_index = hash & ((1<<b->log2_pages)-1);
  v = class_entry_at_index (t, v, value_index);

#ifdef CLASS_USE_SSE
  if (U32X4_ALIGNED(h)) {
    u32x4 *data = (u32x4 *) h;
    for (i = 0; i < t->entries_per_page; i++) {
      key = v->key;
      result.as_u32x4 = (data[0 + t->skip_n_vectors] & mask[0]) ^ key[0];
      switch (t->match_n_vectors)
      {
        case 5:
          result.as_u32x4 |= (data[4 + t->skip_n_vectors] & mask[4]) ^ key[4];
          /* FALLTHROUGH */
        case 4:
          result.as_u32x4 |= (data[3 + t->skip_n_vectors] & mask[3]) ^ key[3];
          /* FALLTHROUGH */
        case 3:
          result.as_u32x4 |= (data[2 + t->skip_n_vectors] & mask[2]) ^ key[2];
          /* FALLTHROUGH */
        case 2:
          result.as_u32x4 |= (data[1 + t->skip_n_vectors] & mask[1]) ^ key[1];
          /* FALLTHROUGH */
        case 1:
          break;
        default:
          abort();
      }

      if (u32x4_zero_byte_mask (result.as_u32x4) == 0xffff) {
        if (PREDICT_TRUE(now)) {
          v->hits++;
          v->last_heard = now;
        }
        return (v);
      }
      v = class_entry_at_index (t, v, 1);

    }
  } else
#endif /* CLASSIFY_USE_SSE */
  {
    u32 skip_u64 = t->skip_n_vectors * 2;
    u64 *data64 = (u64 *)h;
    for (i = 0; i < t->entries_per_page; i++) {
      key = v->key;

      result.as_u64[0] = (data64[0 + skip_u64] & ((u64 *)mask)[0]) ^ ((u64 *)key)[0];
      result.as_u64[1] = (data64[1 + skip_u64] & ((u64 *)mask)[1]) ^ ((u64 *)key)[1];
      switch (t->match_n_vectors)
      {
        case 5:
          result.as_u64[0] |= (data64[8 + skip_u64] & ((u64 *)mask)[8]) ^ ((u64 *)key)[8];
          result.as_u64[1] |= (data64[9 + skip_u64] & ((u64 *)mask)[9]) ^ ((u64 *)key)[9];
          /* FALLTHROUGH */
        case 4:
          result.as_u64[0] |= (data64[6 + skip_u64] & ((u64 *)mask)[6]) ^ ((u64 *)key)[6];
          result.as_u64[1] |= (data64[7 + skip_u64] & ((u64 *)mask)[7]) ^ ((u64 *)key)[7];
          /* FALLTHROUGH */
        case 3:
          result.as_u64[0] |= (data64[4 + skip_u64] & ((u64 *)mask)[4]) ^ ((u64 *)key)[4];
          result.as_u64[1] |= (data64[5 + skip_u64] & ((u64 *)mask)[5]) ^ ((u64 *)key)[5];
          /* FALLTHROUGH */
        case 2:
          result.as_u64[0] |= (data64[2 + skip_u64] & ((u64 *)mask)[2]) ^ ((u64 *)key)[2];
          result.as_u64[1] |= (data64[3 + skip_u64] & ((u64 *)mask)[3]) ^ ((u64 *)key)[3];
          /* FALLTHROUGH */
        case 1:
          break;
        default:
          abort();
      }

      if (result.as_u64[0] == 0 && result.as_u64[1] == 0) {
        if (PREDICT_TRUE(now)) {
          v->hits++;
          v->last_heard = now;
        }
        return (v);
      }
      v = class_entry_at_index (t, v, 1);
    }
  }
  return 0;
  }

class_table_t *
class_new_table (class_main_t *cm,
                         u8 * mask, u32 nbuckets, u32 memory_size,
                         u32 skip_n_vectors,
                         u32 match_n_vectors);

int class_add_del_session (class_main_t * cm,
                                   u32 table_index,
                                   u8 * match,
                                   u32 hit_next_index,
                                   u32 opaque_index,
                                   i32 advance,
                                   int is_add);

int class_add_del_table (class_main_t * cm,
                                 u8 * mask,
                                 u32 nbuckets,
                                 u32 memory_size,
                                 u32 skip,
                                 u32 match,
                                 u32 next_table_index,
                                 u32 miss_next_index,
                                 u32 * table_index,
                                 int is_add);

unformat_function_t unformat_ip4_mask;
unformat_function_t unformat_ip6_mask;
unformat_function_t unformat_l3_mask;
unformat_function_t unformat_l2_mask;
unformat_function_t unformat_class2_mask;
unformat_function_t unformat_l2_next_index;
unformat_function_t unformat_ip_next_index;
unformat_function_t unformat_ip4_match;
unformat_function_t unformat_ip6_match;
unformat_function_t unformat_l3_match;
unformat_function_t unformat_vlan_tag;
unformat_function_t unformat_l2_match;
unformat_function_t unformat_class2_match;
void clear_temp (class_temp_t * temp);


#endif /* __included_class_h__ */
