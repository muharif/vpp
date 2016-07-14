#include <vnet/classify/input_acl.h>
#include <vnet/ip/ip.h>
#include <vnet/api_errno.h>     /* for API error numbers */
#include <vnet/l2/l2_classify.h> /* for L2_CLASSIFY_NEXT_xxx */
#include <vnet/plugin/plugin.h>
#include <class/class.h>

clib_error_t *
vlib_plugin_register (vlib_main_t * vm, vnet_plugin_handoff_t * h,
                      int from_early_init)
{
  class_main2_t * sm = &class_main2;
  clib_error_t * error = 0;

  sm->vlib_main = vm;
  sm->vnet_main = h->vnet_main;
  sm->ethernet_main = h->ethernet_main;

  return error;
}

class_main_t class_main;

#if VALIDATION_SCAFFOLDING
/* Validation scaffolding */
void mv (class_table_t * t)
{
  void * oldheap;

  oldheap = clib_mem_set_heap (t->mheap);
  clib_mem_validate();
  clib_mem_set_heap (oldheap);
}

void rogue (class_table_t * t)
{
  int i, j, k;
  class_entry_t * v, * save_v;
  u32 active_elements = 0;
  class_bucket_t * b;

  for (i = 0; i < t->nbuckets; i++)
    {
      b = &t->buckets [i];
      if (b->offset == 0)
        continue;
      save_v = class_get_entry (t, b->offset);
      for (j = 0; j < (1<<b->log2_pages); j++)
        {
          for (k = 0; k < t->entries_per_page; k++)
            {
              v = class_entry_at_index
                (t, save_v, j*t->entries_per_page + k);

              if (class_entry_is_busy (v))
                active_elements++;
            }
        }
    }

  if (active_elements != t->active_elements)
    clib_warning ("found %u expected %u elts", active_elements,
                  t->active_elements);
}
#else
void mv (class_table_t * t) { }
void rogue (class_table_t * t) { }
#endif

class_table_t *
class_new_table (class_main_t *cm,
                         u8 * mask, u32 nbuckets, u32 memory_size,
                         u32 skip_n_vectors,
                         u32 match_n_vectors)
{
	class_table_t * t;
  void * oldheap;

  nbuckets = 1 << (max_log2 (nbuckets));

  pool_get_aligned (cm->tables, t, CLIB_CACHE_LINE_BYTES);
  memset(t, 0, sizeof (*t));

  vec_validate_aligned (t->mask, match_n_vectors - 1, sizeof(u32x4));
  clib_memcpy (t->mask, mask, match_n_vectors * sizeof (u32x4));

  t->next_table_index = ~0;
  t->nbuckets = nbuckets;
  t->log2_nbuckets = max_log2 (nbuckets);
  t->match_n_vectors = match_n_vectors;
  t->skip_n_vectors = skip_n_vectors;
  t->entries_per_page = 2;

  t->mheap = mheap_alloc (0 /* use VM */, memory_size);

  vec_validate_aligned (t->buckets, nbuckets - 1, CLIB_CACHE_LINE_BYTES);
  oldheap = clib_mem_set_heap (t->mheap);

  t->writer_lock = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
                                           CLIB_CACHE_LINE_BYTES);
  t->writer_lock[0] = 0;

  clib_mem_set_heap (oldheap);
  return (t);
}

void class_delete_table_index (class_main_t *cm,
                                       u32 table_index)
{
  class_table_t * t;
  if (pool_is_free_index (cm->tables, table_index))
    return;

  t = pool_elt_at_index (cm->tables, table_index);
  if (t->next_table_index != ~0)
	  class_delete_table_index (cm, t->next_table_index);

  vec_free (t->mask);
  vec_free (t->buckets);
  mheap_free (t->mheap);

  pool_put (cm->tables, t);
}
class_entry_t *
class_entry_alloc (class_table_t * t, u32 log2_pages)
{
  class_entry_t * rv = 0;
#define _(size)                                 \
  class_entry_##size##_t * rv##size = 0;
  foreach_size_in_u32x4;
#undef _

  void * oldheap;

  ASSERT (t->writer_lock[0]);
  if (log2_pages >= vec_len (t->freelists) || t->freelists [log2_pages] == 0)
    {
      oldheap = clib_mem_set_heap (t->mheap);

      vec_validate (t->freelists, log2_pages);

      switch(t->match_n_vectors)
        {
          /* Euchre the vector allocator into allocating the right sizes */
#define _(size)                                                         \
        case size:                                                      \
          vec_validate_aligned                                          \
            (rv##size, ((1<<log2_pages)*t->entries_per_page) - 1,       \
          CLIB_CACHE_LINE_BYTES);                                       \
          rv = (class_entry_t *) rv##size;                      \
          break;
          foreach_size_in_u32x4;
#undef _

        default:
          abort();
        }

      clib_mem_set_heap (oldheap);
      goto initialize;
    }
  rv = t->freelists[log2_pages];
  t->freelists[log2_pages] = rv->next_free;

initialize:
  ASSERT(rv);
  ASSERT (vec_len(rv) == (1<<log2_pages)*t->entries_per_page);

  switch (t->match_n_vectors)
    {
#define _(size)                                                         \
    case size:                                                          \
      if(vec_len(rv)) 							\
        memset (rv, 0xff, sizeof (*rv##size) * vec_len(rv));            \
      break;
      foreach_size_in_u32x4;
#undef _

    default:
      abort();
    }

  return rv;
}

static void
class_entry_free (class_table_t * t,
                          class_entry_t * v)
{
    u32 free_list_index;

    ASSERT (t->writer_lock[0]);

    free_list_index = min_log2(vec_len(v)/t->entries_per_page);

    ASSERT(vec_len (t->freelists) > free_list_index);

    v->next_free = t->freelists[free_list_index];
    t->freelists[free_list_index] = v;
}

static inline void make_working_copy
(class_table_t * t, vnet_classify_bucket_t * b)
{
  class_entry_t * v;
  vnet_classify_bucket_t working_bucket __attribute__((aligned (8)));
  void * oldheap;
  class_entry_t * working_copy;
#define _(size)                                 \
  class_entry_##size##_t * working_copy##size = 0;
  foreach_size_in_u32x4;
#undef _
  u32 cpu_number = os_get_cpu_number();

  if (cpu_number >= vec_len (t->working_copies))
    {
      oldheap = clib_mem_set_heap (t->mheap);
      vec_validate (t->working_copies, cpu_number);
      clib_mem_set_heap (oldheap);
    }

  /*
   * working_copies are per-cpu so that near-simultaneous
   * updates from multiple threads will not result in sporadic, spurious
   * lookup failures.
   */
  working_copy = t->working_copies[cpu_number];

  t->saved_bucket.as_u64 = b->as_u64;
  oldheap = clib_mem_set_heap (t->mheap);

  if ((1<<b->log2_pages)*t->entries_per_page > vec_len (working_copy))
    {
      switch(t->match_n_vectors)
        {
          /* Euchre the vector allocator into allocating the right sizes */
#define _(size)                                                         \
        case size:                                                      \
          working_copy##size = (void *) working_copy;                   \
          vec_validate_aligned                                          \
            (working_copy##size, 					\
             ((1<<b->log2_pages)*t->entries_per_page) - 1,              \
             CLIB_CACHE_LINE_BYTES);                                    \
          working_copy = (void *) working_copy##size;                   \
            break;
        foreach_size_in_u32x4;
#undef _

        default:
          abort();
        }
      t->working_copies[cpu_number] = working_copy;
    }

  _vec_len(working_copy) = (1<<b->log2_pages)*t->entries_per_page;
  clib_mem_set_heap (oldheap);

  v = class_get_entry (t, b->offset);

  switch(t->match_n_vectors)
    {
#define _(size)                                         \
    case size:                                          \
      clib_memcpy (working_copy, v,                          \
              sizeof (class_entry_##size##_t)   \
              * (1<<b->log2_pages)                      \
              * (t->entries_per_page));                 \
      break;
      foreach_size_in_u32x4 ;
#undef _

    default:
      abort();
    }

  working_bucket.as_u64 = b->as_u64;
  working_bucket.offset = class_get_offset (t, working_copy);
  CLIB_MEMORY_BARRIER();
  b->as_u64 = working_bucket.as_u64;
  t->working_copies[cpu_number] = working_copy;
}

static class_entry_t *
split_and_rehash (class_table_t * t,
                  class_entry_t * old_values,
                  u32 new_log2_pages)
{
  class_entry_t * new_values, * v, * new_v;
  int i, j, k;

  new_values = class_entry_alloc (t, new_log2_pages);

  for (i = 0; i < (vec_len (old_values)/t->entries_per_page); i++)
    {
      u64 new_hash;

      for (j = 0; j < t->entries_per_page; j++)
        {
          v = class_entry_at_index
            (t, old_values, i * t->entries_per_page + j);

          if (class_entry_is_busy (v))
            {
              /* Hack so we can use the packet hash routine */
              u8 * key_minus_skip;
              key_minus_skip = (u8 *) v->key;
              key_minus_skip -= t->skip_n_vectors * sizeof (u32x4);

              new_hash = class_hash_packet (t, key_minus_skip);
              new_hash >>= t->log2_nbuckets;
              new_hash &= (1<<new_log2_pages) - 1;

              for (k = 0; k < t->entries_per_page; k++)
                {
                  new_v = class_entry_at_index (t, new_values,
                                                        new_hash + k);

                  if (class_entry_is_free (new_v))
                    {
                      clib_memcpy (new_v, v, sizeof (class_entry_t)
                              + (t->match_n_vectors * sizeof (u32x4)));
                      new_v->flags &= ~(CLASS_ENTRY_FREE);
                      goto doublebreak;
                    }
                }
              /* Crap. Tell caller to try again */
              class_entry_free (t, new_values);
              return 0;
            }
        doublebreak:
          ;
        }
    }
  return new_values;
}

int class_add_del (class_table_t * t,
                           class_entry_t * add_v,
                           int is_add, u32 table_index)
{
  u32 bucket_index;
  vnet_classify_bucket_t * b, tmp_b;
  class_entry_t * v, * new_v, * save_new_v, * working_copy, * save_v;
  u32 value_index;
  int rv = 0;
  int i;
  u64 hash, new_hash;
  u32 new_log2_pages;
  u32 cpu_number = os_get_cpu_number();
  u8 * key_minus_skip;


  ASSERT ((add_v->flags & CLASS_ENTRY_FREE) == 0);

  key_minus_skip = (u8 *) add_v->key;
  key_minus_skip -= t->skip_n_vectors * sizeof (u32x4);

  hash = class_hash_packet (t, key_minus_skip);

  bucket_index = hash & (t->nbuckets-1);
  b = &t->buckets[bucket_index];

  hash >>= t->log2_nbuckets;

  while (__sync_lock_test_and_set (t->writer_lock, 1))
    ;

  /* First elt in the bucket? */
  if (b->offset == 0)
    {
      if (is_add == 0)
        {
          rv = -1;
          goto unlock;
        }

      v = class_entry_alloc (t, 0 /* new_log2_pages */);
      clib_memcpy (v, add_v, sizeof (class_entry_t) +
              t->match_n_vectors * sizeof (u32x4));
      v->flags &= ~(CLASS_ENTRY_FREE);

      tmp_b.as_u64 = 0;
      tmp_b.offset = class_get_offset (t, v);

      b->as_u64 = tmp_b.as_u64;
      t->active_elements ++;

      goto unlock;
    }

  make_working_copy (t, b);

  save_v = class_get_entry (t, t->saved_bucket.offset);
  value_index = hash & ((1<<t->saved_bucket.log2_pages)-1);

  if (is_add)
    {
      /*
       * For obvious (in hindsight) reasons, see if we're supposed to
       * replace an existing key, then look for an empty slot.
       */

      for (i = 0; i < t->entries_per_page; i++)
        {
          v = class_entry_at_index (t, save_v, value_index + i);

          if (!memcmp (v->key, add_v->key, t->match_n_vectors * sizeof (u32x4)))
            {
              clib_memcpy (v, add_v, sizeof (class_entry_t) +
                      t->match_n_vectors * sizeof(u32x4));
              v->flags &= ~(CLASS_ENTRY_FREE);

              CLIB_MEMORY_BARRIER();
              /* Restore the previous (k,v) pairs */
              b->as_u64 = t->saved_bucket.as_u64;
              goto unlock;
            }
        }
      for (i = 0; i < t->entries_per_page; i++)
        {
          v = class_entry_at_index (t, save_v, value_index + i);

          if (class_entry_is_free (v))
            {
              clib_memcpy (v, add_v, sizeof (class_entry_t) +
                      t->match_n_vectors * sizeof(u32x4));
              v->flags &= ~(CLASS_ENTRY_FREE);
              CLIB_MEMORY_BARRIER();
              b->as_u64 = t->saved_bucket.as_u64;
              t->active_elements ++;
              goto unlock;
            }
        }
      /* no room at the inn... split case... */
    }
  else
    {
      for (i = 0; i < t->entries_per_page; i++)
        {
          v = class_entry_at_index (t, save_v, value_index + i);

          if (!memcmp (v->key, add_v->key, t->match_n_vectors * sizeof (u32x4)))
            {
              memset (v, 0xff, sizeof (class_entry_t) +
                      t->match_n_vectors * sizeof(u32x4));
              v->flags |= CLASS_ENTRY_FREE;
              CLIB_MEMORY_BARRIER();
              b->as_u64 = t->saved_bucket.as_u64;
              t->active_elements --;
              goto unlock;
            }
        }
      rv = -3;
      b->as_u64 = t->saved_bucket.as_u64;
      goto unlock;
    }

  new_log2_pages = t->saved_bucket.log2_pages + 1;

 expand_again:
  working_copy = t->working_copies[cpu_number];
  new_v = split_and_rehash (t, working_copy, new_log2_pages);

  if (new_v == 0)
    {
      new_log2_pages++;
      goto expand_again;
    }

  /* Try to add the new entry */
  save_new_v = new_v;

  key_minus_skip = (u8 *) add_v->key;
  key_minus_skip -= t->skip_n_vectors * sizeof (u32x4);

  new_hash = class_hash_packet_inline (t, key_minus_skip);
  new_hash >>= t->log2_nbuckets;
  new_hash &= (1<<min_log2((vec_len(new_v)/t->entries_per_page))) - 1;

  for (i = 0; i < t->entries_per_page; i++)
    {
      new_v = class_entry_at_index (t, save_new_v, new_hash + i);

      if (class_entry_is_free (new_v))
        {
          clib_memcpy (new_v, add_v, sizeof (class_entry_t) +
                  t->match_n_vectors * sizeof(u32x4));
          new_v->flags &= ~(CLASS_ENTRY_FREE);
          goto expand_ok;
        }
    }
  /* Crap. Try again */
  new_log2_pages++;
  class_entry_free (t, save_new_v);
  goto expand_again;

 expand_ok:
  tmp_b.log2_pages = min_log2 (vec_len (save_new_v)/t->entries_per_page);
  tmp_b.offset = class_get_offset (t, save_new_v);
  CLIB_MEMORY_BARRIER();
  b->as_u64 = tmp_b.as_u64;
  t->active_elements ++;
  v = class_get_entry (t, t->saved_bucket.offset);
  class_entry_free (t, v);

 unlock:
  CLIB_MEMORY_BARRIER();
  t->writer_lock[0] = 0;

  return rv;
}

typedef CLIB_PACKED(struct {
  ethernet_header_t eh;
  ip4_header_t ip;
}) class_data_or_mask_t;

u64 class_hash_packet (class_table_t * t, u8 * h)
{
  return class_hash_packet_inline (t, h);
}

class_entry_t *
class_find_entry (class_table_t * t,
                          u8 * h, u64 hash, f64 now)
{
  return class_find_entry_inline (t, h, hash, now);
}

static u8 * format_class_entry (u8 * s, va_list * args)
  {
  class_table_t * t = va_arg (*args, class_table_t *);
  class_entry_t * e = va_arg (*args, class_entry_t *);

  s = format
    (s, "[%u]: next_index %d advance %d opaque %d\n",
     class_get_offset (t, e), e->next_index, e->advance,
     e->opaque_index);


  s = format (s, "        k: %U\n", format_hex_bytes, e->key,
              t->match_n_vectors * sizeof(u32x4));

  if (class_entry_is_busy (e))
    s = format (s, "        hits %lld, last_heard %.2f\n",
                e->hits, e->last_heard);
  else
    s = format (s, "  entry is free\n");
  return s;
  }

u8 * format_class_table (u8 * s, va_list * args)
{
  class_table_t * t = va_arg (*args, class_table_t *);
  int verbose = va_arg (*args, int);
  vnet_classify_bucket_t * b;
  class_entry_t * v, * save_v;
  int i, j, k;
  u64 active_elements = 0;

  for (i = 0; i < t->nbuckets; i++)
    {
      b = &t->buckets [i];
      if (b->offset == 0)
        {
          if (verbose > 1)
            s = format (s, "[%d]: empty\n", i);
          continue;
        }

      if (verbose)
        {
          s = format (s, "[%d]: heap offset %d, len %d\n", i,
                      b->offset, (1<<b->log2_pages));
        }

      save_v = class_get_entry (t, b->offset);
      for (j = 0; j < (1<<b->log2_pages); j++)
        {
          for (k = 0; k < t->entries_per_page; k++)
            {

              v = class_entry_at_index (t, save_v,
                                                j*t->entries_per_page + k);

              if (class_entry_is_free (v))
                {
                  if (verbose > 1)
                    s = format (s, "    %d: empty\n",
                                j * t->entries_per_page + k);
                  continue;
                }
              if (verbose)
                {
                  s = format (s, "    %d: %U\n",
                              j * t->entries_per_page + k,
                              format_class_entry, t, v);
                }
              active_elements++;
            }
        }
    }

  s = format (s, "    %lld active elements\n", active_elements);
  s = format (s, "    %d free lists\n", vec_len (t->freelists));
  return s;
}

int class_add_del_table (class_main_t * cm,
                                 u8 * mask,
                                 u32 nbuckets,
                                 u32 memory_size,
                                 u32 skip,
                                 u32 match,
                                 u32 next_table_index,
                                 u32 miss_next_index,
                                 u32 * table_index,
                                 int is_add)
{
  class_table_t * t;

  if (is_add)
    {
      *table_index = ~0;
      if (memory_size == 0)
        return VNET_API_ERROR_INVALID_MEMORY_SIZE;

      if (nbuckets == 0)
        return VNET_API_ERROR_INVALID_VALUE;

      t = class_new_table (cm, mask, nbuckets, memory_size,
        skip, match);
      t->next_table_index = next_table_index;
      t->miss_next_index = miss_next_index;
      *table_index = t - cm->tables;

      return 0;
    }


  class_delete_table_index (cm, *table_index);
  return 0;
}

#define foreach_ip4_proto_field                 \
_(src_address)                                  \
_(dst_address)                                  \
_(tos)                                          \
_(length)					\
_(fragment_id)                                  \
_(ttl)                                          \
_(protocol)                                     \
_(checksum)

uword unformat_ip4_mask (unformat_input_t * input, va_list * args)
{
  u8 ** maskp = va_arg (*args, u8 **);
  u8 * mask = 0;
  u8 found_something = 0;
  ip4_header_t * ip;

#define _(a) u8 a=0;
  foreach_ip4_proto_field;
#undef _
  u8 version = 0;
  u8 hdr_length = 0;


  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "version"))
        version = 1;
      else if (unformat (input, "hdr_length"))
        hdr_length = 1;
      else if (unformat (input, "src"))
        src_address = 1;
      else if (unformat (input, "dst"))
        dst_address = 1;
      else if (unformat (input, "proto"))
        protocol = 1;

#define _(a) else if (unformat (input, #a)) a=1;
      foreach_ip4_proto_field
#undef _
      else
        break;
    }

#define _(a) found_something += a;
  foreach_ip4_proto_field;
#undef _

  if (found_something == 0)
    return 0;

  vec_validate (mask, sizeof (*ip) - 1);

  ip = (ip4_header_t *) mask;

#define _(a) if (a) memset (&ip->a, 0xff, sizeof (ip->a));
  foreach_ip4_proto_field;
#undef _

  ip->ip_version_and_header_length = 0;

  if (version)
    ip->ip_version_and_header_length |= 0xF0;

  if (hdr_length)
    ip->ip_version_and_header_length |= 0x0F;

  *maskp = mask;
  return 1;
}

#define foreach_ip6_proto_field                 \
_(src_address)                                  \
_(dst_address)                                  \
_(payload_length)				\
_(hop_limit)                                    \
_(protocol)

uword unformat_ip6_mask (unformat_input_t * input, va_list * args)
{
  u8 ** maskp = va_arg (*args, u8 **);
  u8 * mask = 0;
  u8 found_something = 0;
  ip6_header_t * ip;
  u32 ip_version_traffic_class_and_flow_label;

#define _(a) u8 a=0;
  foreach_ip6_proto_field;
#undef _
  u8 version = 0;
  u8 traffic_class = 0;
  u8 flow_label = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "version"))
        version = 1;
      else if (unformat (input, "traffic-class"))
        traffic_class = 1;
      else if (unformat (input, "flow-label"))
        flow_label = 1;
      else if (unformat (input, "src"))
        src_address = 1;
      else if (unformat (input, "dst"))
        dst_address = 1;
      else if (unformat (input, "proto"))
        protocol = 1;

#define _(a) else if (unformat (input, #a)) a=1;
      foreach_ip6_proto_field
#undef _
      else
        break;
    }

#define _(a) found_something += a;
  foreach_ip6_proto_field;
#undef _

  if (found_something == 0)
    return 0;

  vec_validate (mask, sizeof (*ip) - 1);

  ip = (ip6_header_t *) mask;

#define _(a) if (a) memset (&ip->a, 0xff, sizeof (ip->a));
  foreach_ip6_proto_field;
#undef _

  ip_version_traffic_class_and_flow_label = 0;

  if (version)
    ip_version_traffic_class_and_flow_label |= 0xF0000000;

  if (traffic_class)
    ip_version_traffic_class_and_flow_label |= 0x0FF00000;

  if (flow_label)
    ip_version_traffic_class_and_flow_label |= 0x000FFFFF;

  ip->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (ip_version_traffic_class_and_flow_label);

  *maskp = mask;
  return 1;
}

uword unformat_l3_mask (unformat_input_t * input, va_list * args)
{
  u8 ** maskp = va_arg (*args, u8 **);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "ip4 %U", unformat_ip4_mask, maskp))
      return 1;
    else if (unformat (input, "ip6 %U", unformat_ip6_mask, maskp))
      return 1;
    else
      break;
  }
  return 0;
}

uword unformat_l2_mask (unformat_input_t * input, va_list * args)
{
  u8 ** maskp = va_arg (*args, u8 **);
  u8 * mask = 0;
  u8 src = 0;
  u8 dst = 0;
  u8 proto = 0;
  u8 tag1 = 0;
  u8 tag2 = 0;
  u8 ignore_tag1 = 0;
  u8 ignore_tag2 = 0;
  u8 cos1 = 0;
  u8 cos2 = 0;
  u8 dot1q = 0;
  u8 dot1ad = 0;
  int len = 14;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "src"))
      src = 1;
    else if (unformat (input, "dst"))
      dst = 1;
    else if (unformat (input, "proto"))
      proto = 1;
    else if (unformat (input, "tag1"))
      tag1 = 1;
    else if (unformat (input, "tag2"))
      tag2 = 1;
    else if (unformat (input, "ignore-tag1"))
      ignore_tag1 = 1;
    else if (unformat (input, "ignore-tag2"))
      ignore_tag2 = 1;
    else if (unformat (input, "cos1"))
      cos1 = 1;
    else if (unformat (input, "cos2"))
      cos2 = 1;
    else if (unformat (input, "dot1q"))
      dot1q = 1;
    else if (unformat (input, "dot1ad"))
      dot1ad = 1;
    else
      break;
  }
  if ((src + dst + proto + tag1 + tag2 + dot1q + dot1ad +
      ignore_tag1 + ignore_tag2 + cos1 + cos2) == 0)
    return 0;

  if (tag1 || ignore_tag1 || cos1 || dot1q)
    len = 18;
  if (tag2 || ignore_tag2 || cos2 || dot1ad)
    len = 22;

  vec_validate (mask, len-1);

  if (dst)
    memset (mask, 0xff, 6);

  if (src)
    memset (mask + 6, 0xff, 6);

  if (tag2 || dot1ad)
    {
      /* inner vlan tag */
      if (tag2)
        {
          mask[19] = 0xff;
          mask[18] = 0x0f;
        }
      if (cos2)
        mask[18] |= 0xe0;
      if (proto)
        mask[21] = mask [20] = 0xff;
      if (tag1)
        {
          mask [15] = 0xff;
          mask [14] = 0x0f;
        }
      if (cos1)
        mask[14] |= 0xe0;
      *maskp = mask;
      return 1;
    }
  if (tag1 | dot1q)
    {
      if (tag1)
        {
          mask [15] = 0xff;
          mask [14] = 0x0f;
        }
      if (cos1)
        mask[14] |= 0xe0;
      if (proto)
        mask[16] = mask [17] = 0xff;
      *maskp = mask;
      return 1;
    }
  if (cos2)
    mask[18] |= 0xe0;
  if (cos1)
    mask[14] |= 0xe0;
  if (proto)
    mask[12] = mask [13] = 0xff;

  *maskp = mask;
  return 1;
}

uword unformat_class2_mask (unformat_input_t * input, va_list * args)
{
  class_main_t * CLIB_UNUSED(cm)
    = va_arg (*args, class_main_t *);
  u8 ** maskp = va_arg (*args, u8 **);
  u32 * skipp = va_arg (*args, u32 *);
  u32 * matchp = va_arg (*args, u32 *);
  u32 match;
  u8 * mask = 0;
  u8 * l2 = 0;
  u8 * l3 = 0;
  int i;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "hex %U", unformat_hex_string, &mask))
      ;
    else if (unformat (input, "l2 %U", unformat_l2_mask, &l2))
      ;
    else if (unformat (input, "l3 %U", unformat_l3_mask, &l3))
      ;
    else
      break;
  }

  if (mask || l2 || l3)
    {
      if (l2 || l3)
        {
          /* "With a free Ethernet header in every package" */
          if (l2 == 0)
            vec_validate (l2, 13);
          mask = l2;
          vec_append (mask, l3);
          vec_free (l3);
        }

      /* Scan forward looking for the first significant mask octet */
      for (i = 0; i < vec_len (mask); i++)
        if (mask[i])
          break;

      /* compute (skip, match) params */
      *skipp = i / sizeof(u32x4);
      vec_delete (mask, *skipp * sizeof(u32x4), 0);

      /* Pad mask to an even multiple of the vector size */
      while (vec_len (mask) % sizeof (u32x4))
        vec_add1 (mask, 0);

      match = vec_len (mask) / sizeof (u32x4);

      for (i = match*sizeof(u32x4); i > 0; i-= sizeof(u32x4))
        {
          u64 *tmp = (u64 *)(mask + (i-sizeof(u32x4)));
          if (*tmp || *(tmp+1))
            break;
          match--;
        }
      if (match == 0)
        clib_warning ("BUG: match 0");

      _vec_len (mask) = match * sizeof(u32x4);

      *matchp = match;
      *maskp = mask;

      return 1;
    }

  return 0;
}

#define foreach_l2_next                         \
_(drop, DROP)                                   \
_(ethernet, ETHERNET_INPUT)                     \
_(ip4, IP4_INPUT)                               \
_(ip6, IP6_INPUT)				\
_(li, LI)

uword unformat_l2_next_index (unformat_input_t * input, va_list * args)
{
  class_main_t * cm = &class_main;
  u32 * miss_next_indexp = va_arg (*args, u32 *);
  u32 next_index = 0;
  u32 tmp;
  int i;

  /* First try registered unformat fns, allowing override... */
  for (i = 0; i < vec_len (cm->unformat_l2_next_index_fns); i++)
    {
      if (unformat (input, "%U", cm->unformat_l2_next_index_fns[i], &tmp))
        {
          next_index = tmp;
          goto out;
        }
    }

#define _(n,N) \
  if (unformat (input, #n)) { next_index = L2_CLASSIFY_NEXT_##N; goto out;}
  foreach_l2_next;
#undef _

  if (unformat (input, "%d", &tmp))
    {
      next_index = tmp;
      goto out;
    }

  return 0;

 out:
  *miss_next_indexp = next_index;
  return 1;
}

#define foreach_ip_next                         \
_(miss, MISS)                                   \
_(drop, DROP)                                   \
_(local, LOCAL)                                 \
_(rewrite, REWRITE)

uword unformat_ip_next_index (unformat_input_t * input, va_list * args)
{
  u32 * miss_next_indexp = va_arg (*args, u32 *);
  class_main_t * cm = &class_main;
  u32 next_index = 0;
  u32 tmp;
  int i;

  /* First try registered unformat fns, allowing override... */
  for (i = 0; i < vec_len (cm->unformat_ip_next_index_fns); i++)
    {
      if (unformat (input, "%U", cm->unformat_ip_next_index_fns[i], &tmp))
        {
          next_index = tmp;
          goto out;
        }
    }

#define _(n,N) \
  if (unformat (input, #n)) { next_index = IP_LOOKUP_NEXT_##N; goto out;}
  foreach_ip_next;
#undef _

  if (unformat (input, "%d", &tmp))
    {
      next_index = tmp;
      goto out;
    }

  return 0;

 out:
  *miss_next_indexp = next_index;
  return 1;
}

#define foreach_acl_next                        \
_(deny, DENY)

uword unformat_acl_next_index (unformat_input_t * input, va_list * args)
{
  u32 * next_indexp = va_arg (*args, u32 *);
  class_main_t * cm = &class_main;
  u32 next_index = 0;
  u32 tmp;
  int i;

  /* First try registered unformat fns, allowing override... */
  for (i = 0; i < vec_len (cm->unformat_acl_next_index_fns); i++)
    {
      if (unformat (input, "%U", cm->unformat_acl_next_index_fns[i], &tmp))
        {
          next_index = tmp;
          goto out;
        }
    }

#define _(n,N) \
  if (unformat (input, #n)) { next_index = ACL_NEXT_INDEX_##N; goto out;}
  foreach_acl_next;
#undef _

  if (unformat (input, "permit"))
    {
      next_index = ~0;
      goto out;
    }
  else if (unformat (input, "%d", &tmp))
    {
      next_index = tmp;
      goto out;
    }

  return 0;

 out:
  *next_indexp = next_index;
  return 1;
}

static clib_error_t *
class_table_command_fn (vlib_main_t * vm,
                           unformat_input_t * input,
                           vlib_cli_command_t * cmd)
{
  u32 nbuckets = 2;
  u32 skip = ~0;
  u32 match = ~0;
  int is_add = 1;
  u32 table_index = ~0;
  u32 next_table_index = ~0;
  u32 miss_next_index = ~0;
  u32 memory_size = 2<<20;
  u32 tmp;

  u8 * mask = 0;
  class_main_t * cm = &class_main;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "del"))
      is_add = 0;
    else if (unformat (input, "buckets %d", &nbuckets))
      ;
    else if (unformat (input, "skip %d", &skip))
      ;
    else if (unformat (input, "match %d", &match))
      ;
    else if (unformat (input, "table %d", &table_index))
      ;
    else if (unformat (input, "mask %U", unformat_class2_mask,
                       cm, &mask, &skip, &match))
      ;
    else if (unformat (input, "memory-size %uM", &tmp))
      memory_size = tmp<<20;
    else if (unformat (input, "memory-size %uG", &tmp))
      memory_size = tmp<<30;
    else if (unformat (input, "next-table %d", &next_table_index))
      ;
    else if (unformat (input, "miss-next %U", unformat_ip_next_index,
                       &miss_next_index))
      ;
    else if (unformat (input, "l2-miss-next %U", unformat_l2_next_index,
                       &miss_next_index))
      ;
    else if (unformat (input, "acl-miss-next %U", unformat_acl_next_index,
                       &miss_next_index))
      ;

    else
      break;
  }

  if (is_add && mask == 0)
    return clib_error_return (0, "Mask required");

  if (is_add && skip == ~0)
    return clib_error_return (0, "skip count required");

  if (is_add && match == ~0)
    return clib_error_return (0, "match count required");

  if (!is_add && table_index == ~0)
    return clib_error_return (0, "table index required for delete");

  rv = class_add_del_table (cm, mask, nbuckets, memory_size,
        skip, match, next_table_index, miss_next_index,
        &table_index, is_add);
  switch (rv)
    {
    case 0:
      break;

    default:
      return clib_error_return (0, "vnet_classify_add_del_table returned %d",
                                rv);
    }
  return 0;
}

VLIB_CLI_COMMAND (class_table, static) = {
  .path = "class-new table",
  .short_help =
  "classify table [miss-next|l2-miss_next|acl-miss-next <next_index>]"
  "\n mask <mask-value> buckets <nn> next-hop <nn> [skip <n>] [match <n>] [del]",
  .function = class_table_command_fn,
};

static u8 * format_vnet_class_table (u8 * s, va_list * args)
{
  class_main_t * cm = va_arg (*args, class_main_t *);
  int verbose = va_arg (*args, int);
  u32 index = va_arg (*args, u32);
  class_table_t * t;

  if (index == ~0)
    {
      s = format (s, "%10s%10s%10s%10s", "TableIdx", "Sessions", "NextTbl",
                  "NextNode", verbose ? "Details" : "");
      return s;
    }

  t = pool_elt_at_index (cm->tables, index);
  s = format (s, "%10u%10d%10d%10d", index, t->active_elements,
              t->next_table_index, t->miss_next_index);

  s = format (s, "\n  Heap: %U", format_mheap, t->mheap, 0 /*verbose*/);

  s = format (s, "\n  nbuckets %d, skip %d match %d",
              t->nbuckets, t->skip_n_vectors, t->match_n_vectors);
  s = format (s, "\n  mask %U", format_hex_bytes, t->mask,
              t->match_n_vectors * sizeof (u32x4));
  if (verbose == 0)
    return s;

  s = format (s, "\n%U", format_class_table, t, verbose);

  return s;
}

static clib_error_t *
show_class_tables_command_fn (vlib_main_t * vm,
                                 unformat_input_t * input,
                                 vlib_cli_command_t * cmd)
{
  class_main_t * cm = &class_main;
  class_table_t * t;
  u32 match_index = ~0;
  u32 * indices = 0;
  int verbose = 0;
  int i;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "index %d", &match_index))
        ;
      else if (unformat (input, "verbose %d", &verbose))
        ;
      else if (unformat (input, "verbose"))
        verbose = 1;
      else
        break;
    }

  pool_foreach (t, cm->tables,
  ({
    if (match_index == ~0 || (match_index == t - cm->tables))
      vec_add1 (indices, t - cm->tables);
  }));

  if (vec_len(indices))
    {
      vlib_cli_output (vm, "%U", format_vnet_class_table, cm, verbose,
                       ~0 /* hdr */);
      for (i = 0; i < vec_len (indices); i++)
        vlib_cli_output (vm, "%U", format_vnet_class_table, cm,
                         verbose, indices[i]);
    }
  else
    vlib_cli_output (vm, "No classifier tables configured");

  vec_free (indices);

  return 0;
}

VLIB_CLI_COMMAND (show_class_table_command, static) = {
  .path = "show class-new tables",
  .short_help = "show class-new tables [index <nn>]",
  .function = show_class_tables_command_fn,
};

void check_input ()
{
	int src = 0, dst = 0;

	check.src=src;
	check.dst=dst;
	check.proto=3;
}

uword unformat_ip4_match (unformat_input_t * input, va_list * args)
{
  u8 ** matchp = va_arg (*args, u8 **);
  u8 * match = 0;
  ip4_header_t * ip;
  int version = 0;
  u32 version_val;
  int hdr_length = 0;
  u32 hdr_length_val;
  int src = 0, dst = 0;
  ip4_address_t src_val, dst_val;
  int proto = 0;
  u32 proto_val;
  int tos = 0;
  u32 tos_val;
  int length = 0;
  u32 length_val;
  int fragment_id = 0;
  u32 fragment_id_val;
  int ttl = 0;
  int ttl_val;
  int checksum = 0;
  u32 checksum_val;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "version %d", &version_val))
        version = 1;
      else if (unformat (input, "hdr_length %d", &hdr_length_val))
        hdr_length = 1;
      else if (unformat (input, "src %U", unformat_ip4_address, &src_val))
        src = 1;
      else if (unformat (input, "dst %U", unformat_ip4_address, &dst_val))
        dst = 1;
      else if (unformat (input, "proto %d", &proto_val))
        proto = 1;
      else if (unformat (input, "tos %d", &tos_val))
        tos = 1;
      else if (unformat (input, "length %d", &length_val))
        length = 1;
      else if (unformat (input, "fragment_id %d", &fragment_id_val))
        fragment_id = 1;
      else if (unformat (input, "ttl %d", &ttl_val))
        ttl = 1;
      else if (unformat (input, "checksum %d", &checksum_val))
        checksum = 1;
      else
        break;
    }

  if (version + hdr_length + src + dst + proto + tos + length + fragment_id
      + ttl + checksum == 0)
    return 0;

  /*
   * Aligned because we use the real comparison functions
   */
  vec_validate_aligned (match, sizeof (*ip) - 1, sizeof(u32x4));

  ip = (ip4_header_t *) match;

  /* These are realistically matched in practice */
  if (src)
    ip->src_address.as_u32 = src_val.as_u32;

  if (dst)
    ip->dst_address.as_u32 = dst_val.as_u32;

  if (proto)
    ip->protocol = proto_val;


  /* These are not, but they're included for completeness */
  if (version)
    ip->ip_version_and_header_length |= (version_val & 0xF)<<4;

  if (hdr_length)
    ip->ip_version_and_header_length |= (hdr_length_val & 0xF);

  if (tos)
    ip->tos = tos_val;

  if (length)
    ip->length = length_val;

  if (ttl)
    ip->ttl = ttl_val;

  if (checksum)
    ip->checksum = checksum_val;

  *matchp = match;
  return 1;
}

uword unformat_ip6_match (unformat_input_t * input, va_list * args)
{
  u8 ** matchp = va_arg (*args, u8 **);
  u8 * match = 0;
  ip6_header_t * ip;
  int version = 0;
  u32 version_val;
  u8  traffic_class = 0;
  u32 traffic_class_val;
  u8  flow_label = 0;
  u8  flow_label_val;
  int src = 0, dst = 0;
  ip6_address_t src_val, dst_val;
  int proto = 0;
  u32 proto_val;
  int payload_length = 0;
  u32 payload_length_val;
  int hop_limit = 0;
  int hop_limit_val;
  u32 ip_version_traffic_class_and_flow_label;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "version %d", &version_val))
        version = 1;
      else if (unformat (input, "traffic_class %d", &traffic_class_val))
        traffic_class = 1;
      else if (unformat (input, "flow_label %d", &flow_label_val))
        flow_label = 1;
      else if (unformat (input, "src %U", unformat_ip6_address, &src_val))
        src = 1;
      else if (unformat (input, "dst %U", unformat_ip6_address, &dst_val))
        dst = 1;
      else if (unformat (input, "proto %d", &proto_val))
        proto = 1;
      else if (unformat (input, "payload_length %d", &payload_length_val))
        payload_length = 1;
      else if (unformat (input, "hop_limit %d", &hop_limit_val))
        hop_limit = 1;
      else
        break;
    }

  if (version + traffic_class + flow_label + src + dst + proto +
      payload_length + hop_limit == 0)
    return 0;

  /*
   * Aligned because we use the real comparison functions
   */
  vec_validate_aligned (match, sizeof (*ip) - 1, sizeof(u32x4));

  ip = (ip6_header_t *) match;

  if (src)
    clib_memcpy (&ip->src_address, &src_val, sizeof (ip->src_address));

  if (dst)
    clib_memcpy (&ip->dst_address, &dst_val, sizeof (ip->dst_address));

  if (proto)
    ip->protocol = proto_val;

  ip_version_traffic_class_and_flow_label = 0;

  if (version)
    ip_version_traffic_class_and_flow_label |= (version_val & 0xF) << 28;

  if (traffic_class)
    ip_version_traffic_class_and_flow_label |= (traffic_class_val & 0xFF) << 20;

  if (flow_label)
    ip_version_traffic_class_and_flow_label |= (flow_label_val & 0xFFFFF);

  ip->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (ip_version_traffic_class_and_flow_label);

  if (payload_length)
    ip->payload_length = clib_host_to_net_u16 (payload_length_val);

  if (hop_limit)
    ip->hop_limit = hop_limit_val;

  *matchp = match;
  return 1;
}

uword unformat_l3_match (unformat_input_t * input, va_list * args)
{
  u8 ** matchp = va_arg (*args, u8 **);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "ip4 %U", unformat_ip4_match, matchp))
      return 1;
    else if (unformat (input, "ip6 %U", unformat_ip6_match, matchp))
      return 1;
    /* $$$$ add mpls */
    else
      break;
  }

  return 0;
}

uword unformat_vlan_tag (unformat_input_t * input, va_list * args)
{
  u8 * tagp = va_arg (*args, u8 *);
  u32 tag;

  if (unformat(input, "%d", &tag))
    {
      tagp[0] = (tag>>8) & 0x0F;
      tagp[1] = tag & 0xFF;
      return 1;
    }

  return 0;
}

uword unformat_l2_match (unformat_input_t * input, va_list * args)
{
  u8 ** matchp = va_arg (*args, u8 **);
  u8 * match = 0;
  u8 src = 0;
  u8 src_val[6];
  u8 dst = 0;
  u8 dst_val[6];
  u8 proto = 0;
  u16 proto_val;
  u8 tag1 = 0;
  u8 tag1_val [2];
  u8 tag2 = 0;
  u8 tag2_val [2];
  int len = 14;
  u8 ignore_tag1 = 0;
  u8 ignore_tag2 = 0;
  u8 cos1 = 0;
  u8 cos2 = 0;
  u32 cos1_val = 0;
  u32 cos2_val = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "src %U", unformat_ethernet_address, &src_val))
      src = 1;
    else if (unformat (input, "dst %U", unformat_ethernet_address, &dst_val))
      dst = 1;
    else if (unformat (input, "proto %U",
                       unformat_ethernet_type_host_byte_order, &proto_val))
      proto = 1;
    else if (unformat (input, "tag1 %U", unformat_vlan_tag, tag1_val))
      tag1 = 1;
    else if (unformat (input, "tag2 %U", unformat_vlan_tag, tag2_val))
      tag2 = 1;
    else if (unformat (input, "ignore-tag1"))
      ignore_tag1 = 1;
    else if (unformat (input, "ignore-tag2"))
      ignore_tag2 = 1;
    else if (unformat (input, "cos1 %d", &cos1_val))
      cos1 = 1;
    else if (unformat (input, "cos2 %d", &cos2_val))
      cos2 = 1;
    else
      break;
  }
  if ((src + dst + proto + tag1 + tag2 +
      ignore_tag1 + ignore_tag2 + cos1 + cos2) == 0)
    return 0;

  if (tag1 || ignore_tag1 || cos1)
    len = 18;
  if (tag2 || ignore_tag2 || cos2)
    len = 22;

  vec_validate_aligned (match, len-1, sizeof(u32x4));

  if (dst)
    clib_memcpy (match, dst_val, 6);

  if (src)
    clib_memcpy (match + 6, src_val, 6);

  if (tag2)
    {
      /* inner vlan tag */
      match[19] = tag2_val[1];
      match[18] = tag2_val[0];
      if (cos2)
        match [18] |= (cos2_val & 0x7) << 5;
      if (proto)
        {
          match[21] = proto_val & 0xff;
          match[20] = proto_val >> 8;
        }
      if (tag1)
        {
          match [15] = tag1_val[1];
          match [14] = tag1_val[0];
        }
      if (cos1)
        match [14] |= (cos1_val & 0x7) << 5;
      *matchp = match;
      return 1;
    }
  if (tag1)
    {
      match [15] = tag1_val[1];
      match [14] = tag1_val[0];
      if (proto)
        {
          match[17] = proto_val & 0xff;
          match[16] = proto_val >> 8;
        }
      if (cos1)
        match [14] |= (cos1_val & 0x7) << 5;

      *matchp = match;
      return 1;
    }
  if (cos2)
    match [18] |= (cos2_val & 0x7) << 5;
  if (cos1)
    match [14] |= (cos1_val & 0x7) << 5;
  if (proto)
    {
      match[13] = proto_val & 0xff;
      match[12] = proto_val >> 8;
    }

  *matchp = match;
  return 1;
}

uword unformat_class2_match (unformat_input_t * input, va_list * args)
{
  class_main_t * cm = va_arg (*args, class_main_t *);
  u8 ** matchp = va_arg (*args, u8 **);
  u32 table_index = va_arg (*args, u32);
  class_table_t * t;

  u8 * match = 0;
  u8 * l2 = 0;
  u8 * l3 = 0;

  if (pool_is_free_index (cm->tables, table_index))
    return 0;

  t = pool_elt_at_index (cm->tables, table_index);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "hex %U", unformat_hex_string, &match))
    	;
    else if (unformat (input, "l2 %U", unformat_l2_match, &l2))
    	;
    else if (unformat (input, "l3 %U", unformat_l3_match, &l3))
    	;
    else
      break;
  }

  if (match || l2 || l3)
    {
      if (l2 || l3)
        {
          /* "Win a free Ethernet header in every packet" */
          if (l2 == 0)
            vec_validate_aligned (l2, 13, sizeof(u32x4));
          match = l2;
          vec_append_aligned (match, l3, sizeof(u32x4));
          vec_free (l3);
        }

      /* Make sure the vector is big enough even if key is all 0's */
      vec_validate_aligned
        (match, ((t->match_n_vectors + t->skip_n_vectors) * sizeof(u32x4)) - 1,
         sizeof(u32x4));

      /* Set size, include skipped vectors*/
      _vec_len (match) = (t->match_n_vectors+t->skip_n_vectors) * sizeof(u32x4);

      *matchp = match;

      return 1;
    }

  return 0;
}


int class_add_del_session (class_main_t * cm,
                                   u32 table_index,
                                   u8 * match,
                                   u32 hit_next_index,
                                   u32 opaque_index,
                                   i32 advance,
                                   int is_add)
{
  class_table_t * t;
  class_entry_5_t _max_e __attribute__((aligned (16)));
  class_entry_t * e;
  int i, rv;
  u32 field=9;

  if (pool_is_free_index (cm->tables, table_index))
    return VNET_API_ERROR_NO_SUCH_TABLE;

  t = pool_elt_at_index (cm->tables, table_index);

  e = (class_entry_t *)&_max_e;
  e->next_index = hit_next_index;
  e->opaque_index = opaque_index;
  e->advance = advance;
  e->hits = 0;

  if (hit_next_index==11){
	  if ((t->active_elements)>0){
		  e->hits= (((t->active_elements+1)+(((t->active_elements+1)-1)*(field-1))));
	  } else {
		  e->hits=(t->active_elements+1);
	  }
  }
  e->last_heard = 0;
  e->flags = 0;


  /* Copy key data, honoring skip_n_vectors */
  clib_memcpy (&e->key, match + t->skip_n_vectors * sizeof (u32x4),
          t->match_n_vectors * sizeof (u32x4));

  /* Clear don't-care bits; likely when dynamically creating sessions */
  for (i = 0; i < t->match_n_vectors; i++)
    e->key[i] &= t->mask[i];

  rv = class_add_del (t, e, is_add,table_index);
  if (rv)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  return 0;
}

static clib_error_t *
class_session_command_fn (vlib_main_t * vm,
                             unformat_input_t * input,
                             vlib_cli_command_t * cmd)
{
  class_main_t * cm = &class_main;
  int is_add = 1;
  u32 table_index = ~0;
  u32 hit_next_index = ~0;
  u64 opaque_index = ~0;
  u8 * match = 0;
  i32 advance = 0;
  int i, rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
        is_add = 0;
      else if (unformat (input, "hit-next %U", unformat_ip_next_index,
                         &hit_next_index))
        ;
      else if (unformat (input, "l2-hit-next %U", unformat_l2_next_index,
                         &hit_next_index))
        ;
      else if (unformat (input, "acl-hit-next %U", unformat_acl_next_index,
                         &hit_next_index))
        ;
      else if (unformat (input, "opaque-index %lld", &opaque_index))
        ;
      else if (unformat (input, "match %U", unformat_class2_match,
                         cm, &match, table_index))
        ;
      else if (unformat (input, "advance %d", &advance))
        ;
      else if (unformat (input, "table-index %d", &table_index))
        ;
      else
        {
          /* Try registered opaque-index unformat fns */
          for (i = 0; i < vec_len (cm->unformat_opaque_index_fns); i++)
            {
              if (unformat (input, "%U", cm->unformat_opaque_index_fns[i],
                            &opaque_index))
                goto found_opaque;
            }
          break;
        }
    found_opaque:
      ;
    }

  if (table_index == ~0)
    return clib_error_return (0, "Table index required");

  if (is_add && match == 0)
    return clib_error_return (0, "Match value required");

  rv = class_add_del_session (cm, table_index, match,
                                      hit_next_index,
                                      opaque_index, advance, is_add);

  switch(rv)
    {
    case 0:
      break;

    default:
      return clib_error_return (0, "vnet_classify_add_del_session returned %d",
                                rv);
    }
  return 0;
}

VLIB_CLI_COMMAND (class_session, static) = {
    .path = "class-new session",
    .short_help =
    "classify session [hit-next|l2-hit-next|acl-hit-next <next_index>]"
    "\n table-index <nn> match [hex] [l2] [l3 ip4] [opaque-index <index>]",
    .function = class_session_command_fn,
};

static clib_error_t *
class_gen_command_fn (vlib_main_t * vm,
                             unformat_input_t * input,
                             vlib_cli_command_t * cmd)
{
  class_main_t * cm = &class_main;
  int is_add = 1;
  u32 table_index = 0;
  u32 hit_next_index = 11;
  u64 opaque_index = ~0;
  u8 * match = 0;
  i32 advance=0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
      {
        if (unformat (input, "del"))
          is_add = 0;
        else if (unformat (input, "match %U", unformat_class2_match,
                           cm, &match, table_index))
          ;
      }

    if (table_index == ~0)
      return clib_error_return (0, "Table index required");

    if (is_add && match == 0)
      return clib_error_return (0, "Match value required");

  rv = class_add_del_session (cm, table_index, match,
                                      hit_next_index,
                                      opaque_index, advance, is_add);

  switch(rv)
    {
    case 0:
      break;

    default:
      return clib_error_return (0, "vnet_classify_add_del_session returned %d",
                                rv);
    }
  return 0;
}

VLIB_CLI_COMMAND (class_gen, static) = {
    .path = "class-new generate",
    .short_help =
    "classify session [hit-next|l2-hit-next|acl-hit-next <next_index>]"
    "\n table-index <nn> match [hex] [l2] [l3 ip4] [opaque-index <index>]",
    .function = class_gen_command_fn,
};

int class_add_del_class (class_main_t * cm,
                                   u8 * match,
                                   u32 hit_next_index,
                                   u32 opaque_index,
                                   i32 advance,
                                   int is_add,
								   u32 srcmask,
								   u32 dstmask,
								   u8 src,
								   u8 dst,
								   u8 proto)
{
  class_table_t * t;
  class_entry_5_t _max_e __attribute__((aligned (16)));
  class_entry_t * e;
  int i, rv;
  u32 table_index=0;
  u32 next_table_index=0;
  u64 hash0;
  f64 now = 0.00;
  u32 max=4;
  u32 field=3;
  u32 add=0;
  u32 add2=0;

  e = (class_entry_t *)&_max_e;
  t = pool_elt_at_index (cm->tables, table_index);

  clib_memcpy (&e->key, match + t->skip_n_vectors * sizeof (u32x4),
          t->match_n_vectors * sizeof (u32x4));

  for (i = 0; i < t->match_n_vectors; i++)
    e->key[i] &= t->mask[i];

  u8 * h0;
  h0 = (u8 *) e->key;
  h0 -= t->skip_n_vectors * sizeof (u32x4);

  hash0 = class_hash_packet (t, h0);

  e = class_find_entry (t, (u8 *) h0, hash0,
                                 now);

  if(e) {
	  table_index=e->hits;
  }else {
	    table_index=max;
  }
	for (add=0;add<=(field-1);add=add+1){

		u8 src1=src;
		u8 dst1=dst;
		u8 proto1=proto;
		//u32 mult=0;

		if (add==0) {
			if (src1 !=1)
				continue;

			if (srcmask<=32 && srcmask >24)
				add2=0;
			else if (srcmask<=24 && srcmask >16)
				add2=1;
			else if (srcmask<=16 && srcmask >8)
				add2=2;
			else if (srcmask<=8 && srcmask >0)
				add2=3;
			else
				continue;
		} else if (add==1) {
			if (dst1 !=1)
				continue;

			if (dstmask<=32 && dstmask >24)
				add2=4;
			else if (dstmask<=24 && dstmask >16)
				add2=5;
			else if (dstmask<=16 && dstmask >8)
				add2=6;
			else if (dstmask<=8 && dstmask >0)
				add2=7;
			else
				continue;
		} else {
			if (proto1 !=1)
				continue;

			add2=8;
		}

			next_table_index=(table_index+add2);

		  t = pool_elt_at_index (cm->tables, next_table_index);

		  e = (class_entry_t *)&_max_e;

		  e->next_index = hit_next_index;
		  e->opaque_index=opaque_index;
		  e->advance = advance;
		  e->src1=src1;
		  e->dst1=dst1;
		  e->proto1=proto1;
		  e->hits=0;
		  e->last_heard = 0;
		  e->flags = 0;

		  clib_memcpy (&e->key, match + t->skip_n_vectors * sizeof (u32x4),
				  t->match_n_vectors * sizeof (u32x4));

		  /*if (add==0) {
			  if (add2==0) {
				  u32 temp=e->key[0][3];
				  for (j=0;j<mult;j++) {
					  e->key[0][3] =temp+(256*j);
					  for (i = 0; i < t->match_n_vectors; i++) {
						e->key[i] &= t->mask[i];
					  };
					  rv = class_add_del (t, e, is_add,table_index);
					  if (rv)
						return VNET_API_ERROR_NO_SUCH_ENTRY;
				  }
			  } else if (add2==1) {
			  	  	u32 temp=e->key[0][3];
			  		for (j=0;j<(mult);j++) {
					  	  e->key[0][3]=temp+(1*j);
					  	  for (i = 0; i < t->match_n_vectors; i++) {
								e->key[i] &= t->mask[i];
					  	  };
					  	  rv = class_add_del (t, e, is_add,table_index);
					  	  if (rv)
							return VNET_API_ERROR_NO_SUCH_ENTRY;
			  	  	  }
			  } else if (add2==2) {

			  } else if (add2==3) {
				  u32 temp=e->key[0][2];
				  for (j=0;j<mult;j++) {
					  e->key[0][2] =temp+(65536*j);
					  for (i = 0; i < t->match_n_vectors; i++) {
						e->key[i] &= t->mask[i];
					  };
					  rv = class_add_del (t, e, is_add,table_index);
					  if (rv)
						return VNET_API_ERROR_NO_SUCH_ENTRY;

			  }
		  } else if (add==1) {
			  if (add2==4) {

			  } else if (add2==5) {

			  } else if (add2==6) {

			  } else if (add2==7) {

			  }
		  }*/

		  u32 j=0;
		  if (add==0) {
			  u32 temp=e->key[0][2];
		  	  for (j=0;j<10;j++) {
		  		  e->key[0][2] =temp+(16777216*j);
				  for (i = 0; i < t->match_n_vectors; i++) {
					e->key[i] &= t->mask[i];
				  };
				  rv = class_add_del (t, e, is_add,table_index);
				  if (rv)
					return VNET_API_ERROR_NO_SUCH_ENTRY;
			  }
		  }


		  /*e->key[0][3] =e->key[0][3]+512;
		  rv = class_add_del (t, e, is_add,table_index);
		  if (rv)
			return VNET_API_ERROR_NO_SUCH_ENTRY;*/
	}
	  return 0;

}

void check_input2 (unformat_input_t * input)
{
	int src = 0, dst = 0;
	ip4_address_t src_val, dst_val;
	  int proto;

	  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
	    {
	      if (unformat (input, "src %U", unformat_ip4_address, &src_val))
	        src = 1;
	      else if (unformat (input, "dst %U", unformat_ip4_address, &dst_val))
	        dst = 1;
	      else if (unformat (input, "proto"))
	        proto = 8;
	      else
	    	  break;
	    }

	check.src=src;
	check.dst=dst;
	check.proto=proto;
}

static clib_error_t *
class_class_command_fn (vlib_main_t * vm,
                             unformat_input_t * input,
                             vlib_cli_command_t * cmd)
{
  class_main_t * cm = &class_main;
  int is_add = 1;
  u32 hit_next_index = ~0;
  u64 opaque_index = 0;
  u8 * match = 0;
  i32 advance=0;
  int i, rv;
  u32 table_index=0;
  u32 srcmask=32, dstmask=32;
  u8 src=1, dst=1, proto=1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
        is_add = 0;
      else if (unformat (input, "hit-next %U", unformat_ip_next_index,
                         &hit_next_index))
        ;
      else if (unformat (input, "l2-hit-next %U", unformat_l2_next_index,
                         &hit_next_index))
        ;
      else if (unformat (input, "acl-hit-next %U", unformat_acl_next_index,
                         &hit_next_index))
        ;
      else if (unformat (input, "opaque-index %lld", &opaque_index))
        ;
      else if (unformat (input, "srcmask %d", &srcmask))
    	  ;
      else if (unformat (input, "dstmask %d", &dstmask))
        ;
      else if (unformat (input, "check %d %d %d", &src, &dst, &proto))
    	  ;
      else if (unformat (input, "match %U", unformat_class2_match,
                         cm, &match, table_index))
    	  ;
      else if (unformat (input, "advance %d", &advance))
        ;
      else
        {
          for (i = 0; i < vec_len (cm->unformat_opaque_index_fns); i++)
            {
              if (unformat (input, "%U", cm->unformat_opaque_index_fns[i],
                            &opaque_index))
                goto found_opaque;
            }
          break;
        }
    found_opaque:
      ;
    }

  if (match == 0)
    return clib_error_return (0, "Match value required");

  if (src == 0 && dst == 0 && proto == 0)
	  return clib_error_return (0, "Not checking any field, classification failed");

  rv = class_add_del_class (cm, match,
                                      hit_next_index,
                                      opaque_index, advance, is_add, srcmask, dstmask, src, dst, proto);

  switch(rv)
    {
    case 0:
      break;

    default:
      return clib_error_return (0, "vnet_classify_add_del_session returned %d",
                                rv);
    }
  return 0;
}

VLIB_CLI_COMMAND (class_class, static) = {
    .path = "class-new class",
    .short_help =
    "class-new class [hit-next|l2-hit-next|acl-hit-next <next_index>]"
    "\n [srcmask <mask>] [dstmask <mask>] [check <int> <int> <int>] match [hex] [l2] [l3 ip4] [opaque-index <index>]",
    .function = class_class_command_fn,
};

static uword
unformat_opaque_sw_if_index (unformat_input_t * input, va_list * args)
{
  u64 * opaquep = va_arg (*args, u64 *);
  u32 sw_if_index;

  if (unformat (input, "opaque-sw_if_index %U", unformat_vnet_sw_interface,
                vnet_get_main(), &sw_if_index))
    {
      *opaquep = sw_if_index;
      return 1;
    }
  return 0;
}

static uword
unformat_ip_next_node (unformat_input_t * input, va_list * args)
{
  class_main_t * cm = &class_main;
  u32 * next_indexp = va_arg (*args, u32 *);
  u32 node_index;
  u32 next_index, rv;

  if (unformat (input, "node %U", unformat_vlib_node,
                cm->vlib_main, &node_index))
    {
      rv = next_index = vlib_node_add_next
        (cm->vlib_main, class_node.index, node_index);
      next_index = vlib_node_add_next
        (cm->vlib_main, class_node.index, node_index);
      ASSERT(rv == next_index);

      *next_indexp = next_index;
      return 1;
    }
  return 0;
}

static uword
unformat_l2_next_node (unformat_input_t * input, va_list * args)
{
  class_main_t * cm = &class_main;
  u32 * next_indexp = va_arg (*args, u32 *);
  u32 node_index;
  u32 next_index;

  if (unformat (input, "node %U", unformat_vlib_node,
                cm->vlib_main, &node_index))
    {
      next_index = vlib_node_add_next
        (cm->vlib_main, l2_classify_node.index, node_index);

      *next_indexp = next_index;
      return 1;
    }
  return 0;
}

static uword
unformat_acl_next_node (unformat_input_t * input, va_list * args)
{
  class_main_t * cm = &class_main;
  u32 * next_indexp = va_arg (*args, u32 *);
  u32 node_index;
  u32 next_index, rv;

  if (unformat (input, "node %U", unformat_vlib_node,
                cm->vlib_main, &node_index))
    {
      rv = next_index = vlib_node_add_next
        (cm->vlib_main, ip4_inacl_node.index, node_index);
      next_index = vlib_node_add_next
        (cm->vlib_main, ip6_inacl_node.index, node_index);
      ASSERT(rv == next_index);

      *next_indexp = next_index;
      return 1;
    }
  return 0;
}

static clib_error_t *
vnet_class_init (vlib_main_t * vm)
{
  class_main_t * cm = &class_main;

  cm->vlib_main = vm;
  cm->vnet_main = vnet_get_main();

  vnet_classify_register_unformat_opaque_index_fn
    (unformat_opaque_sw_if_index);

  vnet_classify_register_unformat_ip_next_index_fn
    (unformat_ip_next_node);

  vnet_classify_register_unformat_l2_next_index_fn
    (unformat_l2_next_node);

  vnet_classify_register_unformat_acl_next_index_fn
    (unformat_acl_next_node);


  vlib_node_add_next (vm, ip4_classify_node.index, class_node.index);
  vlib_node_add_next (vm, ip6_classify_node.index, class_node.index);
  vlib_node_add_next (vm, ip4_lookup_node.index, class_node.index);


  return 0;
}

VLIB_INIT_FUNCTION (vnet_class_init);

#define TEST_CODE 1

#if TEST_CODE > 0
static clib_error_t *
test_class_command_fn (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
  u32 buckets = 2;
  u32 sessions = 10;
  int i, rv;
  class_table_t * t = 0;
  class_data_or_mask_t * mask;
  class_data_or_mask_t * data;
  u8 *mp = 0, *dp = 0;
  class_main_t * cm = &class_main;
  class_entry_t * e;
  int is_add = 1;
  u32 tmp;
  u32 table_index = ~0;
  ip4_address_t src;
  u32 deleted = 0;
  u32 memory_size = 64<<20;

  /* Default starting address 1.0.0.10 */
  src.as_u32 = clib_net_to_host_u32 (0x0100000A);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "sessions %d", &sessions))
      ;
    else if (unformat (input, "src %U", unformat_ip4_address, &src))
      ;
    else if (unformat (input, "buckets %d", &buckets))
      ;
    else if (unformat (input, "memory-size %uM", &tmp))
      memory_size = tmp<<20;
    else if (unformat (input, "memory-size %uG", &tmp))
      memory_size = tmp<<30;
    else if (unformat (input, "del"))
      is_add = 0;
    else if (unformat (input, "table %d", &table_index))
      ;
    else
      break;
    }

  vec_validate_aligned (mp, 3 * sizeof(u32x4), sizeof(u32x4));
  vec_validate_aligned (dp, 3 * sizeof(u32x4), sizeof(u32x4));

  mask = (class_data_or_mask_t *) mp;
  data = (class_data_or_mask_t *) dp;

  data->ip.src_address.as_u32 = src.as_u32;

  /* Mask on src address */
  memset (&mask->ip.src_address, 0xff, 4);

  buckets = 1<<max_log2(buckets);

  if (table_index != ~0)
    {
      if (pool_is_free_index (cm->tables, table_index))
        {
          vlib_cli_output (vm, "No such table %d", table_index);
          goto out;
        }
      t = pool_elt_at_index (cm->tables, table_index);
    }

  if (is_add)
    {
      if (t == 0)
        {
          t = class_new_table (cm, (u8 *)mask, buckets,
                                       memory_size,
                                       0 /* skip */,
                                       3 /* vectors to match */);
          t->miss_next_index = IP_LOOKUP_NEXT_LOCAL;
          vlib_cli_output (vm, "Create table %d", t - cm->tables);
        }

      vlib_cli_output (vm, "Add %d sessions to %d buckets...",
                       sessions, buckets);

      for (i = 0; i < sessions; i++)
        {
          rv = class_add_del_session (cm, t - cm->tables, (u8 *) data,
                                              IP_LOOKUP_NEXT_DROP,
                                              i+100 /* opaque_index */,
                                              0 /* advance */,
                                              1 /* is_add */);

          if (rv != 0)
            clib_warning ("add: returned %d", rv);

          tmp = clib_net_to_host_u32 (data->ip.src_address.as_u32) + 1;
          data->ip.src_address.as_u32 = clib_net_to_host_u32 (tmp);
        }
      goto out;
    }

  if (t == 0)
    {
      vlib_cli_output (vm, "Must specify table index to delete sessions");
      goto out;
    }

  vlib_cli_output (vm, "Try to delete %d sessions...", sessions);

  for (i = 0; i < sessions; i++)
    {
      u8 * key_minus_skip;
      u64 hash;

      hash = class_hash_packet (t, (u8 *) data);

      e = class_find_entry (t, (u8 *) data, hash, 0 /* time_now */);
      /* Previous delete, perhaps... */
      if (e == 0)
        continue;
      ASSERT (e->opaque_index == (i+100));

      key_minus_skip = (u8 *)e->key;
      key_minus_skip -= t->skip_n_vectors * sizeof (u32x4);

      rv = class_add_del_session (cm, t - cm->tables, key_minus_skip,
                                          IP_LOOKUP_NEXT_DROP,
                                          i+100 /* opaque_index */,
                                          0 /* advance */,
                                          0 /* is_add */);
      if (rv != 0)
        clib_warning ("del: returned %d", rv);

      tmp = clib_net_to_host_u32 (data->ip.src_address.as_u32) + 1;
      data->ip.src_address.as_u32 = clib_net_to_host_u32 (tmp);
      deleted++;
    }

  vlib_cli_output (vm, "Deleted %d sessions...", deleted);

 out:
  vec_free (mp);
  vec_free (dp);

  return 0;
}

VLIB_CLI_COMMAND (test_class_command, static) = {
    .path = "test class-new",
    .short_help =
    "test class-new [src <ip>] [sessions <nn>] [buckets <nn>] [table <nn>] [del]",
    .function = test_class_command_fn,
};
#endif /* TEST_CODE */
