class_complete_t *
class_new_complete (class_main_t *cm)
{
	class_complete_t * c;

  pool_get_aligned (cm->comp, c, CLIB_CACHE_LINE_BYTES);
  memset(c, 0, sizeof (*c));

  return (c);
}


void class_delete_complete_index (class_main_t *cm,
                                       u32 index)
{
  class_complete_t * c;
  if (pool_is_free_index (cm->comp, index))
    return;

  c = pool_elt_at_index (cm->comp, index);

  pool_put (cm->comp, c);
}

int class_add_complete (class_main_t * cm,
                                 u32 src,
                                 u32 dst,
								 u32 proto,
                                 u32 * index,
                                 int is_add)
{
  class_complete_t * c;

  if (is_add)
    {
      *index = ~0;
      c = class_new_action (cm);
      c->src=src;
      c->dst=dst;
      c->proto=proto;
      *index = c - cm->comp;

      return 0;
    }


  class_delete_complete_index (cm, *index);
  return 0;
}
