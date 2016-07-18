int class_add_next (class_main_t * cm,
                                 u32 srcid,
                                 u32 dstid,
								 u32 protoid,
								 u32 action,
                                 u32 * index,
                                 int is_add)
{
  class_next_t * n;

  if (is_add)
    {
      *index = ~0;
      n = class_new_action (cm, srcid, dstid, protoid,
        action);
      n->src=srcid;
      n->dst=dstid;
      n->proto=protoid;
      n->action=action;
      *index = n - cm->next;

      return 0;
    }


  class_delete_action_index (cm, *index);
  return 0;
}

void class_delete_action_index (class_main_t *cm,
                                       u32 index)
{
  class_next_t * n;
  if (pool_is_free_index (cm->entry, index))
    return;

  t = pool_elt_at_index (cm->entry, index);

  vec_free (n->src);
  vec_free (n->dst);
  vec_free (n->proto);

  pool_put (cm->entry, n);
}


class_next_t *
class_new_action (class_main_t *cm)
{
	class_next_t * n;

  pool_get_aligned (cm->entry, n, CLIB_CACHE_LINE_BYTES);
  memset(n, 0, sizeof (*n));

  return (n);
}
