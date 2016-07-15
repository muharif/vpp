
/*
 * node.c - skeleton vpp engine plug-in dual-loop node skeleton
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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <class/class.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>	/* for ethernet_header_t */

typedef struct {
	u64 next_index;
  u32 table_index;
  u32 entry_index;
} class_trace_t;


/* packet trace format function */
static u8 * format_class_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  class_trace_t * t = va_arg (*args, class_trace_t *);
  
  s = format (s, "IP_CLASS: next_index %d, table %d, entry %d",
              t->next_index, t->table_index, t->entry_index);
  return s;
}

vlib_node_registration_t class_node;

#define foreach_class_error               \
_(MISS, "Class misses")                      \
_(HIT, "Class hits")                         \
_(CHAIN_HIT, "Class hits after chain walk")

typedef enum {
#define _(sym,str) IP_CLASSIFY_ERROR_##sym,
  foreach_class_error
#undef _
  CLASS_N_ERROR,
} class_error_t;

static char * class_error_strings[] = {
#define _(sym,string) string,
  foreach_class_error
#undef _
};

static uword
class_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame, int is_ip4)
{


	  u32 n_left_from, * from, * to_next;
	  ip_lookup_next_t next_index;
	  class_main_t * vcm = &class_main;
	  //ip_lookup_main_t * lm;
	  f64 now = vlib_time_now (vm);
	  u32 hits = 0;
	  u32 misses = 0;
	  u32 chain_hits = 0;
	  int field=9;
	  int x0;
	  int x;
	  u32 next_table;

	  /*if (is_ip4)
	    lm = &ip4_main.lookup_main;
	  else
	    lm = &ip6_main.lookup_main;*/

	  from = vlib_frame_vector_args (frame);
	  n_left_from = frame->n_vectors;

	  while (n_left_from > 0)
	    {
	      vlib_buffer_t * b0;
	      u32 bi0;
	      u8 * h0;
	      //u32 adj_index0;
	      //ip_adjacency_t * adj0;
	      u32 table_index0;
	      class_table_t * t0;

	      bi0 = from[0];
	      b0 = vlib_get_buffer (vm, bi0);
	      h0 = (void *)vlib_buffer_get_current(b0) -
	                ethernet_buffer_header_size(b0);

	      //adj_index0 = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
	      //adj0 = ip_get_adjacency (lm, adj_index0);
	      table_index0 = vnet_buffer(b0)->l2_classify.table_index;

	      t0 = pool_elt_at_index (vcm->tables, table_index0);
	      vnet_buffer(b0)->l2_classify.hash =
	        class_hash_packet (t0, (u8 *) h0);

	      vnet_buffer(b0)->l2_classify.table_index =table_index0;
	      class_prefetch_bucket (t0, vnet_buffer(b0)->l2_classify.hash);

	      from++;
	      n_left_from--;
	    }

	  next_index = node->cached_next_index;
	  from = vlib_frame_vector_args (frame);
	  n_left_from = frame->n_vectors;

	  while (n_left_from > 0)
	    {
	      u32 n_left_to_next;

	      vlib_get_next_frame (vm, node, next_index,
				   to_next, n_left_to_next);

	      while (n_left_from > 0 && n_left_to_next > 0)
		{
	          u32 bi0;
	          vlib_buffer_t * b0;
	          u32 next0 = IP_LOOKUP_NEXT_MISS;
	          u32 table_index0;
	          class_table_t * t0, * t1;
	          class_entry_t * e0;
	          u64 hash0;
	          u8 * h0;

	          /* Stride 3 seems to work best */
	          if (PREDICT_TRUE (n_left_from > 3))
	            {
	              vlib_buffer_t * p1 = vlib_get_buffer(vm, from[3]);
	              class_table_t * tp1;
	              u32 table_index1;
	              u64 phash1;

	              table_index1 = vnet_buffer(p1)->l2_classify.table_index;

	              if (PREDICT_TRUE (table_index1 != ~0))
	                {
	                  tp1 = pool_elt_at_index (vcm->tables, table_index1);
	                  phash1 = vnet_buffer(p1)->l2_classify.hash;
	                  class_prefetch_entry (tp1, phash1);
	                }
	            }

		  bi0 = from[0];
		  to_next[0] = bi0;
		  from += 1;
		  to_next += 1;
		  n_left_from -= 1;
		  n_left_to_next -= 1;

		  	  b0 = vlib_get_buffer (vm, bi0);
	          h0 = b0->data;
	          table_index0 = vnet_buffer(b0)->l2_classify.table_index;
	          e0 = 0;
	          t0 = 0;
	          t1=0;
	          vnet_buffer(b0)->l2_classify.opaque_index = ~0;

	          if (PREDICT_TRUE(table_index0 != ~0))
	            {
	              loop:
	        	  hash0 = vnet_buffer(b0)->l2_classify.hash;
	              t0 = pool_elt_at_index (vcm->tables, table_index0);
	              e0 = class_find_entry (t0, (u8 *) h0, hash0,
	                                             now);

	              //Check next table if entry can't be found

	              if (!e0) {
	            	  table_index0++;
	            	  checkempty:
					  t0 = pool_elt_at_index (vcm->tables, table_index0);
					  if(t0)
						  return 0;

	            	  if (t0->active_elements==0){
	            		  table_index0++;
	            		  goto checkempty;
	            	  } else if (t0->active_elements>0) {
	            			  goto loop;
	            	  }
	              }

	              if (e0)
	                {
	                  vnet_buffer(b0)->l2_classify.opaque_index
	                    = e0->opaque_index;
	                  vlib_buffer_advance (b0, e0->advance);
	                  next0 = (e0->next_index < node->n_next_nodes)?
	                           e0->next_index:next0;
	                  hits++;
	                }
	              else
	                {
	                  while (1)
	                    {
	                      if (t0->next_table_index != ~0)
	                        t0 = pool_elt_at_index (vcm->tables,
	                                                t0->next_table_index);
	                      else
	                        {
	                          next0 = (t0->miss_next_index < IP_LOOKUP_N_NEXT)?
	                                   t0->miss_next_index:next0;
	                          misses++;
	                          break;
	                        }

	                      hash0 = class_hash_packet (t0, (u8 *) h0);
	                      e0 = class_find_entry
	                        (t0, (u8 *) h0, hash0, now);
	                      if (e0)
	                        {
	                          vnet_buffer(b0)->l2_classify.opaque_index
	                            = e0->opaque_index;
	                          vlib_buffer_advance (b0, e0->advance);
	                          next0 = (e0->next_index < node->n_next_nodes)?
	                                   e0->next_index:next0;
	                          hits++;
	                          chain_hits++;
	                          break;
	                        }
	                    }
	                }
	            }

	          x0=table_index0/field;
	          x=x0*field;
	          next_table=0;

              //Check only the field that want to be checked

	          if (table_index0==0) {
	        	  if (e0->src1==0) {
	        		  if (e0->dst1==0){
						  if (e0->proto1==0) {
							  next_table=0;
						  } else
							  next_table=x+field;
					  } else
						  next_table=x+5;
	        	  } else
	        		  next_table=x+1;
	          } else if ((table_index0-x)<=4 && (table_index0-x)>0) {
	        	  if (e0->dst1==0){
	        		  if (e0->proto1==0) {
	        			  next_table=0;
	        		  } else
	        			  next_table=x+field;
	        	  } else
	        		  next_table=x+5;
	          } else if ((table_index0-x)<=8 && (table_index0-x)>4) {
	        	  if (e0->proto1==0)
	        		  next_table=0;
	        	  else
	        		  next_table=x+field;
	          }

	          //Deciding next step

			  if (next_table != 0) {
				  checkempty2:
				  t1 = pool_elt_at_index (vcm->tables, next_table);
				  if (t1) {
					  if(t1->active_elements==0){
						  (next_table)++;
						  goto checkempty2;
					  }
				  }
				  vnet_buffer(b0)->l2_classify.table_index=next_table;
				  if(table_index0!=0){
					  if (t0->prev_act==0) {
						  t1->prev_act=next0;
					  } else {
						  if (t0->prev_act==next0){
							  t1->prev_act=(t0->prev_act);
						  } else {
							  next0=0;
							  goto end;
						  }
					  }
					  next0=11;
				  }
			  } else {
				  if (((e0->src1)+(e0->dst1)+(e0->proto1)) != 1) {
					  if (t0->prev_act!=next0){
						  next0=0;
						  goto end;
					  }
				  }
			  }

			  end:

	          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
	                            && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	            {
	              class_trace_t *t =
	                vlib_add_trace (vm, node, b0, sizeof (*t));
	              t->next_index = e0->next;
	              t->table_index = t0 ? t0 - vcm->tables : ~0;
	              t->entry_index = e0 ? e0 - t0->entries : ~0;
	            }

	          /* verify speculative enqueue, maybe switch current next frame */
		  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
						   to_next, n_left_to_next,
						   bi0, next0);
		}

	      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
	    }

	  vlib_node_increment_counter (vm, node->node_index,
	                               IP_CLASSIFY_ERROR_MISS,
	                               misses);
	  vlib_node_increment_counter (vm, node->node_index,
	                               IP_CLASSIFY_ERROR_HIT,
	                               hits);
	  vlib_node_increment_counter (vm, node->node_index,
	                               IP_CLASSIFY_ERROR_CHAIN_HIT,
	                               chain_hits);
	  return frame->n_vectors;
};

static uword
class_action (vlib_main_t * vm,
              vlib_node_runtime_t * node,
              vlib_frame_t * frame)
{
  return class_node_fn (vm, node, frame,1);
}


VLIB_REGISTER_NODE (class_node) = {
  .function = class_action,
  .name = "class-new",
  .vector_size = sizeof (u32),
  .format_trace = format_class_trace,
  .n_errors = ARRAY_LEN(class_error_strings),
  .error_strings = class_error_strings,

  .n_next_nodes = IP_LOOKUP_N_NEXT,
  .next_nodes = IP4_LOOKUP_NEXT_NODES,
};

VLIB_NODE_FUNCTION_MULTIARCH (class_node, class_action)
