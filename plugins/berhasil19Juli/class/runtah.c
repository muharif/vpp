static clib_error_t *
class_gen_command_fn (vlib_main_t * vm,
                             unformat_input_t * input,
                             vlib_cli_command_t * cmd)
{
  class_main_t * cm = &class_main;
  int is_add = 1;
  u32 table_index = 0;
  u32 hit_next_index = 14;
  u64 opaque_index = ~0;
  u8 * match = 0;
  i32 advance = 0;
  int i, rv;

  unformat (input, "match hex 0000000000000000000000000000000000000000000000000000000a00000000", unformat_class2_match,
                           cm, &match, table_index);

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
