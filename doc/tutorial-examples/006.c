static void
handle_fix (void *cls, const struct MyMessage *msg)
{
  // process 'msg'
}

static int
check_var (void *cls, const struct MyVarMessage *msg)
{
  // check 'msg' is well-formed
  return GNUNET_OK;
}

static void
handle_var (void *cls, const struct MyVarMessage *msg)
{
  // process 'msg'
}

struct GNUNET_MQ_MessageHandler handlers[] = {
  GNUNET_MQ_hd_fixed_size (fix,
                          GNUNET_MESSAGE_TYPE_MY_FIX,
                          struct MyMessage,
                          NULL),
  GNUNET_MQ_hd_fixed_size (var,
                          GNUNET_MESSAGE_TYPE_MY_VAR,
                          struct MyVarMessage,
                          NULL),

  GNUNET_MQ_handler_end ()
};
