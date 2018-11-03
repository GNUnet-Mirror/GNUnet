void *
libgnunet_plugin_block_SERVICE_init (void *cls)
{
  static enum GNUNET_BLOCK_Type types[] =
  {
    GNUNET_BLOCK_TYPE_SERVICE_BLOCKYPE,
    GNUNET_BLOCK_TYPE_ANY
  };
  struct GNUNET_BLOCK_PluginFunctions *api;

  api = GNUNET_new (struct GNUNET_BLOCK_PluginFunctions);
  api->evaluate = &block_plugin_SERICE_evaluate;
  api->get_key = &block_plugin_SERVICE_get_key;
  api->types = types;
  return api;
}

