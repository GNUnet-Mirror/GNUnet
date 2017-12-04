GNUNET_SERVICE_MAIN
("service-name",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_fixed_size (...),
 GNUNET_MQ_hd_var_size (...),
 GNUNET_MQ_handler_end ());
