# private key in 'struct GNUNET_CRYPTO_EccPrivateKey' (FIXME: rename from 'd' to something longer...)
::^d$

# private key in 'struct GNUNET_CRYPTO_AesSessionKey'
::^key$

# private key in 'struct GNUNET_CRYPTO_AesSessionKey'
::^key$

# buf in adjust in crypto_ecc.c
crypto_ecc\.c:^adjust$:^buf$

# buf in mpi_print in crypto_ecc.c
crypto_ecc\.c:^mpi_print$:^buf$

# data in mpi_scan in crypto_ecc.c
crypto_ecc\.c:^mpi_scan$:^data$

# xbuf in GNUNET_CRYPTO_ecc_ecdh in crypto_ecc.c
crypto_ecc\.c:^GNUNET_CRYPTO_ecc_edch$:^xbuf$

# key_material in GNUNET_CRYPTO_ecc_ecdh in crypto_ecc.c
crypto_ecc\.c:^GNUNET_CRYPTO_ecc_edch$:^key_material$

# label in key derivation in crypto_ecc.c
crypto_ecc\.c:^derive_h$:^label$
crypto_ecc\.c:^GNUNET_CRYPTO_ecc_key_derive$:^label$
crypto_ecc\.c:^GNUNET_CRYPTO_ecc_public_key_derive$:^label$

# random numbers in crypto_random.c
crypto_ecc\.c:^GNUNET_CRYPTO_random_u32$:^ret$
crypto_ecc\.c:^GNUNET_CRYPTO_random_u64$:^ret$
crypto_ecc\.c:^GNUNET_CRYPTO_random_permute$:^x$

# keys in gnunet-service-core_kx.c
gnunet-service-core_kx\.c:GSC_KX_handle_ephemeral_key:^key_material$
gnunet-service-core_kx\.c::^encrypt_key$
gnunet-service-core_kx\.c::^decrypt_key$
gnunet-service-core_kx\.c:derive_aes_key:^key_material$
gnunet-service-core_kx\.c:derive_aes_key:^skey$
gnunet-service-core_kx\.c:derive_auth_key:^akey$
gnunet-service-core_kx\.c:derive_auth_key:^skey$

# keywords in file-sharing
fs_.*::keyword
gnunet-service-fs.*::keyword
gnunet-search\.c.*::keyword
gnunet-search\.c.*:^run$:^args$


# download URI for downloading
gnunet-service-fs.*::chk
gnunet-search\.c.*::chk
fs_uri\.c:uri_chk_parse:^h1$
fs_uri\.c:uri_chk_parse:^h2$
fs_uri\.c:GNUNET_FS_uri_parse:^uri$
gnunet-download\.c.*:^run$:^args$

# filename for downloading
gnunet-download\.c::^filename$

# filename for publishing
gnunet-publish\.c:run:^uri_string$
gnunet-publish\.c:run:^args$
gnunet-publish\.c:identity_continuation:^args0$

