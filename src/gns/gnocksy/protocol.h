

/* The socks phases */
enum
{
  SOCKS5_INIT,
  SOCKS5_REQUEST,
  SOCKS5_DATA_TRANSFER
};

/* Client hello */
struct socks5_client_hello
{
  uint8_t version;
  uint8_t num_auth_methods;
  char* auth_methods;
};

/* Client socks request */
struct socks5_client_request
{
  uint8_t version;
  uint8_t command;
  uint8_t resvd;
  uint8_t addr_type;
  /* 
   * followed by either an ip4/ipv6 address
   * or a domain name with a length field in front
   */
};

/* Server hello */
struct socks5_server_hello
{
  uint8_t version;
  uint8_t auth_method;
};

/* Struct used to store connection
 * information
 */
struct socks5_bridge
{
  int fd;
  struct socks5_bridge* remote_end;
  struct sockaddr addr;
  socklen_t addr_len;
  int status;
};

/* Server response to client requests */
struct socks5_server_response
{
  uint8_t version;
  uint8_t reply;
  uint8_t reserved;
  uint8_t addr_type;
  uint8_t add_port[18];
};
