/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. Handles (badly) IPv4 for tun, ARP and IPv4 for     *
 * tap. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.                     *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2009 Davide Brini.                                                 *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define FAIL -1
typedef unsigned char byte;

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000
#define TYPELIMIT 30
#define CLIENT 0
#define SERVER 1
#define PORT 55555
#define PORT_SSL 55535

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

int debug;
char *progname;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags)
{

  struct ifreq ifr;
  int fd, err;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
  {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev)
  {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0)
  {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/************************************************
 * Prepare a SSL context for use by the client  *
 ************************************************/

static SSL_CTX *get_client_context(const char *ca_pem,
                                   const char *cert_pem,
                                   const char *key_pem)
{
  SSL_CTX *ctx;

  /* Create a generic context */
  if (!(ctx = SSL_CTX_new(SSLv23_client_method())))
  {
    fprintf(stderr, "Cannot create a client context\n");
    return NULL;
  }

  /* Load the client's CA file location */
  if (SSL_CTX_load_verify_locations(ctx, ca_pem, NULL) != 1)
  {
    fprintf(stderr, "Cannot load client's CA file\n");
    goto fail;
  }

  /* Load the client's certificate */
  if (SSL_CTX_use_certificate_file(ctx, cert_pem, SSL_FILETYPE_PEM) != 1)
  {
    fprintf(stderr, "Cannot load client's certificate file\n");
    goto fail;
  }

  /* Load the client's key */
  if (SSL_CTX_use_PrivateKey_file(ctx, key_pem, SSL_FILETYPE_PEM) != 1)
  {
    fprintf(stderr, "Cannot load client's key file\n");
    goto fail;
  }

  /* Verify that the client's certificate and the key match */
  if (SSL_CTX_check_private_key(ctx) != 1)
  {
    fprintf(stderr, "Client's certificate and key don't match\n");
    goto fail;
  }

  /* We won't handle incomplete read/writes due to renegotiation */
  SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

  /* Specify that we need to verify the server's certificate */
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

  /* We accept only certificates signed only by the CA himself */
  SSL_CTX_set_verify_depth(ctx, 1);

  /* Done, return the context */
  return ctx;

fail:
  SSL_CTX_free(ctx);
  return NULL;
}

/************************************************
 * Authenticated Encryption AES256-CBC + SHA256 *
 ************************************************/
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len = 0;

  int ciphertext_len;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    perror("Fail to create the context");

  /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    perror("Fail to initialise the encryption operation");

  /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    perror("Fail to read plaintext");
  ciphertext_len = len;

  /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    perror("Fail to add additional length");
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len = 0;

  int plaintext_len;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    perror("Fail to create the context");

  /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    perror("Fail to initialise key or IV");

  /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    perror("Fail to read ciphertext");
  plaintext_len = len;

  /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    perror("Fail to add additional length");
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

int hmac_it(const byte *msg, size_t mlen, byte **val, size_t *vlen, EVP_PKEY *pkey)
{
  /* Returned to caller */
  int result = -1;

  if (!msg || !mlen || !val || !pkey)
  {
    perror("Check hmac_it input parameters");
    return -1;
  }

  if (*val)
    OPENSSL_free(*val);

  *val = NULL;
  *vlen = 0;

  EVP_MD_CTX *ctx = NULL;

  do
  {
    ctx = EVP_MD_CTX_create();
    if (ctx == NULL)
    {
      printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    const EVP_MD *md = EVP_sha256();
    if (md == NULL)
    {
      printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    int rc = EVP_DigestInit_ex(ctx, md, NULL);
    if (rc != 1)
    {
      printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
    if (rc != 1)
    {
      printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    rc = EVP_DigestSignUpdate(ctx, msg, mlen);
    if (rc != 1)
    {
      printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    size_t req = 0;
    rc = EVP_DigestSignFinal(ctx, NULL, &req);
    if (rc != 1)
    {
      printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    if (!(req > 0))
    {
      printf("EVP_DigestSignFinal failed (2), error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    *val = OPENSSL_malloc(req);
    if (*val == NULL)
    {
      printf("OPENSSL_malloc failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    *vlen = req;
    rc = EVP_DigestSignFinal(ctx, *val, vlen);
    if (rc != 1)
    {
      printf("EVP_DigestSignFinal failed (3), return code %d, error 0x%lx\n", rc, ERR_get_error());
      break; /* failed */
    }

    if (req != *vlen)
    {
      printf("EVP_DigestSignFinal failed, mismatched signature sizes %ld, %ld", req, *vlen);
      break; /* failed */
    }

    result = 0;

  } while (0);

  if (ctx)
  {
    EVP_MD_CTX_destroy(ctx);
    ctx = NULL;
  }

  /* Convert to 0/1 result */
  return !!result;
}

int verify_it(const byte *msg, size_t mlen, const byte *val, size_t vlen, EVP_PKEY *pkey)
{
  /* Returned to caller */
  int result = -1;

  if (!msg || !mlen || !val || !vlen || !pkey)
  {
    perror("Check verify_it input parameters");
    return -1;
  }

  EVP_MD_CTX *ctx = NULL;

  do
  {
    ctx = EVP_MD_CTX_create();
    if (ctx == NULL)
    {
      printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    const EVP_MD *md = EVP_sha256();
    if (md == NULL)
    {
      printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    int rc = EVP_DigestInit_ex(ctx, md, NULL);
    if (rc != 1)
    {
      printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
    if (rc != 1)
    {
      printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    rc = EVP_DigestSignUpdate(ctx, msg, mlen);
    if (rc != 1)
    {
      printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    byte buff[EVP_MAX_MD_SIZE];
    size_t size = sizeof(buff);

    rc = EVP_DigestSignFinal(ctx, buff, &size);
    if (rc != 1)
    {
      printf("EVP_DigestVerifyFinal failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    if (!(size > 0))
    {
      printf("EVP_DigestSignFinal failed (2)\n");
      break; /* failed */
    }

    const size_t m = (vlen < size ? vlen : size);
    result = !!CRYPTO_memcmp(val, buff, m);

    OPENSSL_cleanse(buff, sizeof(buff));

  } while (0);

  if (ctx)
  {
    EVP_MD_CTX_destroy(ctx);
    ctx = NULL;
  }

  /* Convert to 0/1 result */
  return !!result;
}

int authentic_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *buffer, unsigned char *iv, unsigned char *key, EVP_PKEY *hash_key)
{
  int result = 0;
  unsigned char ciphertext[plaintext_len + 2];
  memset(ciphertext, 0, sizeof(ciphertext));
  int ciphertext_len = 0;
  unsigned char *hash = NULL; //hmac_it() will free the memory assigned to hash if not NULL
  size_t hash_len = 0;
  //unsigned char tag[20];
  if ((ciphertext_len = encrypt(plaintext, plaintext_len, key, iv, ciphertext)) == -1)
  {
    perror("Encryption fails");
    return -1;
  }

  if ((result = hmac_it(ciphertext, ciphertext_len, &hash, &hash_len, hash_key)) != 0)
  {
    printf("Fails to create HMAC \n");
    return -1;
  }

  int text_len = -1;
  unsigned int *p_cipher_len = (unsigned int *)buffer;
  *p_cipher_len = ciphertext_len;
  unsigned int *p_hash_len = p_cipher_len + 1;
  *p_hash_len = hash_len;
  unsigned char *p_cipher = (unsigned char *)(p_hash_len + 1);
  memcpy(p_cipher, ciphertext, ciphertext_len);
  unsigned char *p_hash = p_cipher + ciphertext_len;
  memcpy(p_hash, hash, hash_len);
  text_len = sizeof(unsigned int) * 2 + ciphertext_len + hash_len;

  return text_len;
}

int authentic_decrypt(unsigned char *buffer, int buffer_len, unsigned char *decryptedtext, unsigned char *iv, unsigned char *key, EVP_PKEY *hash_key)
{
  int result = 1;
  int decryptedtext_len = -1;
  unsigned int *p_cipher_len = (unsigned int *)buffer;
  int ciphertext_len = *p_cipher_len;
  unsigned int *p_hash_len = p_cipher_len + 1;
  int hash_len = *p_hash_len;
  unsigned char *p_cipher = (unsigned char *)(p_hash_len + 1);
  unsigned char ciphertext[buffer_len + 2];
  unsigned char hash[40];
  memset(ciphertext, 0, sizeof(ciphertext));
  memset(hash, 0, sizeof(hash));
  memcpy(ciphertext, p_cipher, ciphertext_len);
  unsigned char *p_hash = p_cipher + ciphertext_len;
  memcpy(hash, p_hash, hash_len);

  if ((result = verify_it(ciphertext, ciphertext_len, hash, hash_len, hash_key) == 0))
  {
    if ((decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext)) == -1)
    {
      perror("Decryption fails");
      return -1;
    }
    decryptedtext[decryptedtext_len] = '\0';
  }
  else
  {
    perror("HMAC authentication Fails\n");
    return -1;
  }

  return decryptedtext_len;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n)
{

  int nread;

  if ((nread = read(fd, buf, n)) < 0)
  {
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n)
{

  int nwrite;

  if ((nwrite = write(fd, buf, n)) < 0)
  {
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n)
{

  int nread, left = n;

  while (left > 0)
  {
    if ((nread = cread(fd, buf, left)) == 0)
    {
      return 0;
    }
    else
    {
      left -= nread;
      buf += nread;
    }
  }
  return n;
}

/**************************************************************************
 * udpRecv: read the received UDP package and return package length       *
 **************************************************************************/
int udpRecv(int sockfd, char *buf, int n, struct sockaddr *p_addr)
{

  int nread;
  socklen_t addrlen = sizeof(*p_addr);
  if ((nread = recvfrom(sockfd, (char *)buf, n, MSG_WAITALL, p_addr, &addrlen)) < 0)
  {
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * udpSend: Send UDP packet to remote IP address                          *
 **************************************************************************/
int udpSend(int sockfd, char *buf, int n, struct sockaddr_in addr)
{

  int nwrite;
  socklen_t addrlen = sizeof(addr);
  if ((nwrite = sendto(sockfd, buf, n, MSG_CONFIRM, (const struct sockaddr *)&addr, addrlen)) < 0)
  {
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/************************************************************
 *               Print packet payload                       *
 * *********************************************************/
void print_payload(const u_char *payload, int len);

void print_hex_ascii_line(const u_char *payload, int len, int offset);

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len)
{

  int len_rem = len;
  int line_width = 16; /* number of bytes per line */
  int line_len;
  int offset = 0; /* zero-based offset counter */
  const u_char *ch = payload;

  if (len <= 0)
    return;

  /* data fits on one line */
  if (len <= line_width)
  {
    print_hex_ascii_line(ch, len, offset);
    return;
  }

  /* data spans multiple lines */
  for (;;)
  {
    /* compute current line length */
    line_len = line_width % len_rem;
    /* print line */
    print_hex_ascii_line(ch, line_len, offset);
    /* compute total remaining */
    len_rem = len_rem - line_len;
    /* shift pointer to remaining bytes to print */
    ch = ch + line_len;
    /* add offset */
    offset = offset + line_width;
    /* check if we have line width chars or less */
    if (len_rem <= line_width)
    {
      /* print last line and get out */
      print_hex_ascii_line(ch, len_rem, offset);
      break;
    }
  }

  return;
}

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

  int i;
  int gap;
  const u_char *ch;

  /* offset */
  fprintf(stderr, "%05d   ", offset);

  /* hex */
  ch = payload;
  for (i = 0; i < len; i++)
  {
    fprintf(stderr, "%02x ", *ch);
    ch++;
    /* print extra space after 8th byte for visual aid */
    if (i == 7)
      fprintf(stderr, " ");
  }
  /* print space to handle line less than 8 bytes */
  if (len < 8)
    fprintf(stderr, " ");

  /* fill hex gap with spaces if not full line */
  if (len < 16)
  {
    gap = 16 - len;
    for (i = 0; i < gap; i++)
    {
      fprintf(stderr, "   ");
    }
  }
  fprintf(stderr, "   ");

  /* ascii (if printable) */
  ch = payload;
  for (i = 0; i < len; i++)
  {
    if (isprint(*ch))
      fprintf(stderr, "%c", *ch);
    else
      fprintf(stderr, ".");
    ch++;
  }

  fprintf(stderr, "\n");

  return;
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...)
{

  va_list argp;

  if (debug)
  {
    va_start(argp, msg);
    vfprintf(stderr, msg, argp);
    va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...)
{

  va_list argp;

  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

int main(int argc, char *argv[])
{

  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  int maxfd;
  uint16_t nread, nwrite;
  //  uint16_t total_len, ethertype;
  char buffer[BUFSIZE];
  char buffer2[BUFSIZE];
  char buffer_std[TYPELIMIT];
  memset(buffer, 0, BUFSIZE);
  memset(buffer2, 0, BUFSIZE);
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";
  unsigned short int port = PORT;
  unsigned short int port_SSL = PORT_SSL;
  int sock_fd, net_fd, ssl_fd, optval = 1;
  socklen_t remotelen;
  int cliserv = -1; /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;
  SSL_CTX *ctx;
  BIO *sbio;
  SSL *ssl;
  /* Failure till we know it's a success */
  int rc = -1;
  char ca_pem[] = "./CA/ca.crt";
  char client_crt[] = "./CA/client.crt";
  char client_key[] = "./CA/client.key";
  int userid = -1;

  progname = argv[0];

  /* Check command line options */
  while ((option = getopt(argc, argv, "i:sc:p:uahd")) > 0)
  {
    switch (option)
    {
    case 'd':
      debug = 1;
      break;
    case 'h':
      usage();
      break;
    case 'i':
      strncpy(if_name, optarg, IFNAMSIZ - 1);
      break;
    case 's':
      cliserv = SERVER;
      break;
    case 'c':
      cliserv = CLIENT;
      strncpy(remote_ip, optarg, 15);
      break;
    case 'p':
      port = atoi(optarg);
      break;
    case 'u':
      flags = IFF_TUN;
      break;
    case 'a':
      flags = IFF_TAP;
      header_len = ETH_HDR_LEN;
      break;
    default:
      my_err("Unknown option %c\n", option);
      usage();
    }
  }

  argv += optind;
  argc -= optind;

  if (argc > 0)
  {
    my_err("Too many options!\n");
    usage();
  }

  if (*if_name == '\0')
  {
    my_err("Must specify interface name!\n");
    usage();
  }
  else if (cliserv < 0)
  {
    my_err("Must specify client or server mode!\n");
    usage();
  }
  else if ((cliserv == CLIENT) && (*remote_ip == '\0'))
  {
    my_err("Must specify server address!\n");
    usage();
  }

  /* initialize tun/tap interface */
  if ((tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0)
  {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", if_name);

  /*****************************************
  *  SSL Client, try to connect to server  *
  *****************************************/

  /* Initialize OpenSSL */
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();

  /* Get a context */
  if (!(ctx = get_client_context(ca_pem, client_crt, client_key)))
  {
    return rc;
  }

  /* Get a BIO */
  if (!(sbio = BIO_new_ssl_connect(ctx)))
  {
    fprintf(stderr, "Could not get a BIO object from context\n");
    BIO_ssl_shutdown(sbio);
    exit(1);
  }

  /* Get the SSL handle from the BIO */
  BIO_get_ssl(sbio, &ssl);

  /* Connect to the server */
  char conn_str[30];
  char port_str[6];
  sprintf(port_str, "%d", port_SSL);
  memset(conn_str, 0, sizeof(conn_str));
  strcat(conn_str, remote_ip);
  strcat(conn_str, ":");
  strcat(conn_str, port_str);
  if (BIO_set_conn_hostname(sbio, conn_str) != 1)
  {
    fprintf(stderr, "Could not connecto to the server\n");
    BIO_free_all(sbio);
    exit(1);
  }

  /* Perform SSL handshake with the server */
  if (SSL_do_handshake(ssl) != 1)
  {
    fprintf(stderr, "SSL Handshake failed\n");
    BIO_free_all(sbio);
    exit(1);
  }

  /* Verify that SSL handshake completed successfully */
  if (SSL_get_verify_result(ssl) != X509_V_OK)
  {
    fprintf(stderr, "Verification of handshake failed\n");
    BIO_free_all(sbio);
    exit(1);
  }

  /* get file descriptor linked to an SSL object */
  ssl_fd = SSL_get_fd(ssl);

  /* Inform the user that we've successfully connected */
  printf("SSL handshake successful with %s\n", conn_str);

  /* receive userid */
  SSL_read(ssl, buffer, sizeof(int));
  userid = *((int *)buffer);
  do_debug("CLIENT: userid = %d\n", userid);

  /*********************************
  *Initialize encryption parameters*
  *********************************/
  unsigned char iv[33]; // iv length=32
  unsigned char key[33];
  memset(iv, 0, sizeof(iv));
  memset(key, 0, sizeof(key));
  srand(time(NULL)); // randomize seed
  int i = 0;
  for (i = 0; i < 32; ++i)
  {
    iv[i] = rand() % 255;
  }
  for (i = 0; i < 32; ++i)
  {
    key[i] = rand() % 255;
  }

  nwrite = SSL_write(ssl, iv, sizeof(iv));
  do_debug("CLIENT: send iv through SSL\n");
  // do_debug("iv: %s\n", iv);
  nwrite = SSL_write(ssl, key, sizeof(key));
  do_debug("CLIENT: send session key through SSL\n");
  // do_debug("session key: %s\n", key);

  //create hash key
  EVP_PKEY *hash_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, strlen((const char *)key));

  /******************************
  ** UDP Client, create socket **
  ******************************/

  if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
  {
    perror("socket()");
    exit(1);
  }

  if (cliserv == CLIENT)
  {
    /* Client, try to connect to server */

    /* assign the destination address */
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);

    net_fd = sock_fd;
    do_debug("CLIENT: UDP Client is ready to connect server %s\n", inet_ntoa(remote.sin_addr));
  }
  else
  {
    /* Server, wait for connections */

    /* avoid EADDRINUSE error on bind() */
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0)
    {
      perror("setsockopt()");
      exit(1);
    }

    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);
    if (bind(sock_fd, (struct sockaddr *)&local, sizeof(local)) < 0)
    {
      perror("bind()");
      exit(1);
    }

    /* wait for connection request */
    remotelen = sizeof(remote);
    memset(&remote, 0, remotelen);

    net_fd = sock_fd;
    do_debug("SERVER: ready for UDP connection\n");
  }

  // do_debug("tap_fd = %d, net_fd = %d.\n", tap_fd, net_fd);

  /* use select() to handle two descriptors at once */
  maxfd = (tap_fd > net_fd) ? tap_fd : net_fd;

  int do_work = 1;
  while (do_work)
  {
    int ret;
    fd_set rd_set;

    // do_debug("Enter while loop. \n");
    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set);
    FD_SET(net_fd, &rd_set);
    FD_SET(0, &rd_set); //stdin

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);
    // do_debug("There are %d active file descriptor\n", ret);
    if (ret < 0 && errno == EINTR)
    {
      continue;
    }

    if (ret < 0)
    {
      perror("select()");
      exit(1);
    }

    //do_debug("There are %d active file descriptor\n", ret);

    if (FD_ISSET(tap_fd, &rd_set))
    {
      /* data from tun/tap: just read it and write it to the network */

      nread = cread(tap_fd, buffer, BUFSIZE);

      tap2net++;
      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

      // print_payload((unsigned char *)buffer, nread);
      memset(buffer2, 0, BUFSIZE);
      int *ptr_userid = (int *)buffer2;
      *ptr_userid = userid;
      unsigned char *message = (unsigned char *)(ptr_userid + 1);

      /* authenticated encryption */
      int text_len = -1;
      if ((text_len = authentic_encrypt((unsigned char *)buffer, nread, message, iv, key, hash_key)) < 0)
      {
        perror("Authentic encryption fails!\n");
      }

      /* write UDP packet */
      nwrite = udpSend(net_fd, buffer2, sizeof(int) + text_len, remote);

      do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    }

    if (FD_ISSET(net_fd, &rd_set))
    {
      /* data from the network: read it, and write it to the tun/tap interface. */
      net2tap++;
      // do_debug("NET2TAP %lu: Receive data from the network\n", net2tap);

      /* read packet */
      nread = recvfrom(net_fd, buffer, BUFSIZE, MSG_WAITALL, (struct sockaddr *)&remote, &remotelen);
      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

      /* authenticated decryption */
      int decryptedtext_len = -1;
      memset(buffer2, 0, BUFSIZE);
      if ((decryptedtext_len = authentic_decrypt((unsigned char *)buffer, nread, (unsigned char *)buffer2, iv, key, hash_key)) < 0)
      {
        perror("Authentic decryption fails!\n");
      }

      /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */
      nwrite = cwrite(tap_fd, buffer2, decryptedtext_len);
      do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }

    if (FD_ISSET(0, &rd_set))
    {
      // do_debug("Receive type-in information\n");
      fgets(buffer_std, TYPELIMIT, stdin);
      buffer_std[strcspn(buffer_std, "\n")] = 0;
      if (!strcmp(buffer_std, "exitVPN"))
      {
        // do_debug("CLIENT: Closing ssl connection\n");
        /* Cleanup the SSL handle */
        SSL_shutdown(ssl);
        do_debug("CLIENT: Close ssl connection\n");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        do_work = 0;
      }
      if (!strcmp(buffer_std, "resetIV"))
      {
        int i = 0;
        for (i = 0; i < 32; ++i)
        {
          iv[i] = rand() % 255;
        }
        nwrite = SSL_write(ssl, "iv", sizeof("iv"));
        nwrite = SSL_write(ssl, iv, sizeof(iv));
        do_debug("CLIENT: Reset iv through SSL\n");
        // do_debug("iv: %s\n", iv);
      }
      if (!strcmp(buffer_std, "resetKEY"))
      {
        int i = 0;
        for (i = 0; i < 32; ++i)
        {
          key[i] = rand() % 255;
        }
        //create hash key
        hash_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, strlen((const char *)key));
        nwrite = SSL_write(ssl, "key", sizeof("key"));
        nwrite = SSL_write(ssl, key, sizeof(key));
        do_debug("CLIENT: send session key through SSL\n");
        // do_debug("session key: %s\n", key);
      }
    }
  }

  return (0);
}
