/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. Handles (badly) IPv4 for tun, ARP and IPv4 for     *
 * tap. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.                     *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2020 Ming Zhu                                                      *
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
#include <time.h>
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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define MAX_CLIENT 30
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

/* IP header */
struct sniff_ip
{
  u_char ip_vhl;                 /* version << 4 | header length >> 2 */
  u_char ip_tos;                 /* type of service */
  u_short ip_len;                /* total length */
  u_short ip_id;                 /* identification */
  u_short ip_off;                /* fragment offset field */
#define IP_RF 0x8000             /* reserved fragment flag */
#define IP_DF 0x4000             /* dont fragment flag */
#define IP_MF 0x2000             /* more fragments flag */
#define IP_OFFMASK 0x1fff        /* mask for fragmenting bits */
  u_char ip_ttl;                 /* time to live */
  u_char ip_p;                   /* protocol */
  u_short ip_sum;                /* checksum */
  struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

int debug;
char *progname;

/* client information */
struct user_info
{
  uint16_t udp_port;
  char udp_ip[16];
  char real_ip[16];
};

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
 * Prepare a SSL context for use by the server  *
 ************************************************/
static SSL_CTX *get_server_context(const char *ca_pem,
                                   const char *cert_pem,
                                   const char *key_pem)
{
  SSL_CTX *ctx;

  /* Get a default context */
  if (!(ctx = SSL_CTX_new(SSLv23_server_method())))
  {
    fprintf(stderr, "SSL_CTX_new failed\n");
    return NULL;
  }

  /* Set the CA file location for the server */
  if (SSL_CTX_load_verify_locations(ctx, ca_pem, NULL) != 1)
  {
    fprintf(stderr, "Could not set the CA file location\n");
    goto fail;
  }

  /* Load the client's CA file location as well */
  SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(ca_pem));

  /* Set the server's certificate signed by the CA */
  if (SSL_CTX_use_certificate_file(ctx, cert_pem, SSL_FILETYPE_PEM) != 1)
  {
    fprintf(stderr, "Could not set the server's certificate\n");
    goto fail;
  }

  /* Set the server's key for the above certificate */
  if (SSL_CTX_use_PrivateKey_file(ctx, key_pem, SSL_FILETYPE_PEM) != 1)
  {
    fprintf(stderr, "Could not set the server's key\n");
    goto fail;
  }

  /* We've loaded both certificate and the key, check if they match */
  if (SSL_CTX_check_private_key(ctx) != 1)
  {
    fprintf(stderr, "Server's certificate and the key don't match\n");
    goto fail;
  }

  /* We won't handle incomplete read/writes due to renegotiation */
  SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

  /* Specify that we need to verify the client as well */
  SSL_CTX_set_verify(ctx,
                     SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                     NULL);

  /* We accept only certificates signed only by the CA himself */
  SSL_CTX_set_verify_depth(ctx, 1);

  /* Done, return the context */
  return ctx;

fail:
  SSL_CTX_free(ctx);
  return NULL;
}

/************************************************
 *  Create a SSL socket for use by the server   *
 ************************************************/

static int get_SSLsocket(int port_num)
{
  struct sockaddr_in sin;
  int sock, val;

  /* Create a socket */
  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    fprintf(stderr, "Cannot create a socket\n");
    return -1;
  }

  /* We don't want bind() to fail with EBUSY */
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0)
  {
    fprintf(stderr, "Could not set SO_REUSEADDR on the socket\n");
    goto fail;
  }

  /* Fill up the server's socket structure */
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons(port_num);

  /* Bind the socket to the specified port number */
  if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0)
  {
    fprintf(stderr, "Could not bind the socket\n");
    goto fail;
  }

  /* Specify that this is a listener socket */
  if (listen(sock, SOMAXCONN) < 0)
  {
    fprintf(stderr, "Failed to listen on this socket\n");
    goto fail;
  }

  /* Done, return the socket */
  return sock;
fail:
  close(sock);
  return -1;
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
  struct sniff_ip *iph = NULL; /* Construct the IP header*/
  int maxfd;
  uint16_t nread, nwrite;
  //  uint16_t total_len, ethertype;
  char buffer[BUFSIZE];
  char buffer2[BUFSIZE];
  memset(buffer, 0, BUFSIZE);
  memset(buffer2, 0, BUFSIZE);
  unsigned char iv[MAX_CLIENT][33]; // iv length=32
  unsigned char key[MAX_CLIENT][33];
  memset(iv, 0, sizeof(iv));
  memset(key, 0, sizeof(key));
  struct sockaddr_in local, remote; //for UDP
  struct sockaddr_in sin;           //for SSL
  socklen_t sin_len;
  SSL_CTX *ctx;
  SSL *ssl;
  SSL *client_ssl[MAX_CLIENT];
  int rc;
  char remote_ip[16] = "";
  unsigned short int port = PORT;
  unsigned short int port_SSL = PORT_SSL;
  int sock_fd, net_fd, listen_fd, act_fd, ssl_fd = -1, optval = 1;
  int client_fd[MAX_CLIENT] = {0};
  socklen_t remotelen;
  int cliserv = -1; /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;
  char ca_pem[] = "./CA/ca.crt";
  char server_crt[] = "./CA/server.crt";
  char server_key[] = "./CA/server.key";
  EVP_PKEY *hash_key[MAX_CLIENT];
  struct user_info client_info[MAX_CLIENT];
  int activity[MAX_CLIENT] = {0};

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
  *  SSL server, Listen to the port SSL  ***
  *****************************************/
  /* Parse the port number, and then validate it's range */
  if (port_SSL < 1 || port_SSL > 65535)
  {
    fprintf(stderr, "Invalid port number: %d\n", port_SSL);
    exit(1);
  }

  /* Initialize OpenSSL */
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();

  /* Get a server context for our use */
  if (!(ctx = get_server_context(ca_pem, server_crt, server_key)))
  {
    exit(1);
  }

  /* Get a socket which is ready to listen on the server's port number */
  if ((listen_fd = get_SSLsocket(port_SSL)) < 0)
  {
    exit(1);
  }

  /******************************
  ** UDP Server, create socket **
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

  while (1)
  {
    int ret;
    fd_set rd_set;

    // do_debug("Enter while loop. \n");
    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set);
    FD_SET(net_fd, &rd_set);
    FD_SET(listen_fd, &rd_set);
    /* use select() to handle two descriptors at once */
    maxfd = (tap_fd > net_fd) ? tap_fd : net_fd;
    maxfd = (maxfd > listen_fd) ? maxfd : listen_fd;
    int i = 0;
    for (i = 0; i < MAX_CLIENT; i++)
    {
      if (activity[i] != 0)
      {
        FD_SET(client_fd[i], &rd_set);
        maxfd = (maxfd > client_fd[i]) ? maxfd : client_fd[i];
      }
    }

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
    if (FD_ISSET(listen_fd, &rd_set))
    {
      /* Hold on till we can an incoming connection */
      sin_len = sizeof(sin);
      if ((ssl_fd = accept(listen_fd, (struct sockaddr *)&sin, &sin_len)) < 0)
      {
        perror("Failed to accept connection\n");
        exit(1);
      }

      /* Get an SSL handle from the context */
      if (!(ssl = SSL_new(ctx)))
      {
        perror("Could not get an SSL handle from the context\n");
        close(ssl_fd);
        exit(1);
      }

      /* Associate the newly accepted connection with this handle */
      SSL_set_fd(ssl, ssl_fd);

      /* Now perform handshake */
      if ((rc = SSL_accept(ssl)) != 1)
      {
        perror("Could not perform SSL handshake\n");
        if (rc != 0)
        {
          SSL_shutdown(ssl);
        }
        SSL_free(ssl);
        exit(1);
      }

      /* Print success connection message on the server */
      do_debug("SSL handshake successful with %s:%d\n",
               inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));

      /* Send userid  */
      int i = 0;
      int skip = 0;
      for (i = 0; i <= MAX_CLIENT; i++)
      {
        if (i == MAX_CLIENT)
        {
          SSL_shutdown(ssl);
          SSL_free(ssl);
          skip = 1;
        }
        else
        {
          if (activity[i] == 0)
          {
            activity[i] = 1;
            client_fd[i] = ssl_fd;
            client_ssl[i] = ssl;
            *((int *)buffer) = i;
            SSL_write(ssl, buffer, sizeof(int));
            do_debug("SERVER: userid = %d, fd = %d\n", i, client_fd[i]);
            break;
          }
        }
      }

      if (skip == 1)
      {
        do_debug("SERVER: achieve max client limit\n");
        continue;
      }

      /*********************************
      *Initialize encryption parameters*
      *********************************/
      nread = SSL_read(ssl, iv[i], sizeof(iv[i]));
      do_debug("SERVER: receive iv (%d byte) through SSL\n", nread);
      // do_debug("iv: %s\n", iv[i]);
      nread = SSL_read(ssl, key[i], sizeof(key[i]));
      do_debug("SERVER: receive session key (%d byte) through SSL\n", nread);
      // do_debug("session key: %s\n", key[i]);
      //create hash key
      hash_key[i] = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key[i], strlen((const char *)key[i]));
    }

    for (i = 0; i < MAX_CLIENT; i++)
    {
      if (activity[i] != 0)
      {
        act_fd = client_fd[i];
        // do_debug("SERVER: the %d client socket %d is active\n", i, act_fd);
        if (FD_ISSET(act_fd, &rd_set))
        {
          /* Read SSL packet */
          // do_debug("Server: enter %d case.\n", act_fd);
          nread = SSL_read(client_ssl[i], buffer, BUFSIZE);
          do_debug("SERVER: the %d client socket receive %d bytes message\n", i, nread);

          if (nread <= 0)
          {
            // do_debug("Server: Closing current TCP/SSL connection\n");
            /* Cleanup the SSL handle */
            SSL_shutdown(client_ssl[i]);
            SSL_free(client_ssl[i]);
            do_debug("SERVER: Close TCP/SSL connection to the %d client.\n", i);
            close(act_fd);
            // do_debug("SERVER: Close socket file descriptor\n");
            act_fd = -1;
            activity[i] = 0;
            // do_debug("SERVER: Update activity list\n");
            continue;
          }

          do_debug("receive message: %s\n", buffer);
          if (!strcmp(buffer, "iv"))
          {
            nread = SSL_read(client_ssl[i], iv[i], sizeof(iv[i]));
            do_debug("SERVER: reset iv of client %d through SSL\n", i);
          }

          if (!strcmp(buffer, "key"))
          {
            nread = SSL_read(client_ssl[i], key[i], sizeof(key[i]));
            // do_debug("SERVER: the %d client socket receive %d bytes message\n", i, nread);
            do_debug("SERVER: reset session key of client %d through SSL\n", i);
            // do_debug("session key: %s\n", key[i]);
            //create hash key
            EVP_PKEY_free(hash_key[i]);
            hash_key[i] = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key[i], strlen((const char *)key[i]));
          }
        }
      }
    }

    if (FD_ISSET(tap_fd, &rd_set))
    {
      /* data from tun/tap: just read it and write it to the network */

      nread = cread(tap_fd, buffer, BUFSIZE);

      tap2net++;
      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

      /* retrive client information */
      iph = (struct sniff_ip *)(buffer2);
      char real_addr[16];
      memset(real_addr, 0, sizeof(real_addr));
      strcpy(real_addr, inet_ntoa(iph->ip_src));
      // do_debug("       From: %s\n", inet_ntoa(iph->ip_src));
      int i = 0;
      for (i = 0; i < MAX_CLIENT; i++)
      {
        if (!strcmp(real_addr, client_info[i].real_ip))
        {
          remote.sin_addr.s_addr = inet_addr(client_info[i].udp_ip);
          remote.sin_port = htons(client_info[i].udp_port);
          break;
        }
      }

      /* authenticated encryption */
      int text_len = -1;
      memset(buffer2, 0, BUFSIZE);
      if ((text_len = authentic_encrypt((unsigned char *)buffer, nread, (unsigned char *)buffer2, iv[i], key[i], hash_key[i])) < 0)
      {
        perror("Authentic encryption fails!\n");
      }

      /* write UDP packet */
      nwrite = udpSend(net_fd, buffer2, text_len, remote);

      do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    }

    if (FD_ISSET(net_fd, &rd_set))
    {
      /* data from the network: read it, and write it to the tun/tap interface. */
      net2tap++;
      // do_debug("NET2TAP %lu: Receive data from the network\n", net2tap);

      /* read packet */
      nread = recvfrom(net_fd, buffer, BUFSIZE, MSG_WAITALL, (struct sockaddr *)&remote, &remotelen);
      // do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

      int *ptr_userid = (int *)buffer;
      int i = *ptr_userid;
      unsigned char *message = (unsigned char *)(ptr_userid + 1);
      do_debug("NET2TAP %lu: Read %d bytes from the user %d\n", net2tap, nread, i);

      // do_debug("       From: %s\n", inet_ntoa(remote.sin_addr));
      // do_debug("   Src port: %d\n", ntohs(remote.sin_port));
      strcpy(client_info[i].udp_ip, inet_ntoa(remote.sin_addr));
      client_info[i].udp_port = ntohs(remote.sin_port);

      // print_payload(buffer, nread);
      // print_payload(message, nread - sizeof(int));
      /* authenticated decryption */
      int decryptedtext_len = -1;
      memset(buffer2, 0, BUFSIZE);
      if ((decryptedtext_len = authentic_decrypt(message, nread - sizeof(int), (unsigned char *)buffer2, iv[i], key[i], hash_key[i])) < 0)
      {
        perror("Authentic decryption fails!\n");
      }

      // fprintf(stderr, "IP header:\n");
      // print_payload((unsigned char *)buffer2, 20);
      iph = (struct sniff_ip *)(buffer2);
      // printf("       From: %s\n", inet_ntoa(iph->ip_src));
      strcpy(client_info[i].real_ip, inet_ntoa(iph->ip_src));

      /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */
      nwrite = cwrite(tap_fd, buffer2, decryptedtext_len);
      do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }
  }
  /* Cleanup the SSL handle */
  SSL_shutdown(ssl);
  SSL_free(ssl);
  /* Close the listening socket */
  close(listen_fd);
  SSL_CTX_free(ctx);
  return (0);
}
