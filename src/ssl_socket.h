#ifndef SSL_SOCKET_H
#define SSL_SOCKET_H

#include <openssl/ssl.h>
#include <openssl/bio.h>

#include <string>

class SSL_socket
{
public:
    SSL_socket();
    ~SSL_socket();

    bool is_started;

    bool start();
    bool write_read(std::string req, std::string *ret);

private:
    SSL_CTX *ctx;
    BIO *bio;
    SSL *ssl;

    void cleanup();
};

#endif
