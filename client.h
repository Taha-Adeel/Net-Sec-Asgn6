#ifndef CLIENT_H
#define CLIENT_H

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

class Client
{
private:
    int client_socket;           // socket descriptor
    SSL_CTX *ctx;                // SSL context
    std::string server_hostname; // hostname of the server

    int create_socket(std::string hostname, int port = 4433)
    {
        struct sockaddr_in addr;
        struct hostent *server;

        server = gethostbyname(hostname.c_str());
        if (server == NULL)
        {
            std::cerr << "ERROR, no such host" << std::endl;
            exit(0);
        }

        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(inet_ntoa(*(struct in_addr *)*server->h_addr_list));

        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0)
        {
            perror("Unable to create socket");
            exit(EXIT_FAILURE);
        }

        if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        {
            perror("Unable to connect");
            exit(EXIT_FAILURE);
        }

        return s;
    }

    SSL_CTX *create_context()
    {
		SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();

        const SSL_METHOD *method;
        SSL_CTX *ctx;

        method = TLS_client_method();

        ctx = SSL_CTX_new(method);
        if (!ctx)
        {
            perror("Unable to create SSL context for client");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        return ctx;
    }

    SSL *create_ssl()
    {
        SSL *ssl = SSL_new(ctx);
        if (!ssl)
        {
            perror("Unable to create SSL object for client");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        SSL_set_fd(ssl, client_socket);

        if (SSL_connect(ssl) != 1)
        {
            perror("Unable to connect to server :((( ");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
			throw std::runtime_error("Unable to connect to server :((( ");
        }

        return ssl;
    }

public:
    Client(std::string hostname)
    {
        // ctx = create_context();
        client_socket = create_socket(hostname);
    }

    ~Client()
    {
        close(client_socket);
        // SSL_CTX_free(ctx);
    }

    void run()
    {
        // SSL *ssl = create_ssl();
        char buf[1024];
        int bytes;

        while (true)
        {
            // bytes = SSL_read(ssl, buf, sizeof(buf));
            bytes = read(client_socket, buf, sizeof(buf));
            if (bytes > 0)
            {
                buf[bytes] = 0;
                std::cout << "Server: " << buf << std::endl;
            }
            else
            {
                ERR_print_errors_fp(stderr);
            }

            std::cout<< "Client: ";
            std::cin.getline(buf, sizeof(buf));

            // bytes = SSL_write(ssl, buf, strlen(buf));
            bytes = write(client_socket, buf, strlen(buf));

            if (bytes < 0)
            {
                ERR_print_errors_fp(stderr);
            }
        }

        // SSL_free(ssl);
    }
};

#endif