#ifndef SERVER_H
#define SERVER_H

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>

class Server
{
private:
    int server_socket;     // socket descriptor
    SSL_CTX *ctx;          // SSL context
    std::string hostname;  // hostname of the server
    std::string cert_file; // certificate file
    std::string key_file;  // private key file

    int client;           // current client socket descriptor

    int create_socket(int port = 4421)
    {
        struct sockaddr_in addr;

        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0)
        {
            perror("Unable to create socket");
            exit(EXIT_FAILURE);
        }

        if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        {
            perror("Unable to bind");
            exit(EXIT_FAILURE);
        }

        if (listen(s, 1) < 0)
        {
            perror("Unable to listen");
            exit(EXIT_FAILURE);
        }

        return s;
    }

    SSL_CTX *create_context()
    {
        SSL_library_init();              /* load encryption & hash algorithms for SSL */
        OpenSSL_add_all_algorithms();       /* load & register all cryptos, etc. */
    	SSL_load_error_strings();        /* load all error messages */


        const SSL_METHOD *method;
        SSL_CTX *ctx;

        method = TLS_server_method();

        ctx = SSL_CTX_new(method);
        if (!ctx)
        {
            perror("Unable to create SSL context for server");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        return ctx;
    }

    void configure_context()
    {
        /* Set the key and cert */
        if (SSL_CTX_use_certificate_file(ctx, cert_file.c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, key_file.c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }


    void accept_connection(){
        struct sockaddr_in addr;
        unsigned int len = sizeof(addr);
        SSL *ssl;

        client = accept(server_socket, (struct sockaddr *)&addr, &len);
        if (client < 0)
        {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }
    }

    void read_from_client(){
        char buf[1024];
        int bytes;
        while (true)
        {
            // bytes = SSL_read(ssl, buf, sizeof(buf));
            bytes = read(client, buf, sizeof(buf));
            if (bytes > 0)
            {
                buf[bytes] = 0;
                std::cout << "Client: " << buf << std::endl;
            }
            else if (bytes == -1)
            {   
                std::cout << "Client Disconnected" << std::endl;
                ERR_print_errors_fp(stderr);
            }
        }
    }

    void write_to_client(){
        char buf[1024];
        int bytes;
        while (true)
        {
            std::cin.getline(buf, sizeof(buf));
            // bytes = SSL_write(ssl, buf, strlen(buf));
            bytes = write(client, buf, strlen(buf));
            if (bytes < 0)
            {
                perror("Unable to write");
                ERR_print_errors_fp(stderr);
            }
        }
    }

public:
    Server(): cert_file("bob.crt"), key_file("bobKey.pem")
    {
        server_socket = create_socket();

        /* Ignore broken pipe signals */
        signal(SIGPIPE, SIG_IGN);

        /* Create a new SSL context for the server */
        // ctx = create_context();
        // configure_context();
    }

    ~Server()
    {
        close(server_socket);
        // SSL_CTX_free(ctx);
    }

    void run()
    {
        std::cout << "Server is running..." << std::endl;
        
        /* Handle connections */
        while(true){
            accept_connection();
            std::cout << "Client Connected" << std::endl;

            // Fork process to handle both read and write
            pid_t pid = fork();
            if(pid == 0){
                // Child process
                read_from_client();
            }
            else{
                // Parent process
                write_to_client();
            }
            close(client);
        }
    }
};

#endif