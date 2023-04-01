#ifndef SERVER_TLS_H
#define SERVER_TLS_H

#include <iostream>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_PORT 4431

class Server
{
private:
	int serverSocket;  // socket descriptor
	int server_port;   // port of the server
	bool is_connected; // flag to check if the client is connected to the server

	BIO *bio; // BIO object (wrapper for socket)

	// SSL variables
	SSL_CTX *ssl_ctx; // SSL context
	SSL *ssl;		  // SSL object


	// Protocol function
	bool handle_protocol_message(std::string message);

	// Connection functions
	void create_socket();

	// SSL functions
	void init_openssl();
	void load_certificate();
	void upgrade_connection();
	void cleanup_openssl();

public:
	Server(int server_port = SERVER_PORT);
	~Server();

	void run();

	// Functions to send and receive messages and accept connections
	void accept_connection();
	void send_message(std::string message);
	std::string receive_message();
};

// Constructor to initialize the server and create a TCP socket
Server::Server(int server_port)
	: server_port(server_port)
{
	// Create a socket
	create_socket();
}

// Destructor to close the connection
Server::~Server()
{
	close(serverSocket);
}

void Server::run()
{
	init_openssl();
	load_certificate();

	while (true)
	{
		// Accept a connection from the client
		accept_connection();

		// Upgrade the connection to TLS
		// upgrade_connection();

		// Start the chat
		int child_pid = fork();
		if (child_pid == 0)
		{
			// Read messages from the server and send them to the client
			while (is_connected)
			{
				std::string message;
				std::getline(std::cin, message);
				send_message(message);
			}
		}
		else
		{
			// Read messages from the client and print them to the console
			while (is_connected)
			{
				std::string message = receive_message();
				if (!handle_protocol_message(message))
					std::cout << "Client: " << message << std::endl;
			}
			kill(child_pid, SIGKILL); // Kill the read process waiting for input from server
		}
		std::cout << "Client disconnected" << std::endl;
	}
}

void Server::create_socket()
{
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(server_port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	serverSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (serverSocket < 0)
	{
		perror("Unable to create socket");
		exit(EXIT_FAILURE);
	}

	if (bind(serverSocket, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		perror("Unable to bind");
		exit(EXIT_FAILURE);
	}

	if (listen(serverSocket, 1) < 0)
	{
		perror("Unable to listen");
		exit(EXIT_FAILURE);
	}

	std::cout << "Server started on port " << server_port << std::endl;
}

void Server::accept_connection()
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

	int client = accept(serverSocket, (struct sockaddr *)&addr, &len);
	if (client < 0)
	{
		perror("Unable to accept");
		exit(EXIT_FAILURE);
	}

	// Create a BIO object to wrap the socket
	bio = BIO_new_socket(client, BIO_NOCLOSE);
	if (bio == NULL)
	{
		perror("Unable to create BIO");
		exit(EXIT_FAILURE);
	}

	is_connected = true;
	std::cout << "Client connected" << std::endl;
}

void Server::send_message(std::string message)
{
	// Check if the client is connected
	if (!is_connected)
	{
		std::cout << "Client is not connected" << std::endl;
		return;
	}

	// Send the message to the client
	std::cout << "Sending message: " << message << std::endl;
	int msg_len = BIO_write(bio, message.c_str(), message.length());

	// Check if the message was sent successfully
	if (msg_len == 0)
	{
		is_connected = false;
		std::cout << "Client disconnected" << std::endl;
		exit(EXIT_FAILURE);
	}
	else if (msg_len < 0)
	{
		if (!BIO_should_retry(bio))
		{
			is_connected = false;
			std::cout << "Error sending message to client" << std::endl;
			exit(EXIT_FAILURE);
		}
		std::cout << "Retrying to send message" << std::endl;
		send_message(message);
	}
}

std::string Server::receive_message()
{
	// Check if the client is connected
	if (!is_connected)
	{
		std::cout << "Client is not connected" << std::endl;
		return "";
	}

	// Receive the message from the client
	char buffer[1024];
	int msg_len = BIO_read(bio, buffer, sizeof(buffer));

	// Check if the message was received successfully
	if (msg_len == 0)
	{
		is_connected = false;
		std::cout << "Client disconnected" << std::endl;
		exit(EXIT_FAILURE);
	}
	else if (msg_len < 0)
	{
		if (!BIO_should_retry(bio))
		{
			is_connected = false;
			std::cout << "Error receiving message from client" << std::endl;
			exit(EXIT_FAILURE);
		}
		std::cout << "Retrying to receive message" << std::endl;
		return receive_message();
	}

	std::string message(buffer, msg_len);
	std::cout << "Received message: " << message << std::endl;
	return message;
}

bool Server::handle_protocol_message(std::string message)
{
	if (message == "chat_hello")
		send_message("chat_ok_reply");
	else if (message == "chat_ok_reply")
		return true;
	else if (message == "chat_close")
	{
		send_message("chat_close_ok");
		is_connected = false;
	}
	else if (message == "chat_close_ok")
		is_connected = false;
	else if (message == "chat_START_SSL")
	{
		send_message("chat_START_SSL_ACK");
		upgrade_connection();
	}
	else if(message == "chat_START_SSL_NOT_SUPPORTED"){
		std::cout << "Peer doesnt support SSL, continuing with unsecure communication";
	}
	else
		return false;

	return true;
}

void Server::init_openssl()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
	ERR_load_BIO_strings();

	// Create a new SSL context
	ssl_ctx = SSL_CTX_new(TLS_server_method());

	// Check if the context was created successfully
	if (ssl_ctx == NULL)
	{
		perror("Unable to create SSL context");
		exit(EXIT_FAILURE);
	}

	// Sets the auto mode for Elliptic Curve Diffie-Hellman (ECDH) key exchange
	SSL_CTX_set_ecdh_auto(ctx, 1);

	std::cout << "SSL context created" << std::endl;
}

void Server::load_certificate()
{
	// Load the server certificate
	if (SSL_CTX_use_certificate_chain_file(ssl_ctx, "/home/ubuntu/bob_chain.pem") != 1)
	{
		std::cerr << "Error loading trust store" << std::endl;
		exit(EXIT_FAILURE);
	}

	// Load the client private key from file
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "/home/ubuntu/bobKey.pem", SSL_FILETYPE_PEM) != 1)
	{
		std::cerr << "Error loading private key" << std::endl;
		exit(EXIT_FAILURE);
	}

	// Verify private key matches client certificate
	if (SSL_CTX_check_private_key(ssl_ctx) != 1)
	{
		std::cerr << "Private key does not match the certificate public key" << std::endl;
		exit(EXIT_FAILURE);
	}

	std::cout << "Certificate loaded" << std::endl;
}

void Server::upgrade_connection()
{
	// Create a new SSL object
	ssl = SSL_new(ssl_ctx);

	// Check if the SSL object was created successfully
	if (ssl == NULL)
	{
		std::cerr << "Error creating SSL object" << std::endl;
		exit(EXIT_FAILURE);
	}

	// Set the BIO object to use the SSL object
	BIO_set_ssl(bio, ssl, BIO_NOCLOSE);

	// Set the SSL mode to auto retry
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	SSL_set_bio(ssl, bio, bio);

	// Set the SSL object to use the server certificate
	SSL_use_certificate(ssl, SSL_CTX_get0_certificate(ssl_ctx));

	// Set the SSL object to use the server private key
	SSL_use_PrivateKey(ssl, SSL_CTX_get0_privatekey(ssl_ctx));

	// Check if the private key matches the certificate
	if (SSL_check_private_key(ssl) != 1)
	{
		std::cerr << "Private key does not match the certificate public key" << std::endl;
		exit(EXIT_FAILURE);
	}

	// Perform the SSL handshake
	if (SSL_accept(ssl) <= 0)
	{
		std::cerr << "Error accepting SSL connection" << std::endl;
		printf("Error: %s", ERR_error_string(ERR_get_error(), NULL));
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	std::cout << "Connection upgraded to SSL" << std::endl;
}

void Server::cleanup_openssl()
{
	SSL_CTX_free(ssl_ctx);
	SSL_free(ssl);
}

#endif