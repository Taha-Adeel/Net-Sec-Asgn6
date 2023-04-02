#ifndef CLIENT_TLS_H
#define CLIENT_TLS_H

#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_PORT 4431

class Client
{
private:
	// Connection variables
	BIO *bio;					 // BIO object (wrapper for socket)
	std::string server_hostname; // hostname of the server
	int server_port;			 // port of the server
	bool is_connected;			 // flag to check if the client is connected to the server

	// SSL variables
	SSL_CTX *ssl_ctx; // SSL context
	SSL *ssl;		  // SSL object

	// Protocol function
	bool handle_protocol_message(std::string message);

	// Handshakes
	void hello_handshake();
	void ssl_handshake(){};

	// TLS functions
	void init_openssl();
	void load_certificate();
	void upgrade_connection();

public:
	Client(std::string server_hostname, int server_port = SERVER_PORT);
	~Client();

	void run();

	// Connection functions
	void connect_to_server();

	// Functions to send and receive messages
	void send_message(std::string message);
	std::string receive_message();
};

// Constructor to initialize the client and establish a TCP connection to the server
Client::Client(std::string server_hostname, int server_port)
	: server_hostname(server_hostname), server_port(server_port)
{
}

// Destructor to close the connection
Client::~Client()
{
	BIO_free_all(bio);
	SSL_CTX_free(ssl_ctx);
	SSL_free(ssl);
}

// Run the client
void Client::run()
{
	// Open the connection to the server
	connect_to_server();

	std::cout << "Client started" << std::endl;

	// Perform the hello handshake
	hello_handshake();

	// int temp; std::cin >> temp;
	// 	init_openssl();
	// load_certificate();
	// upgrade_connection();

	// Start the chat
	int child_pid = fork();
	if (child_pid == 0)
	{
		// Read messages from the user and send them to the server
		while (is_connected)
		{
			std::string message;
			std::getline(std::cin, message);
			send_message(message);
		}
	}
	else
	{
		// Read messages from the server and print them to the console
		while (is_connected)
		{
			std::string message = receive_message();
			if (!handle_protocol_message(message))
				std::cout << "Server: " << message << std::endl;
		}
		kill(child_pid, SIGKILL); // Kill the child process waiting for user input
	}

	std::cout << "Client stopped" << std::endl;
}

// Open a connection to the server
void Client::connect_to_server()
{
	// Creates a new BIO object and connects to the server
	bio = BIO_new_connect((server_hostname + ":" + std::to_string(server_port)).c_str());

	// Check if the BIO object was created successfully
	if (bio == NULL)
	{
		std::cerr << "Error creating BIO object" << std::endl;
		exit(EXIT_FAILURE);
	}

	// Check if the connection was successful
	if (BIO_do_connect(bio) <= 0)
	{
		std::cerr << "Error connecting to server" << std::endl;
		exit(EXIT_FAILURE);
	}

	is_connected = true;
	std::cout << "Connected to server" << std::endl;
}

// Wrapper function to send a message to the server
void Client::send_message(std::string message)
{
	// Check if the client is connected to the server
	if (!is_connected)
	{
		std::cerr << "Client is not connected to the server" << std::endl;
		exit(EXIT_FAILURE);
	}

	// Send the message to the server
	std::cout << "Sending message: " << message << std::endl;
	int msg_len = BIO_write(bio, message.c_str(), message.length());

	// Check if the message was sent successfully
	if (msg_len == 0)
	{
		is_connected = false;
		std::cerr << "Server connection is closed" << std::endl;
		exit(EXIT_FAILURE);
	}
	else if (msg_len < 0)
	{
		if (!BIO_should_retry(bio))
		{
			std::cerr << "Error sending message to server" << std::endl;
			exit(EXIT_FAILURE);
		}
		// Handle retry
		std::cout << "Retrying to send message" << std::endl;
		send_message(message);
	}
}

// Wrapper function to receive a message from the server
std::string Client::receive_message()
{
	// Check if the client is connected to the server
	if (!is_connected)
	{
		std::cerr << "Client is not connected to the server" << std::endl;
		exit(EXIT_FAILURE);
	}

	// Receive the message from the server
	char buffer[1024];
	int msg_len = BIO_read(bio, buffer, sizeof(buffer));

	// Check if the message was received successfully
	if (msg_len == 0)
	{
		is_connected = false;
		std::cerr << "Server connection is closed" << std::endl;
		exit(EXIT_FAILURE);
	}
	else if (msg_len < 0)
	{
		if (!BIO_should_retry(bio))
		{
			std::cerr << "Error receiving message from server" << std::endl;
			exit(EXIT_FAILURE);
		}
		// Handle retry
		return receive_message();
	}

	std::string message(buffer, msg_len);
	std::cout << "Received message: " << message << std::endl;
	return message;
}

// Handle the protocol messages
bool Client::handle_protocol_message(std::string message)
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
	else if (message == "chat_START_SSL_ACK")
	{
		init_openssl();
		load_certificate();
		upgrade_connection();
	}
	else if (message == "chat_START_SSL_NOT_SUPPORTED")
	{
		std::cout << "Peer doesnt support SSL, continuing with unsecure communication";
	}
	else
		return false;

	return true;
}

// Perform the hello handshake
void Client::hello_handshake()
{
	send_message("chat_hello");
	std::string response = receive_message();
	if (response != "chat_ok_reply")
	{
		std::cerr << "Hello handshake failed" << std::endl;
		exit(EXIT_FAILURE);
	}

	std::cout << "Hello handshake successful" << std::endl;
}

void Client::init_openssl()
{
	// Initialize OpenSSL
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_ssl_algorithms();

	// Create a new SSL context and set the version to TLSv1.2
	ssl_ctx = SSL_CTX_new(TLS_client_method());

	// Check if the SSL context was created successfully
	if (ssl_ctx == NULL)
	{
		std::cerr << "Error creating SSL context" << std::endl;
		exit(EXIT_FAILURE);
	}

	// Sets the auto mode for Elliptic Curve Diffie-Hellman (ECDH) key exchange
	SSL_CTX_set_ecdh_auto(ctx, 1);

	std::cout << "OpenSSL initialized" << std::endl;
}

// Load the client certificate and private key
void Client::load_certificate()
{
	// Load the client certificate
	if (SSL_CTX_use_certificate_chain_file(ssl_ctx, "/home/ubuntu/alice_chain.pem") != 1)
	{
		std::cerr << "Error loading trust store" << std::endl;
		exit(EXIT_FAILURE);
	}

	// Load the client private key from file
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "/home/ubuntu/aliceKey.pem", SSL_FILETYPE_PEM) != 1)
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

	std::cout << "Client certificate and private key loaded" << std::endl;
}

void Client::upgrade_connection()
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

	// Set the SSL to use the client certificate and private key
	SSL_use_certificate(ssl, SSL_CTX_get0_certificate(ssl_ctx));
	SSL_use_PrivateKey(ssl, SSL_CTX_get0_privatekey(ssl_ctx));

	// Create a new SSL connection
	if (SSL_connect(ssl) != 1)
	{
		std::cerr << "Error creating SSL connection" << std::endl;
		printf("Error: %s", ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}

	// Check the certificate
	X509 *cert = SSL_get_peer_certificate(ssl);
	if (cert == NULL)
	{
		std::cerr << "Error getting certificate from server" << std::endl;
		exit(EXIT_FAILURE);
	}

	// Verify the certificate
	if (SSL_get_verify_result(ssl) != X509_V_OK)
	{
		std::cerr << "Certificate verification failed" << std::endl;
		exit(EXIT_FAILURE);
	}

	// Free the certificate
	X509_free(cert);

	std::cout << "SSL connection established" << std::endl;
}

#endif