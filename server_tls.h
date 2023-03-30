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

class Server{
private:
	int serverSocket; 	// socket descriptor
	int server_port; 	// port of the server
	bool is_connected;	// flag to check if the client is connected to the server

	BIO *bio;			// BIO object (wrapper for socket)

	// Wrapper functions to send and receive messages
	void send_message(std::string message);
	std::string receive_message();

	// Protocol function
	bool handle_protocol_message(std::string message);

	void create_socket();
	void accept_connection();


public:
	Server(int server_port = SERVER_PORT);
	~Server();

	void run();
};

// Constructor to initialize the server and create a TCP socket
Server::Server(int server_port)
	: server_port(server_port)
{
	// Create a socket
	create_socket();
}

// Destructor to close the connection
Server::~Server(){
	// Close the socket
	close(serverSocket);
}

void Server::run(){
	while(true){
		// Accept a connection from the client
		accept_connection();

		// Start the chat
		int child_pid = fork();
		if(child_pid == 0){
			// Read messages from the server and send them to the client
			while(is_connected){
				std::string message;
				std::getline(std::cin, message);
				send_message(message);
			}
		}
		else{
			// Read messages from the client and print them to the console
			while(is_connected){
				std::string message = receive_message();
				if(!handle_protocol_message(message))
					std::cout << "Client: " << message << std::endl;
			}
			kill(child_pid, SIGKILL); // Kill the read process waiting for input from server
		}
		std::cout << "Client disconnected" << std::endl;
	}
}

void Server::create_socket(){
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(server_port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	serverSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (serverSocket < 0){
		perror("Unable to create socket");
		exit(EXIT_FAILURE);
	}

	if (bind(serverSocket, (struct sockaddr *)&addr, sizeof(addr)) < 0){
		perror("Unable to bind");
		exit(EXIT_FAILURE);
	}

	if (listen(serverSocket, 1) < 0){
		perror("Unable to listen");
		exit(EXIT_FAILURE);
	}

	std::cout << "Server started on port " << server_port << std::endl;
}

void Server::accept_connection(){
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

	int client = accept(serverSocket, (struct sockaddr *)&addr, &len);
	if (client < 0){
		perror("Unable to accept");
		exit(EXIT_FAILURE);
	}

	// Create a BIO object to wrap the socket
	bio = BIO_new_socket(client, BIO_NOCLOSE);
	if(bio == NULL){
		perror("Unable to create BIO");
		exit(EXIT_FAILURE);
	}

	is_connected = true;
	std::cout << "Client connected" << std::endl;
}

void Server::send_message(std::string message){
	// Check if the client is connected
	if(!is_connected){
		std::cout << "Client is not connected" << std::endl;
		return;
	}

	// Send the message to the client
	std::cout << "Sending message: " << message << std::endl;
	int msg_len = BIO_write(bio, message.c_str(), message.length());

	// Check if the message was sent successfully
	if(msg_len == 0){
		is_connected = false;
		std::cout << "Client disconnected" << std::endl;
		exit(EXIT_FAILURE);
	}
	else if(msg_len < 0){
		if(!BIO_should_retry(bio)){
			is_connected = false;
			std::cout << "Error sending message to client" << std::endl;
			exit(EXIT_FAILURE);
		}
		std::cout << "Retrying to send message" << std::endl;
		send_message(message);
	}
}

std::string Server::receive_message(){
	// Check if the client is connected
	if(!is_connected){
		std::cout << "Client is not connected" << std::endl;
		return "";
	}

	// Receive the message from the client
	char buffer[1024];
	int msg_len = BIO_read(bio, buffer, sizeof(buffer));

	// Check if the message was received successfully
	if(msg_len == 0){
		is_connected = false;
		std::cout << "Client disconnected" << std::endl;
		exit(EXIT_FAILURE);
	}
	else if(msg_len < 0){
		if(!BIO_should_retry(bio)){
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

bool Server::handle_protocol_message(std::string message){
	if(message == "chat_hello")
		send_message("chat_ok_reply");
	else if(message == "chat_ok_reply")
		return true;
	else if(message == "chat_close"){
		send_message("chat_close_ok");
		is_connected = false;
	}
	else if(message == "chat_close_ok")
		is_connected = false;
	else
		return false;

	return true;
}

#endif