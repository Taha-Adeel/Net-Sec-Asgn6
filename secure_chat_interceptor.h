#ifndef INTERCEPT_SERVER_TLS
#define INTERCEPT_SERVER_TLS

#include "server_tls.h"

class Interceptor_server : protected Server
{
private:
    bool handle_protocol_message(std::string message);

public:
    Interceptor_server(int server_port = SERVER_PORT) : Server(server_port);
};

Interceptor_server::Interceptor_server(int server_port) : Server(server_port)
{
}

bool Interceptor_server::handle_protocol_message(std::string message)
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
    else
        return false;

    return true;
}

class Interceptor
{
private:
    Interceptor_server server;
    Client Interceptor_client;
};

#endif