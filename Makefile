all: push build

push:
	lxc file push secure_chat_app.cpp server_tls.h client_tls.h alice.crt aliceKey.pem alice1/home/ubuntu/
	lxc file push secure_chat_app.cpp server_tls.h client_tls.h bob.crt bobKey.pem bob1/home/ubuntu/
	lxc file push secure_chat_interceptor.cpp server_tls.h client_tls.h trudy1/home/ubuntu/

build:
	lxc exec alice1 -- bash -c "cd /home/ubuntu/ && g++ -o secure_chat_app secure_chat_app.cpp -lssl -lcrypto -lpthread"
	lxc exec bob1 -- bash -c "cd /home/ubuntu/ && g++ -o secure_chat_app secure_chat_app.cpp -lssl -lcrypto -lpthread"
	lxc exec trudy1 -- bash -c "cd /home/ubuntu/ && g++ -o secure_chat_interceptor secure_chat_interceptor.cpp -lssl -lcrypto -lpthread"

clean:
	lxc exec alice1 -- bash -c "cd /home/ubuntu/ && rm -f secure_chat_app"
	lxc exec bob1 -- bash -c "cd /home/ubuntu/ && rm -f secure_chat_app"
	lxc exec trudy1 -- bash -c "cd /home/ubuntu/ && rm -f secure_chat_interceptor"