# Sniffer
Sniffer in c combining with python via ctypes


run

	gcc -o packet_sniffer sniffer_complex.c -Wall

	sudo ./packet_sniffer

	gcc -o packet_capture sniffer2.c -lpcap 

	sudo setcap cap_net_raw+eip ./packet_capture 

	./packet_capture -t 30 -o capture.tx