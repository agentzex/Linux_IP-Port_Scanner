
#ifndef UNTITLED_PORTS_SCANNER_H
#define UNTITLED_PORTS_SCANNER_H


struct thread_addr {
    char host[INET_ADDRSTRLEN];
    int port;
    int thread_id;
};

void ports_scanner(const char * ip);

void *scan_port(void *args);

bool scanner(const char * ip, int port);




#endif //UNTITLED_PORTS_SCANNER_H
