#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <iomanip>

#include "ports_scanner.h"

using namespace std;


void *scan_port(void *args)
{
    struct thread_addr *my_args;
    bool status;
    string is_active;
    my_args = (struct thread_addr *)args;
    status = scanner(my_args->host, my_args->port);
    if (status){
        is_active = "Active";
    }
    else {
        is_active = "Inactive";
    }
    cout << left << setw(30) << my_args->host << setw(30) << my_args->port << setw(30) << is_active << endl;
    return NULL;
}


void ports_scanner(const char * ip){
    pthread_t threads[4];
    struct thread_addr args[4];
    int thread_id;
    char host[INET_ADDRSTRLEN];
    unsigned int ports[] = {20,23,80,443};

    strncpy(host, ip, (size_t) INET_ADDRSTRLEN);

    //Loop through the ports.
    for (thread_id = 0; thread_id < 4; thread_id++) {
        //Set the host, port and thread ID.
        strncpy(args[thread_id].host, host, (size_t) INET_ADDRSTRLEN);
        args[thread_id].port = ports[thread_id];
        args[thread_id].thread_id = thread_id;

        if (pthread_create(&threads[thread_id], NULL, scan_port, (void *) &args[thread_id])) {
            continue;
        };
        pthread_join(threads[thread_id],NULL);
    }
}


bool scanner(const char * ip, int port){
    struct sockaddr_in addr_s;
    short int fd = -1;
    fd_set fdset;
    struct timeval tv;
    int rc;
    int so_error;
    socklen_t len;
    int seconds = 1; //timeout for socket connection in seconds

    addr_s.sin_family = AF_INET;
    addr_s.sin_addr.s_addr = inet_addr(ip);
    addr_s.sin_port = htons(port);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    fcntl(fd, F_SETFL, O_NONBLOCK); // setup non blocking socket

    // make the connection
    rc = connect(fd, (struct sockaddr *)&addr_s, sizeof(addr_s));
    if ((rc == -1) && (errno != EINPROGRESS)) {  //any connection failure that is not inprogress, we return false
        close(fd);
        return false;
    }
    if (rc == 0) {
        // connection has succeeded immediately
        close(fd);
        return true;
    }

    // connection attempt is in progress
    FD_ZERO(&fdset);
    FD_SET(fd, &fdset);
    tv.tv_sec = seconds; //setting the timeout for checking for successfull connection
    tv.tv_usec = 0;

    rc = select(fd + 1, NULL, &fdset, NULL, &tv); //using select() on the fd, to check if now the socket is ready
    if (rc){
        len = sizeof(so_error);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len); // if so_error holds 0 , the socket connection succeeded
        if (so_error == 0) {
            close(fd);
            return true;
        }
    }
    close(fd);
    return false;
}



