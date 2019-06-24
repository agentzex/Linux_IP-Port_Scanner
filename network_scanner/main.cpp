#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <vector>
#include <unordered_map>
#include <iostream>
#include <signal.h>
#include <iomanip>
#include <netdb.h>
#include <sys/fcntl.h>
#include <errno.h>

#include "ifaces.h"
#include "misc.h"
#include "found_ips.h"
#include "ports_scanner.h"





using namespace std;

pthread_t sniffer;

string get_subnet(string &subnet_mask)
{
    //currently supporting only whole class A, B, or C private networks
    string sub;
    if (subnet_mask == "255.255.255.0")
        sub = "24";
    else if (subnet_mask == "255.255.0.0")
        sub = "16";
    else if (subnet_mask == "255.0.0.0")
        sub = "8";
    else
        sub = "0";
    return sub;
}


void get_interfaces(vector< unordered_map<string, string> > &interfaces)
{
    //prints ips and subnet masks

    struct ifaddrs * ifAddrStruct=NULL;
    struct ifaddrs * ifa=NULL;
    void * tmpAddrPtr=NULL;
    unordered_map<string, string> interface;
    string sub;

    getifaddrs(&ifAddrStruct);

    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) {
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET)
        {
            // if valid IP4 Address
            tmpAddrPtr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
            interface["ip"] = addressBuffer;
            interface["name"] = ifa->ifa_name;

            if(ifa->ifa_netmask != NULL)
            {
                tmpAddrPtr = &((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr;
                inet_ntop(ifa->ifa_netmask->sa_family,tmpAddrPtr,addressBuffer,sizeof(addressBuffer));
                interface["subnet"] = addressBuffer;
                sub = get_subnet(interface["subnet"]);
                interface["sub"] = sub;
            }
            interfaces.push_back(interface);
            cout << "Name: " << interface["name"] << endl << "IP: " << interface["ip"] << endl << "Subnet: " << interface["subnet"]
                 << endl << endl;
        }
    }
    if (ifAddrStruct!=NULL)
        freeifaddrs(ifAddrStruct);

}


void scan_net(char const *start_ip, char const *source_ip)
{
    //sends arp requests to each of the hosts in the subnet
    int x, j;
    char test[16];
    char fromip[16];
    sprintf(fromip,"%s.%s", start_ip, source_ip);

    for (j=1; j<255; j++){
        sprintf(test,"%s.%i", start_ip, j);
        forge_arp(fromip, test);
        //500000 - 0.5 seconds
        usleep(500000);
    }
}


void split_ip(string &ip, vector<string> &splitted_ip){
    //splits ip address to octets
    string delimiter = ".";
    size_t pos = 0;
    string token;
    while ((pos = ip.find(delimiter)) != string::npos) {
        token = ip.substr(0, pos);
        splitted_ip.push_back(token);
        ip.erase(0, pos + delimiter.length());
    }
    splitted_ip.push_back(ip);
}


void print_map(unordered_map<string, unordered_map<string, string>> const &ips_list)
{
    //prints the IP to Vendor map
    cout << endl;
    for (auto const  & interface : ips_list) {
        cout << "Found IPs for interface: " << interface.first << endl;
        cout << left << setw(30) << "IP" << setw(30) << "Vendor" << endl;
        for (auto const  & key : interface.second) {
            cout << left << setw(30) << key.first << setw(30) << key.second << endl;
        }
        cout << endl;
    }
    cout << endl;
}


int main (int argc, const char * argv[])
{

    int i;
    int k;
    struct t_data datos;

    /* Some default values for the program options.  */
    datos.source_ip = NULL;
    datos.interface = NULL;
    datos.pcap_filter = NULL;

    _data_reply.init();
    _data_request.init();
    _data_unique.init();

    /* Init mutex */
    data_access = (pthread_mutex_t *)malloc(sizeof (pthread_mutex_t));
    pthread_mutex_init(data_access, NULL);

    vector<string> splitted_ip;
    unordered_map<string, unordered_map<string, string>> ips_list;
    vector< unordered_map<string, string> > interfaces;
    string start_ip;
    int interface_ret;

    cout << "Finding out interfaces of host machine" << endl;
    get_interfaces(interfaces);
    cout << "*********************" << endl;

    cout << "Scanning IPs for each interface" << endl << endl;
    for (auto &&interface : interfaces){
        if (interface["ip"] == "127.0.0.1"){
            cout << "Skipping interface: " << interface["name"] << endl;
            continue;
        }
        interface_ret = inject_init(interface["name"].c_str());
        if (interface_ret == -1){
            continue;
        }
        datos.interface = interface["name"].c_str();
        //starting the sniffer thread which will listen for incmoing arp replies from broadcasts
        pthread_create(&sniffer, NULL, start_sniffer, (void *)&datos);

        split_ip(interface["ip"], splitted_ip);
        //starting the scan, based on the subnet, the amount of hosts to scan is decided
        cout << "Scanning IPs on interface: " << interface["name"] << endl;
        if (interface["sub"] == "24") {
            start_ip = splitted_ip[0] + '.' + splitted_ip[1] + '.' + splitted_ip[2];
            scan_net(start_ip.c_str(), interface["ip"].c_str());
        }
        else if (interface["sub"] == "16"){
            start_ip = splitted_ip[0] + '.' + splitted_ip[1];
            for (i=0; i<256; i++) {
                scan_net(start_ip.c_str(), interface["ip"].c_str());
            }
        }
        else if (interface["sub"] == "8"){
            start_ip = splitted_ip[0];
            for (k=0; k<256; k++){
                for (i=0; i<256; i++){
                    scan_net(start_ip.c_str(), interface["ip"].c_str());
                }
            }
        }
        else {
            cout << "Error: network subnet mask not supported" << endl;
            return -1;
        }

        //finishing the pcap listening thread
        break_pcap_loop();
        inject_destroy();
        pthread_join(sniffer,NULL);
        sleep(1);
        cout << "Interface: " << interface["name"] << " IPs scan finished" << endl;
        cout << "*********************" << endl;

    }

    //printing the found ips
    ips_list = get_ips_list();
    print_map(ips_list);

    cout << "*********************" << endl;
    cout << "Scanning ports for each found IP" << endl << endl;

    //write ports table to stdout
    cout << left << setw(30) << "IP" << setw(30) << "Port" << setw(30) << "Status" <<  endl;

    for (auto const  & interface : ips_list) {
        for (auto const  & key : interface.second) {
            ports_scanner(key.first.c_str());
            cout << endl;
        }
    }

    return 0;
}
