
#include "found_ips.h"
#include <iostream>
#include <unordered_map>

using namespace std;


unordered_map<string, unordered_map<string, string>> active_ips;
string unk_vendor = "Unknown Vendor";

extern "C" void add_to_ip_list(char * ip, char * vendor, char interface_name[50]){
    if (ip!= NULL){
        if (vendor == NULL){
            active_ips[interface_name][ip] = unk_vendor;
        } else {
            active_ips[interface_name][ip] = vendor;
        }
    }
}

unordered_map<string, unordered_map<string, string>> get_ips_list(){
    return active_ips;
}
