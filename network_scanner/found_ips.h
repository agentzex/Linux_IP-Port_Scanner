

#ifndef UNTITLED_FOUND_IPS_H
#define UNTITLED_FOUND_IPS_H


#ifdef __cplusplus
#include <unordered_map>

std::unordered_map<std::string, std::unordered_map<std::string, std::string>> get_ips_list();

extern "C" {
#endif

void add_to_ip_list(char * ip, char * vendor, char interface_name[50]);

#ifdef __cplusplus
}
#endif


#endif //UNTITLED_FOUND_IPS_H
