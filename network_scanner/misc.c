
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <netinet/ether.h>

#include "ifaces.h"
#include "misc.h"
#include "oui.h"


/* optional table/list of MAC addresses of known hosts */
char **known_mac_table;


char *search_vendor(unsigned char mac[6])
{
	char tmac[7];
	int i = 0;
	
	sprintf(tmac, "%02x%02x%02x", mac[0], mac[1], mac[2]);

	/* Convert mac prefix to upper */
	for (i=0; i<6; i++)
	   tmac[i] = toupper(tmac[i]);
	
	i = 0;

	while (oui_table[i].prefix != NULL)
	{
		if (strcmp(oui_table[i].prefix, tmac) == 0)
			return oui_table[i].vendor;
        	i++;
	}
	
	return "Unknown vendor";
}


char *get_known_mac_hostname(char *mac_hostname)
{
	if (strlen(mac_hostname) != 12) {
	    /* error in MACs table content */
	    return NULL;
	}

	/* skip MAC and all '\0' */
	mac_hostname += 12;
	while (*mac_hostname == '\0') mac_hostname++;

	return mac_hostname;
}


/* find out known host name */
char *search_known_mac(unsigned char mac[6])
{
	char tmac[13];
	int i;

	/* protection */
	if (known_mac_table == NULL)
      return NULL;

	sprintf(tmac, "%02x%02x%02x%02x%02x%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	/* Convert mac to upper */
	for (i=0; i<12; i++)
	   tmac[i] = toupper(tmac[i]);

	i = 0;

	while (known_mac_table[i] != NULL) {
      
		if (strcmp(known_mac_table[i]/*separated MAC*/, tmac) == 0)
			return get_known_mac_hostname(known_mac_table[i]);
      i++;
	}

	return NULL;
}


/* First try find out known host name, otherwise use standard vendor */
void search_mac(struct data_registry *registry)
{
   registry->vendor = search_known_mac(registry->header->smac);

   if (registry->vendor == NULL) {
      registry->vendor = search_vendor(registry->header->smac);
      registry->focused = 0;	/* unidentified host, vendor used */
    } else {
      registry->focused = 1; /* identified host, hostname used */
    }
}

