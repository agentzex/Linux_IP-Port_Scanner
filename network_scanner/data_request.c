
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "misc.h"
#include "data_al.h"


/* Pointers to hold list data */
struct data_registry *request_first, *request_last;

/* Pointer to handle list */
struct data_registry *request_current;

/* Registry data counter */
struct data_counter request_count;

/* Screen printing buffers */
char line[300], tline[300];
extern char blank[];


/* Initialize required data */
void request_init()
{
   request_first = NULL;
   request_last = NULL;
}

/* Used to beging the iteration between registries */
void request_beginning_registry() { request_current = request_first; }

/* Go to next registry */
void request_next_registry(void) { request_current = request_current->next; }

/* Return current registry mainly to check if its null */
struct data_registry *request_current_registry(void) {return request_current;}

/* Return hosts count */
int request_hosts_count(void) { return request_count.hosts; }



/* Add new data to the registry list */
void request_add_registry(struct data_registry *registry)
{
   int i = 0;

   _data_unique.add_registry(registry);

   if ( request_first == NULL )
   {
      request_count.hosts++;
      search_mac(registry);

      request_first = registry;
      request_last = registry;

   } else {

      struct data_registry *tmp_request;
      tmp_request = request_first;

      /* Check for dupe packets */
      while ( tmp_request != NULL && i != 1 ) {

         if ( ( strcmp(tmp_request->sip, registry->sip) == 0 ) &&
            ( strcmp(tmp_request->dip, registry->dip) == 0 ) &&
            ( memcmp(tmp_request->header->smac, registry->header->smac, 6) == 0 ) ) {

            tmp_request->count++;
            tmp_request->header->length += registry->header->length;

            i = 1;
         }

         tmp_request = tmp_request->next;
      }

      /* Add it if isnt dupe */
      if ( i != 1 ) {

         request_count.hosts++;
         search_mac(registry);

         request_last->next = registry;
         request_last = registry;
      }
   }

   request_count.pakets++;
   request_count.length += registry->header->length;

}




/* Arp reply data abstraction functions */
const struct data_al _data_request = {
   request_init,
   request_beginning_registry,
   request_next_registry,
   request_current_registry,
   request_add_registry,
   request_hosts_count
};
