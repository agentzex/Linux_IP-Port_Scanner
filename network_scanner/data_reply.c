

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "misc.h"
#include "data_al.h"


/* Pointers to hold list data */
struct data_registry *first_reply, *last_reply;

/* Pointer to handle list */
struct data_registry *current_reply;

/* Registry data counter */
struct data_counter reply_count;

/* Screen printing buffers */
char line[300], tline[300];
extern char blank[];


/* Initialize required data */
void reply_init()
{
   first_reply = NULL;
   last_reply = NULL;
}

/* Used to beging the iteration between registries */
void reply_beginning_registry() { current_reply = first_reply; }

/* Go to next registry */
void reply_next_registry(void) { current_reply = current_reply->next; }

/* Return current registry mainly to check if its null */
struct data_registry *reply_current_reply(void) { return current_reply; }

/* Return hosts count */
int reply_hosts_count(void) { return reply_count.hosts; }



/* Add new data to the registry list */
void reply_add_registry(struct data_registry *registry)
{
   int i = 0;

   _data_unique.add_registry(registry);

   if ( first_reply == NULL )
   {
      reply_count.hosts++;
      search_mac(registry);

      first_reply = registry;
      last_reply = registry;

   } else {

      struct data_registry *tmp_registry;
      tmp_registry = first_reply;

      /* Check for dupe packets */
      while ( tmp_registry != NULL && i != 1 ) {

         if ( ( strcmp(tmp_registry->sip, registry->sip) == 0 ) &&
            ( memcmp(tmp_registry->header->smac, registry->header->smac, 6) == 0 ) ) {

            tmp_registry->count++;
            tmp_registry->header->length += registry->header->length;

            i = 1;
         }

         tmp_registry = tmp_registry->next;
      }

      /* Add it if isnt dupe */
      if ( i != 1 ) {

         reply_count.hosts++;
         search_mac(registry);

         last_reply->next = registry;
         last_reply = registry;
      }
   }

   reply_count.pakets++;
   reply_count.length += registry->header->length;

}


/* Arp reply data abstraction functions */
const struct data_al _data_reply = {
   reply_init,
   reply_beginning_registry,
   reply_next_registry,
   reply_current_reply,
   reply_add_registry,
   reply_hosts_count
};
