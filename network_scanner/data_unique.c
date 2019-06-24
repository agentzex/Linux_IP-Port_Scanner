#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include "misc.h"
#include "data_al.h"


/* Pointers to hold list data */
struct data_registry *first_unique, *last_unique;

/* Pointer to handle list */
struct data_registry *current_unique;

/* Registry data counter */
struct data_counter unique_count;

/* Screen printing buffers */
char line[300], tline[300];
extern char blank[];


/* Initialize required data */
void unique_init()
{
   first_unique = NULL;
   last_unique = NULL;
}

/* Used to beging the iteration between registries */
void unique_beginning_registry() { current_unique = first_unique; }

/* Go to next registry */
void unique_next_registry(void) { current_unique = current_unique->next; }

/* Return current registry mainly to check if its null */
struct data_registry *unique_current_unique(void) { return current_unique; }

/* Return hosts count */
int unique_hosts_count(void) { return unique_count.hosts; }



/* Add new data to the registry list */
void unique_add_registry(struct data_registry *registry)
{
   int i = 0;
   struct data_registry *new_data;


   if ( first_unique == NULL )
   {
      /* Duplicate this registry, as the pointer is being used by rep/req al */
      new_data = (struct data_registry *) malloc (sizeof(struct data_registry));
      *new_data = *registry;

      unique_count.hosts++;
      search_mac(new_data);

      first_unique = new_data;
      last_unique = new_data;


   } else {

      struct data_registry *tmp_registry;
      tmp_registry = first_unique;

      /* Check for dupe packets */
      while ( tmp_registry != NULL && i != 1 ) {

         if ( ( strcmp(tmp_registry->sip, registry->sip) == 0 ) &&
            ( memcmp(tmp_registry->header->smac, registry->header->smac, 6) == 0 ) ) {

            tmp_registry->count++;
            tmp_registry->tlength += registry->header->length;

            i = 1;
         }

         tmp_registry = tmp_registry->next;
      }

      /* Add it if isnt dupe */
      if ( i != 1 ) {

         /* Duplicate this registry, as the pointer is being used by rep/req al */
         new_data = (struct data_registry *) malloc (sizeof(struct data_registry));
         *new_data = *registry;

         unique_count.hosts++;
         search_mac(new_data);

         last_unique->next = new_data;
         last_unique = new_data;
      }
   }

   unique_count.pakets++;
   unique_count.length += registry->header->length;
}


/* Arp reply data abstraction functions */
const struct data_al _data_unique = {
   unique_init,
   unique_beginning_registry,
   unique_next_registry,
   unique_current_unique,
   unique_add_registry,
   unique_hosts_count,
};

