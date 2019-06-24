
#ifndef _MISC_H
#define _MISC_H

#include "data_al.h"

#ifdef __cplusplus
extern "C"
{
#endif

    char *search_vendor(unsigned char[6]);
    void search_mac(struct data_registry *);
	
#ifdef __cplusplus
}
#endif

#endif /* _MISC_H */
