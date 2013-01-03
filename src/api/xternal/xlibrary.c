/***************************************************************************\
 * xlibrary.c - a hashtable implementation on top of a binary tree
 ***************************************************************************
 * Copyright  CEA/DAM/DIF (2009)
 *
 * Written by Matthieu Hautreux <matthieu.hautreux@cea.fr>
 * 
 * This software is a computer program whose purpose is to simplify
 * the addition of kerberos credential support in Batch applications.
 *
 * This software is governed by the CeCILL-C license under French law and
 * abiding by the rules of distribution of free software.  You can  use, 
 * modify and/ or redistribute the software under the terms of the CeCILL-C
 * license as circulated by CEA, CNRS and INRIA at the following URL
 * "http://www.cecill.info". 
 * 
 * As a counterpart to the access to the source code and  rights to copy,
 * modify and redistribute granted by the license, users are provided only
 * with a limited warranty  and the software's author,  the holder of the
 * economic rights,  and the successive licensors  have only  limited
 * liability. 
 * 
 * In this respect, the user's attention is drawn to the risks associated
 * with loading,  using,  modifying and/or developing or reproducing the
 * software by the user in light of its specific status of free software,
 * that may mean  that it is complicated to manipulate,  and  that  also
 * therefore means  that it is reserved for developers  and  experienced
 * professionals having in-depth computer knowledge. Users are therefore
 * encouraged to load and test the software's suitability as regards their
 * requirements in conditions enabling the security of their systems and/or 
 * data to be ensured and,  more generally, to use and operate it in the 
 * same conditions as regards security. 
 * 
 * The fact that you are presently reading this means that you have had
 * knowledge of the CeCILL-C license and that you accept its terms.
 ***************************************************************************
 * Copyright  CEA/DAM/DIF (2009)
 * 
 * Ecrit par Matthieu Hautreux <matthieu.hautreux@cea.fr>
 *
 * Ce logiciel est un programme informatique servant à faciliter l'ajout
 * du support des tickets Kerberos aux applications Batch.
 * 
 * Ce logiciel est régi par la licence CeCILL-C soumise au droit français et
 * respectant les principes de diffusion des logiciels libres. Vous pouvez
 * utiliser, modifier et/ou redistribuer ce programme sous les conditions
 * de la licence CeCILL-C telle que diffusée par le CEA, le CNRS et l'INRIA 
 * sur le site "http://www.cecill.info".
 * 
 * En contrepartie de l'accessibilité au code source et des droits de copie,
 * de modification et de redistribution accordés par cette licence, il n'est
 * offert aux utilisateurs qu'une garantie limitée.  Pour les mêmes raisons,
 * seule une responsabilité restreinte pèse sur l'auteur du programme,  le
 * titulaire des droits patrimoniaux et les concédants successifs.
 * 
 * A cet égard  l'attention de l'utilisateur est attirée sur les risques
 * associés au chargement,  à l'utilisation,  à la modification et/ou au
 * développement et à la reproduction du logiciel par l'utilisateur étant 
 * donné sa spécificité de logiciel libre, qui peut le rendre complexe à 
 * manipuler et qui le réserve donc à des développeurs et des professionnels
 * avertis possédant  des  connaissances  informatiques approfondies.  Les
 * utilisateurs sont donc invités à charger  et  tester  l'adéquation  du
 * logiciel à leurs besoins dans des conditions permettant d'assurer la
 * sécurité de leurs systèmes et ou de leurs données et, plus généralement, 
 * à l'utiliser et l'exploiter dans les mêmes conditions de sécurité. 
 * 
 * Le fait que vous puissiez accéder à cet en-tête signifie que vous avez 
 * pris connaissance de la licence CeCILL-C, et que vous en avez accepté les
 * termes. 
\***************************************************************************/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include <pthread.h>

#include <search.h>

#include <string.h>
#include <errno.h>
extern int errno;

/* directory lookup */
#include <dirent.h>
#include <sys/types.h>
#include <fnmatch.h>


/* logging */
#include "xlogger.h"

/* xfreelist */
#include "xfreelist.h"

#ifndef XLIBRARY_LOGHEADER
#define XLIBRARY_LOGHEADER "xlibrary: "
#endif

#ifndef XLIBRARY_VERBOSE_BASE_LEVEL
#define XLIBRARY_VERBOSE_BASE_LEVEL 7
#endif

#ifndef XLIBRARY_DEBUG_BASE_LEVEL
#define XLIBRARY_DEBUG_BASE_LEVEL   7
#endif

#define VERBOSE(h,a...) xverboseN(XLIBRARY_VERBOSE_BASE_LEVEL,XLIBRARY_LOGHEADER h,##a)
#define VERBOSE2(h,a...) xverboseN(XLIBRARY_VERBOSE_BASE_LEVEL + 1,XLIBRARY_LOGHEADER h,##a)
#define VERBOSE3(h,a...) xverboseN(XLIBRARY_VERBOSE_BASE_LEVEL + 2,XLIBRARY_LOGHEADER h,##a)

#define DEBUG(h,a...) xdebugN(XLIBRARY_DEBUG_BASE_LEVEL,XLIBRARY_LOGHEADER h,##a)
#define DEBUG2(h,a...) xdebugN(XLIBRARY_DEBUG_BASE_LEVEL + 1,XLIBRARY_LOGHEADER h,##a)
#define DEBUG3(h,a...) xdebugN(XLIBRARY_DEBUG_BASE_LEVEL + 2,XLIBRARY_LOGHEADER h,##a)

#define ERROR(h,a...) VERBOSE(h,##a)

#define INIT_DEBUG_MARK()    DEBUG("%s : entering",function_name)
#define EXIT_DEBUG_MARK(a)   DEBUG("%s : exiting with status %d",function_name,a)

#define INIT_DEBUG2_MARK()   DEBUG2("%s : entering",function_name)
#define EXIT_DEBUG2_MARK(a)  DEBUG2("%s : exiting with status %d",function_name,a)

#define INIT_DEBUG3_MARK()   DEBUG3("%s : entering",function_name)
#define EXIT_DEBUG3_MARK(a)  DEBUG3("%s : exiting with status %d",function_name,a)


#include "xlibrary.h"

#define STR_ERROR_SIZE 128
#define DUMP_ERROR(e,s,S) if(strerror_r(e,s,S)) { s[0]='-';s[1]='\0';}

/* reset item memory area and then release it to its freelist */
void _release_item(void* p);

/* used to print items during tree walk */
void _print_item(const void* node,const VISIT method,const int depth);

void _count_item(const void* node,const VISIT method,const int depth);
void _update_index(const void* node,const VISIT method,const int depth);

/* used to manage item into the tree (add, remove, balance,...) */
int _cmp_item_by_reference(const void* p1,const void* p2);

/**/
int
xlibrary_init(xlibrary_t* library,
	      size_t default_length,
	      size_t item_maxsize,
	      xlibrary_item_free_func_t f) {
  char* function_name="xlibrary_init";
  INIT_DEBUG2_MARK();
  
  int fstatus;
  
  size_t item_size=item_maxsize;
  
  library->root=NULL;
  library->item_nb=0;

  library->index=NULL;
  library->current=NULL;

  library->free_item=f;

  /* mutex initialization */
  fstatus=pthread_mutex_init(&(library->mutex),NULL);
  if(fstatus){
    ERROR("init: mutex initialization failed");
    fstatus=XERROR_MUTEX_INIT;
  }
  else{
    /* condition initialization */
    fstatus=pthread_cond_init(&(library->condition),NULL);
    if(fstatus){
      ERROR("init: condition initialization failed");
      fstatus=XERROR_CONDITION_INIT;
    }
    else{

      /* reference freelist initialization */
      fstatus=xfreelist_init(&(library->ref_freelist),default_length,sizeof(xlibrary_item_t));
      if(fstatus){
	ERROR("init: reference freelist initialization failed (%d*%d bytes)",default_length,sizeof(xlibrary_item_t));
	fstatus=XERROR_FREELIST_INIT;
      }
      else{

	/* object freelist initialization */
	fstatus=xfreelist_init(&(library->obj_freelist),default_length,item_size);
	if(fstatus){
	  ERROR("init: reference freelist initialization failed (%d*%d bytes)",default_length,item_size);
	  fstatus=XERROR_FREELIST_INIT;
	}
	else{

	  /* set success */
	  fstatus=XSUCCESS;
	  
	}
	/*_*/ /* object freelist init */

      }
      /*_*/ /* reference freelist init */

      /* an error occured - destroy condition */
      if(fstatus){
	pthread_cond_destroy(&(library->condition));
      }

    }
    /*_*/ /* condition init */
	
    /* an error occured - destroy mutex */
    if(fstatus){
      pthread_mutex_destroy(&(library->mutex));
    }

  }
  /*_*/ /* mutex init */
  
  EXIT_DEBUG2_MARK(fstatus);
  return fstatus;
}

/**/
int
xlibrary_free_contents(xlibrary_t* library){
  int fstatus;
  char* function_name="xlibrary_free_contents";
  INIT_DEBUG2_MARK();

  /* release credential repository items */
  tdestroy(library->root,_release_item);
  library->item_nb=0;

  /* clean index */
  if(library->index!=NULL){
    free(library->index);
    library->index=NULL;
  }
  library->current=NULL;

  /* condition destruction */
  pthread_cond_destroy(&(library->condition));

  /* mutex destruction */
  pthread_mutex_destroy(&(library->mutex));

  /* free reference freelist contents */
  xfreelist_free_contents(&(library->ref_freelist));

  /* free object freelist contents */
  xfreelist_free_contents(&(library->obj_freelist));
  
  fstatus=XSUCCESS;

  EXIT_DEBUG2_MARK(fstatus);
  return fstatus;
}


/**/
int
xlibrary_get_item(xlibrary_t* library,
		  char* reference,
		  void* item,
		  size_t item_size)
{
  char* function_name="xlibrary_get_item";
  INIT_DEBUG_MARK();


  int fstatus;

  /* lock repository */
  fstatus=pthread_mutex_lock(&(library->mutex));
  if(fstatus){
    ERROR("get_item: unable to get item referenced by '%s' : unable to lock repository",reference);
    fstatus=XERROR_MUTEX_LOCK;
  }
  else{
    /* push unlock method ( used if externaly canceled )*/
    pthread_cleanup_push((void (*)(void*))pthread_mutex_unlock,
			 (void*)(&(library->mutex)));

    /* call no lock method */
    fstatus=xlibrary_get_item_nolock(library,reference,item,item_size);
    
    /* pop unlock method */
    pthread_cleanup_pop(1); /*   pthread_mutex_unlock(&(library->mutex)) */
  }
  
  EXIT_DEBUG_MARK(fstatus);
  return fstatus;
}

/**/
int
xlibrary_get_item_nolock(xlibrary_t* library,
			 char* reference,
			 void* item,
			 size_t item_size)
{
  char* function_name="xlibrary_get_item_nolock";
  INIT_DEBUG2_MARK();

  int fstatus;
  
  xfreelist_item_t* pitem;
  xlibrary_item_t litem;
  
  /* set item reference */
  strncpy(litem.reference,reference,XLIBRARY_REFERENCE_MAXLENGTH);

  /* extract a working ref freelist item */
  fstatus=xfreelist_extract_item(&(library->ref_freelist),&pitem);
  if(fstatus){
    ERROR("add_item: unable to get working reference freelist item : object freelist is empty",reference);
    fstatus=XERROR_FREELIST_IS_EMPTY;
  }
  else{
    /* build working freelist item */
    memcpy(pitem->data,&litem,sizeof(xlibrary_item_t));
  
    /* look for corresponding item in the tree */
    void* result;
    result=tfind(pitem,&(library->root),_cmp_item_by_reference);
    if(result==NULL){
      ERROR("get_item: no item referenced by '%s' in tree",reference);
      fstatus=XERROR_LIBRARY_ITEM_NOT_FOUND;
    }
    else{
    
      /* extract object */
      memcpy(&litem,(*(xfreelist_item_t**)result)->data,sizeof(xlibrary_item_t));
      if ( litem.object == NULL ){
	fstatus=XERROR_LIBRARY_OBJECT_NOT_FOUND;
      }
      else {
	xfreelist_item_t* obj;
	obj=(xfreelist_item_t*)litem.object;
	memcpy(item,obj->data,item_size);
	VERBOSE3("get_item: item referenced by '%s' successfully got",litem.reference);
	fstatus=XSUCCESS;
	
      }
    
    }
    
    /* release working ref freelist item */
    xfreelist_release_item(&(library->ref_freelist),pitem);

  }
  /*_*/ /* extract a working ref freelist item */

  
  EXIT_DEBUG2_MARK(fstatus);
  return fstatus;
}

/**/
int
xlibrary_remove_item(xlibrary_t* library,
		     char* reference)
{
  char* function_name="xlibrary_remove_item";
  INIT_DEBUG_MARK();
  
  int fstatus;

  /* lock repository */
  fstatus=pthread_mutex_lock(&(library->mutex));
  if(fstatus){
    ERROR("remove_item: unable to remove item referenced by '%s' : unable to lock repository",reference);
    fstatus=XERROR_MUTEX_LOCK;
  }
  else{
    /* push unlock method ( used if externaly canceled )*/
    pthread_cleanup_push((void (*)(void*))pthread_mutex_unlock,
			 (void*)(&(library->mutex)));

    /* call nolock method */
    fstatus=xlibrary_remove_item_nolock(library,reference);

    /* pop unlock method */
    pthread_cleanup_pop(1); /*   pthread_mutex_unlock(&(library->mutex)) */
  }
  
  EXIT_DEBUG_MARK(fstatus);
  return fstatus;
}

/**/
int
xlibrary_remove_item_nolock(xlibrary_t* library,
			    char* reference)
{
  char* function_name="xlibrary_remove_item_nolock";
  INIT_DEBUG_MARK();

  int fstatus;

  xfreelist_item_t* item;
  xlibrary_item_t litem;

  /* set item reference */
  strncpy(litem.reference,reference,XLIBRARY_REFERENCE_MAXLENGTH);

  /* extract a working ref freelist item */
  fstatus=xfreelist_extract_item(&(library->ref_freelist),&item);
  if(fstatus){
    ERROR("remove_item: unable to get working reference freelist item : object freelist is empty",reference);
    fstatus=XERROR_FREELIST_IS_EMPTY;
  }
  else{
    void* result;

    /* build freelist item */
    memcpy(item->data,&litem,sizeof(xlibrary_item_t));
    
    /* look for corresponding item in the tree */
    result=tfind(item,&(library->root),_cmp_item_by_reference);
    if(result==NULL){
      ERROR("get_item: no item referenced by '%s' in tree",reference);
      fstatus=XERROR_LIBRARY_ITEM_NOT_FOUND;
    }
    else{
      /* remove the item from the tree */
      xfreelist_item_t* pitem;
      pitem=*(xfreelist_item_t**)result;
      tdelete(pitem,&(library->root),_cmp_item_by_reference);
      
      VERBOSE3("remove_item: item referenced by '%s' successfully removed",reference);

      /* release item storage space */
      _release_item((void*)pitem);
      
      
      fstatus=XSUCCESS;
    }
    
    /* release working ref freelist item */
    xfreelist_release_item(&(library->ref_freelist),item);
  }
  /*_*/ /* extract a working ref freelist item */

  EXIT_DEBUG_MARK(fstatus);
  return fstatus;
}

/**/
int
xlibrary_add_item(xlibrary_t* library,
		  char* reference,
		  void* item,
		  size_t item_size)
{
  char* function_name="xlibrary_add_item";
  INIT_DEBUG_MARK();

  int fstatus;
  
  /* lock repository */
  fstatus=pthread_mutex_lock(&(library->mutex));
  if(fstatus){
    ERROR("add_item: unable to add item referenced by '%s' : unable to lock repository");
    fstatus=XERROR_MUTEX_LOCK;
  }
  else{
    /* push unlock method ( used if externaly canceled )*/
    pthread_cleanup_push((void (*)(void*))pthread_mutex_unlock,
			 (void*)(&(library->mutex)));
    
    /* call no lock method */
    fstatus=xlibrary_add_item_nolock(library,
				     reference,
				     item,
				     item_size);
    
    /* pop unlock method */
    pthread_cleanup_pop(1); /*   pthread_mutex_unlock(&(library->mutex)) */
  }

  EXIT_DEBUG_MARK(fstatus);
  return fstatus;
}

/**/
int
xlibrary_add_item_nolock(xlibrary_t* library,
			 char* reference,
			 void* item,
			 size_t item_size)
{
  char* function_name="xlibrary_add_item_nolock";
  INIT_DEBUG2_MARK();

  int fstatus;

  xfreelist_item_t* pitem;

  xlibrary_item_t litem;

  /* set item reference */
  strncpy(litem.reference,reference,XLIBRARY_REFERENCE_MAXLENGTH);
  time(&(litem.timestamp));
  litem.library=(void*)library;
  litem.flag=0;

  /* add item */
  fstatus=xfreelist_extract_item(&(library->obj_freelist),&pitem);
  if(fstatus){
    ERROR("add_item: unable to get object freelist item for '%s' : object freelist is empty",reference);
    fstatus=XERROR_FREELIST_IS_EMPTY;
  }
  else{

    /* we first try to remove the item */
    xlibrary_remove_item_nolock(library,reference);

    /* store item into object freelist item */
    memcpy(pitem->data,item,item_size);

    /* store object freelist item into library item */
    litem.object=pitem;
      
    /* extract a reference freelist item */
    fstatus=xfreelist_extract_item(&(library->ref_freelist),&pitem);
    if(fstatus){
      ERROR("add_item: unable to get reference freelist item for '%s' : object freelist is empty",reference);
      fstatus=XERROR_FREELIST_IS_EMPTY;
    }
    else{
		
      memcpy(pitem->data,&litem,sizeof(xlibrary_item_t));

      /* add the item to the tree */
      void* result;
      result=tsearch(pitem,&(library->root),_cmp_item_by_reference);
      if(result==NULL){
	ERROR("add_item: unable to add item referenced by '%s' to the tree",reference);
	xfreelist_release_item(&(library->ref_freelist),pitem);
	fstatus=XERROR_LIBRARY_ADD;
      }
      else{

	fstatus=XSUCCESS;
	
      }

    }

    if(fstatus) {
      xfreelist_release_item(&(library->obj_freelist),litem.object);
    }

  }
  /*_*/ /* add item */
    
  EXIT_DEBUG2_MARK(fstatus);
  return fstatus;
}

int
xlibrary_update_index(xlibrary_t* library){
  int fstatus;
  char* function_name="xlibrary_update_index";
  INIT_DEBUG2_MARK();
  
  fstatus=-1;

  library->item_nb=0;

  if(library->index!=NULL){
    free(library->index);
    library->index=NULL;
  }
  library->item_nb=0;
  twalk(library->root,_count_item);

  if(library->item_nb>0){
    library->index=(xlibrary_item_t**)malloc(library->item_nb*sizeof(xlibrary_item_t*));
    if(library->index!=NULL){
      library->current=library->index;
      twalk(library->root,_update_index);
      library->current=library->index;
      fstatus=0;
    }
  }
  else{
    fstatus=0;
  }

  EXIT_DEBUG2_MARK(fstatus);
  return fstatus;
}

/**/
int
xlibrary_print_contents(xlibrary_t* library){
  int fstatus;
  char* function_name="xlibrary_print_contents";
  INIT_DEBUG2_MARK();

  /* release credential repository items */
  twalk(library->root,_print_item);
  fstatus=XSUCCESS;

  EXIT_DEBUG2_MARK(fstatus);
  return fstatus;
}


/**/
int
xlibrary_lock(xlibrary_t* library){
  int fstatus;
  char* function_name="xlibrary_lock";
  INIT_DEBUG2_MARK();

  fstatus=pthread_mutex_lock(&(library->mutex));
  if(fstatus){
    fstatus=XERROR_MUTEX_LOCK;
  }
  else{
    fstatus=XSUCCESS;
  }

  EXIT_DEBUG2_MARK(fstatus);
  return fstatus;
}


/**/
int
xlibrary_unlock(xlibrary_t* library){
  int fstatus;
  char* function_name="xlibrary_unlock";
  INIT_DEBUG2_MARK();

  fstatus=pthread_mutex_unlock(&(library->mutex));
  if(fstatus){
    fstatus=XERROR_MUTEX_LOCK;
  }
  else{
    fstatus=XSUCCESS;
  }

  EXIT_DEBUG2_MARK(fstatus);
  return fstatus;
}


/*
 * ------------------------------------------------------------------------------------
 * INTERNAL  INTERNAL   INTERNAL   INTERNAL   INTERNAL   INTERNAL   INTERNAL   INTERNAL 
 *
 * INTERNAL  INTERNAL   INTERNAL   INTERNAL   INTERNAL   INTERNAL   INTERNAL   INTERNAL 
 *
 * INTERNAL  INTERNAL   INTERNAL   INTERNAL   INTERNAL   INTERNAL   INTERNAL   INTERNAL 
 * ------------------------------------------------------------------------------------
 */

/* reset item memory area and then release it to its freelist */
void
_release_item(void* p){

  xfreelist_item_t* ref_pitem;
  xfreelist_item_t* obj_pitem;

  xlibrary_item_t* litem;
  xlibrary_t* library;


  ref_pitem=(xfreelist_item_t*)p;
  litem=(xlibrary_item_t*)ref_pitem->data;

  obj_pitem=(xfreelist_item_t*)litem->object;

  /* call object free function first */
  library = (xlibrary_t*)litem->library;
  if ( library != NULL &&
       library->free_item != NULL ) {
    library->free_item( obj_pitem->data );
  }

  /* zeroed object item data */
  memset(obj_pitem->data,'\0',obj_pitem->size);
  /* release object item */
  xfreelist_release_item(obj_pitem->freelist,obj_pitem);

  /* zeroed reference item data */
  memset(ref_pitem->data,'\0',ref_pitem->size);
  /* release reference item */
  xfreelist_release_item(ref_pitem->freelist,ref_pitem);

}

/* used to print items during tree walk */
void
_print_item(const void* node,const VISIT method,const int depth){

  if(method==leaf || method==postorder){
    xfreelist_item_t* item;
    xlibrary_item_t* litem;

    item=*(xfreelist_item_t**)node;
    litem=(xlibrary_item_t*)item->data;

    if(litem!=NULL){
      VERBOSE("############");
      VERBOSE("reference  : %s",litem->reference);
      VERBOSE("############");
    }
  }
}

/* used to manage item management into the tree (add, remove, balance,...) */
int
_cmp_item_by_reference(const void* p1,const void* p2){

  xfreelist_item_t* item1;
  xfreelist_item_t* item2;

  xlibrary_item_t* litem1;
  xlibrary_item_t* litem2;

  item1=(xfreelist_item_t*)p1;
  item2=(xfreelist_item_t*)p2;

  litem1=(xlibrary_item_t*)item1->data;
  litem2=(xlibrary_item_t*)item2->data;

  if ( strncmp(litem1->reference,litem2->reference,XLIBRARY_REFERENCE_MAXLENGTH) < 0 )
    return -1;
  else if ( strncmp(litem1->reference,litem2->reference,XLIBRARY_REFERENCE_MAXLENGTH) > 0 )
    return 1;
  else
    return 0;

}

void
_count_item(const void* node,const VISIT method,const int depth){

  if(method==leaf || method==postorder){
    xfreelist_item_t* item;
    xlibrary_item_t* litem;
    xlibrary_t* library;

    item=*(xfreelist_item_t**)node;
    litem=(xlibrary_item_t*)item->data;
    library=(xlibrary_t*)litem->library;
    
    library->item_nb++;
  }
  
}

void
_update_index(const void* node,const VISIT method,const int depth){

  if(method==leaf || method==postorder){

    xfreelist_item_t* item;
    xlibrary_item_t* litem;
    xlibrary_t* library;

    item=*(xfreelist_item_t**)node;
    litem=(xlibrary_item_t*)item->data;
    library=(xlibrary_t*)litem->library;

    *library->current=litem;
    library->current++;

  }
  
}
