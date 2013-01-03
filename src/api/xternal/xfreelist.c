/***************************************************************************\
 * xfreelist.c - a freelist implementation
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

#include "xerror.h"

/* logging */
#include "xlogger.h"

#ifndef XFREELIST_LOGHEADER
#define XFREELIST_LOGHEADER "xfreelist: "
#endif

#ifndef XFREELIST_VERBOSE_BASE_LEVEL
#define XFREELIST_VERBOSE_BASE_LEVEL 7
#endif

#ifndef XFREELIST_DEBUG_BASE_LEVEL
#define XFREELIST_DEBUG_BASE_LEVEL   7
#endif

#define VERBOSE(h,a...) xverboseN(XFREELIST_VERBOSE_BASE_LEVEL,XFREELIST_LOGHEADER h,##a)
#define VERBOSE2(h,a...) xverboseN(XFREELIST_VERBOSE_BASE_LEVEL + 1,XFREELIST_LOGHEADER h,##a)
#define VERBOSE3(h,a...) xverboseN(XFREELIST_VERBOSE_BASE_LEVEL + 2,XFREELIST_LOGHEADER h,##a)

#define DEBUG(h,a...) xdebugN(XFREELIST_DEBUG_BASE_LEVEL,XFREELIST_LOGHEADER h,##a)
#define DEBUG2(h,a...) xdebugN(XFREELIST_DEBUG_BASE_LEVEL + 1,XFREELIST_LOGHEADER h,##a)
#define DEBUG3(h,a...) xdebugN(XFREELIST_DEBUG_BASE_LEVEL + 2,XFREELIST_LOGHEADER h,##a)

#define ERROR VERBOSE

#define INIT_DEBUG_MARK()    DEBUG("%s : entering",function_name)
#define EXIT_DEBUG_MARK(a)   DEBUG("%s : exiting with status %d",function_name,a)

#define INIT_DEBUG2_MARK()   DEBUG2("%s : entering",function_name)
#define EXIT_DEBUG2_MARK(a)  DEBUG2("%s : exiting with status %d",function_name,a)

#define INIT_DEBUG3_MARK()   DEBUG3("%s : entering",function_name)
#define EXIT_DEBUG3_MARK(a)  DEBUG3("%s : exiting with status %d",function_name,a)

/* main header */
#include "xfreelist.h"

int
xfreelist_init(xfreelist_t* list,unsigned int default_length,size_t item_size){
  int fstatus=XERROR;
  char* function_name="xfreelist_init";
  INIT_DEBUG3_MARK();

  xfreelist_item_t* items_ptr;
  void* heap_ptr;

  list->head=NULL;
  list->tail=NULL;

  list->item_nb=0;
  list->item_size=item_size;

  list->next=NULL;
  
  /* allocate xfreelist_item_t pool */
  list->items=(xfreelist_item_t*)malloc(sizeof(xfreelist_item_t)*default_length);
  if(list->items!=NULL){

    /* allocate heap for items contents */
    list->heap=malloc(item_size*default_length);
    if(list->heap==NULL){
      free(list->items);
      list->items=NULL;
      fstatus=XERROR_MEMORY;
    }
    else{
      int i;
      /* initialize items and structure */
      items_ptr=list->items;
      heap_ptr=list->heap;
      for(i=0;i<default_length;i++){
	/* set item metadata */
	items_ptr->free=1;
	items_ptr->data=heap_ptr;
	items_ptr->size=item_size;
	items_ptr->next=items_ptr+1;
	items_ptr->previous=items_ptr-1;
	items_ptr->freelist=list;
	/**/
	items_ptr++;
	heap_ptr+=item_size;
      }

      list->items[0].previous=NULL;
      list->items[default_length-1].next=NULL;
      list->item_nb=default_length;

      list->head=&(list->items[0]);
      list->tail=&(list->items[default_length-1]);
      
      fstatus=XSUCCESS;
    }
    
  }
  else{
    fstatus=XERROR_MEMORY;
  }

  EXIT_DEBUG3_MARK(fstatus);
  return fstatus;
}

int
xfreelist_free_contents(xfreelist_t* list){
  int fstatus=XERROR;
  char* function_name="xfreelist_free_contents";
  INIT_DEBUG3_MARK();

  list->head=NULL;
  list->tail=NULL;

  list->item_nb=0;
  if(list->items!=NULL){
    free(list->items);
    list->items=NULL;
  }

  list->item_size=0;
  if(list->heap!=NULL){
    free(list->heap);
    list->heap=NULL;
  }

  /* free sub xfreelist */
  if ( list->next != NULL ) {
    xfreelist_free_contents(list->next);
    free(list->next);
    list->next=NULL;
  }

  fstatus=XSUCCESS;

  EXIT_DEBUG3_MARK(fstatus);
  return fstatus;
}

int
xfreelist_extend(xfreelist_t* list){
  int fstatus=-1;
  char* function_name="xfreelist_extend";
  INIT_DEBUG3_MARK();

  if ( list->next != NULL ) {

    return xfreelist_extend((xfreelist_t*)list->next);

  }
  else {

    list->next=(xfreelist_t*)malloc(sizeof(xfreelist_t));
    if ( list->next !=NULL ) {

      fstatus=xfreelist_init(list->next,list->item_nb,list->item_size);

    }
    else
      fstatus=XERROR_MEMORY;

  }

  if ( fstatus==XSUCCESS ) {
    VERBOSE("list '%x' successfully extended",list);
  }
  else {
    ERROR("unable to extend list '%x'",list);
  }

  EXIT_DEBUG3_MARK(fstatus);
  return fstatus;
}

int
xfreelist_extract_item(xfreelist_t* list,xfreelist_item_t** pitem){
  int fstatus=-1;
  char* function_name="xfreelist_extract_item";
  INIT_DEBUG3_MARK();

  xfreelist_item_t* item;

  /* if list is empty, just try to extract from a next list */
  if(list->head==NULL){

    VERBOSE("no more items in list '%x'",list);

    if ( list->next == NULL)
      xfreelist_extend(list);

    if ( list->next != NULL) {
      fstatus=xfreelist_extract_item(list->next,pitem);      
    }
    else
      fstatus=XERROR_FREELIST_IS_EMPTY;

  }
  else {

    /* get item from head */
    item=list->head;

    /* shift freelist */
    list->head=item->next;
    if(list->head!=NULL)
      list->head->previous=NULL;
    else
      list->tail=NULL;
    
    item->next=NULL;
    item->previous=NULL;
    item->free=0;

    *pitem=item;

    VERBOSE3("item '%x' successfully extracted from freelist '%x'",item,list);
    fstatus=XSUCCESS;

  }
  
  EXIT_DEBUG3_MARK(fstatus);
  return fstatus;
}

int
xfreelist_release_item(xfreelist_t* list,xfreelist_item_t* item){
  int fstatus=XERROR;
  char* function_name="xfreelist_release_item";
  INIT_DEBUG3_MARK();

  /* check that this item is linked with this freelist */
  if( list->items <= item && item < list->items + list->item_nb ) {

    if(item->free){
      fstatus=XERROR_FREELIST_ITEM_ALREADY_FREE;
    }
    else{

      item->free=1;
      item->previous=NULL;

      if(list->head==NULL){
	/* freelist empty */
	item->next=NULL;
	list->head=item;
	list->tail=item;      
      }
      else{
	/* freelist not empty */
	item->next=list->head;
	list->head->previous=item;
	list->head=item;
      }

      VERBOSE3("item '%x' successfully released to freelist '%x'",item,list);
      fstatus=XSUCCESS;

    }

  }
  /* this item is not linked with this list, we have to try sub lists */
  else {

    if ( list->next != NULL ) {
      VERBOSE("item '%x' is not linked to list '%x', releasing using sublist '%x'",item,list,list->next);
      fstatus=xfreelist_release_item(list->next,item);
    }
    else {
      VERBOSE("item '%x' is not linked to list '%x'",item,list);
      fstatus=XERROR_FREELIST_ITEM_NOT_FOUND;
    }

  }

  EXIT_DEBUG3_MARK(fstatus);
  return fstatus;
}

