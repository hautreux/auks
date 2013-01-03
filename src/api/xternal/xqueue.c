/***************************************************************************\
 * xqueue.c - a queueing system implementation
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

#include <string.h>

#include <pthread.h>

#include "xerror.h"

/* logging */
#include "xlogger.h"

#ifndef XQUEUE_LOGHEADER
#define XQUEUE_LOGHEADER "xqueue: "
#endif

#ifndef XQUEUE_VERBOSE_BASE_LEVEL
#define XQUEUE_VERBOSE_BASE_LEVEL 7
#endif

#ifndef XQUEUE_DEBUG_BASE_LEVEL
#define XQUEUE_DEBUG_BASE_LEVEL   7
#endif

#define VERBOSE(h,a...) xverboseN(XQUEUE_VERBOSE_BASE_LEVEL,	\
				  XQUEUE_LOGHEADER h,##a)
#define VERBOSE2(h,a...) xverboseN(XQUEUE_VERBOSE_BASE_LEVEL + 1,	\
				   XQUEUE_LOGHEADER h,##a)
#define VERBOSE3(h,a...) xverboseN(XQUEUE_VERBOSE_BASE_LEVEL + 2,	\
				   XQUEUE_LOGHEADER h,##a)

#define DEBUG(h,a...) xdebugN(XQUEUE_DEBUG_BASE_LEVEL,XQUEUE_LOGHEADER h,##a)
#define DEBUG2(h,a...) xdebugN(XQUEUE_DEBUG_BASE_LEVEL + 1,XQUEUE_LOGHEADER h,##a)
#define DEBUG3(h,a...) xdebugN(XQUEUE_DEBUG_BASE_LEVEL + 2,XQUEUE_LOGHEADER h,##a)

#define ERROR VERBOSE

#define INIT_DEBUG_MARK()    DEBUG("%s : entering",function_name)
#define EXIT_DEBUG_MARK(a)   DEBUG("%s : exiting with status %d",function_name,a)

#define INIT_DEBUG2_MARK()   DEBUG2("%s : entering",function_name)
#define EXIT_DEBUG2_MARK(a)  DEBUG2("%s : exiting with status %d",function_name,a)

#define INIT_DEBUG3_MARK()   DEBUG3("%s : entering",function_name)
#define EXIT_DEBUG3_MARK(a)  DEBUG3("%s : exiting with status %d",function_name,a)

/* main header */
#include "xqueue.h"

int
xqueue_init(xqueue_t* queue,unsigned int default_length,size_t item_size)
{
	int fstatus;
	char* function_name="xqueue_init";
	INIT_DEBUG2_MARK();
	
	queue->head=NULL;
	queue->tail=NULL;
	
	/* mutex initialization */
	fstatus=pthread_mutex_init(&(queue->mutex),NULL);
	if(fstatus){
		fstatus=XERROR_MUTEX_INIT;
	}
	else{
		/* condition initialization */
		fstatus=pthread_cond_init(&(queue->condition),NULL);
		if(fstatus){
			fstatus=XERROR_CONDITION_INIT;
		}
		else{
			/* freelist initialization */
			fstatus=xfreelist_init(&(queue->freelist),
					       default_length,item_size);
			if(fstatus){
				fstatus=XERROR;
				/* an error occured - destroy condition */
				pthread_cond_destroy(&(queue->condition));
			}
		}
		/*_*/ /* condition init */
		
		/* an error occured - destroy mutex */
		if(fstatus){
			pthread_mutex_destroy(&(queue->mutex));
		}
		
	}
	/*_*/ /* mutex init */
	
	EXIT_DEBUG2_MARK(fstatus);
	return fstatus;
}

int
xqueue_free_contents(xqueue_t* queue)
{
	int fstatus=XERROR;
	char* function_name="xqueue_free_contents";
	INIT_DEBUG2_MARK();
	
	xfreelist_item_t* item;
	xfreelist_t* freelist;
	
	/* release queued items */
	freelist=&(queue->freelist);
	if(freelist!=NULL){
		item=queue->head;
		while(item!=NULL){
			xfreelist_release_item(freelist,item);
			item=item->next;
		}
	}
	
	queue->head=NULL;
	queue->tail=NULL;
	
	/* condition destruction */
	pthread_cond_destroy(&(queue->condition));
	
	/* mutex destruction */
	pthread_mutex_destroy(&(queue->mutex));
	
	/* free freelist contents */
	fstatus=xfreelist_free_contents(&(queue->freelist));
	
	EXIT_DEBUG2_MARK(fstatus);
	return fstatus;
}

int
xqueue_enqueue_base(xqueue_t* queue,void* data,size_t length,int blocking)
{
	int fstatus;
	char* function_name="xqueue_enqueue";
	INIT_DEBUG_MARK();
	
	xfreelist_t* freelist;
	xfreelist_item_t* item;
	
	fstatus=pthread_mutex_lock(&(queue->mutex));
	if(fstatus){
		return XERROR_MUTEX_LOCK;
	}
	pthread_cleanup_push((void (*)(void*))pthread_mutex_unlock,
			     (void*)(&(queue->mutex)));
	
	/* extract an item from freelist */
	freelist=&(queue->freelist);
	if(freelist==NULL){
		fstatus=XERROR_QUEUE_FREELIST_IS_NULL;
		goto exit;
	}
	
	/* check input element size */
	if(length>freelist->item_size){
		fstatus=XERROR_FREELIST_IS_EMPTY;
		goto exit;
	}
	
	
	do{
		/* extract an item from freelist */
		fstatus=xfreelist_extract_item(freelist,&item);
		
		if(fstatus==XERROR_FREELIST_IS_EMPTY){
			if ( blocking == 1 ) {
				VERBOSE("enqueuing: queue's freelist is empty, "
					"waiting for dequeing");
				pthread_cond_wait(&(queue->condition),
						  &(queue->mutex));
			}
			else
				break;
		}
	}
	while(fstatus==XERROR_FREELIST_IS_EMPTY);
	
	if(fstatus){
		fstatus=XERROR_QUEUE_FREELIST_EXTRACT_ITEM;
	}
	else{
		/* copy input element into extracted item */
		memcpy(item->data,data,length);

		/* enqueue item on queue */
		if(queue->head==NULL){
			/* empty queue */
			item->next=NULL;
			queue->head=item;
			queue->tail=item;
		}
		else{
			/* non empty queue */
			item->next=queue->head;
			queue->head->previous=item;
			queue->head=item;
		}
		fstatus=XSUCCESS;
	}
	
exit:
	if(fstatus==XSUCCESS)
		pthread_cond_signal(&(queue->condition));

	pthread_cleanup_pop(1); /*   pthread_mutex_unlock(&(queue->mutex)) */
	
	EXIT_DEBUG_MARK(fstatus);
	return fstatus;
}

int
xqueue_enqueue(xqueue_t* queue,void* data,size_t length)
{
	return xqueue_enqueue_base(queue,data,length,1);

	int fstatus;
	char* function_name="xqueue_enqueue";
	INIT_DEBUG_MARK();
	
	xfreelist_t* freelist;
	xfreelist_item_t* item;
	
	fstatus=pthread_mutex_lock(&(queue->mutex));
	if(fstatus){
		return XERROR_MUTEX_LOCK;
	}
	pthread_cleanup_push((void (*)(void*))pthread_mutex_unlock,
			     (void*)(&(queue->mutex)));
	
	/* extract an item from freelist */
	freelist=&(queue->freelist);
	if(freelist==NULL){
		fstatus=XERROR_QUEUE_FREELIST_IS_NULL;
		goto exit;
	}
	
	/* check input element size */
	if(length>freelist->item_size){
		fstatus=XERROR_FREELIST_IS_EMPTY;
		goto exit;
	}
	
	
	do{
		/* extract an item from freelist */
		fstatus=xfreelist_extract_item(freelist,&item);
		
		if(fstatus==XERROR_FREELIST_IS_EMPTY){
			VERBOSE("enqueuing: queue's freelist is empty, "
				"waiting for dequeing");
			pthread_cond_wait(&(queue->condition),&(queue->mutex));
		}
	}
	while(fstatus==XERROR_FREELIST_IS_EMPTY);
	
	if(fstatus){
		fstatus=XERROR_QUEUE_FREELIST_EXTRACT_ITEM;
	}
	else{
		/* copy input element into extracted item */
		memcpy(item->data,data,length);

		/* enqueue item on queue */
		if(queue->head==NULL){
			/* empty queue */
			item->next=NULL;
			queue->head=item;
			queue->tail=item;
		}
		else{
			/* non empty queue */
			item->next=queue->head;
			queue->head->previous=item;
			queue->head=item;
		}
		fstatus=XSUCCESS;
	}
	
exit:
	if(fstatus==XSUCCESS)
		pthread_cond_signal(&(queue->condition));

	pthread_cleanup_pop(1); /*   pthread_mutex_unlock(&(queue->mutex)) */
	
	EXIT_DEBUG_MARK(fstatus);
	return fstatus;
}

int
xqueue_dequeue_base(xqueue_t* queue,void* data,size_t length,int blocking)
{
	int fstatus;
	char* function_name="xqueue_dequeue";
	INIT_DEBUG_MARK();
	
	xfreelist_item_t* item;
	
	fstatus=pthread_mutex_lock(&(queue->mutex));
	if(fstatus){
		ERROR("unable to lock queue for dequeuing");
		return XERROR_MUTEX_LOCK;
	}
	pthread_cleanup_push((void (*)(void*))pthread_mutex_unlock,
			     (void*)(&(queue->mutex)));

	do{
		/* check for queue emptyness */
		if(queue->tail==NULL){
			if ( blocking == 1 ) {
				VERBOSE("dequeuing: queue is empty, waiting for"
					" element enqueuing...");
				pthread_cond_wait(&(queue->condition),
						  &(queue->mutex));
			}
			else
				break;
		}
	}
	while(queue->tail==NULL);
	
	if(queue->tail==NULL){
		fstatus=XERROR_QUEUE_IS_EMPTY;
	}
	else{
		/* check freelist validity */
		xfreelist_t* freelist;
		freelist=&(queue->freelist);
		if(freelist==NULL){
			fstatus=XERROR_QUEUE_FREELIST_IS_NULL;
			goto exit;
		}

		/* check output element size */
		if(length>freelist->item_size){
			fstatus=XERROR_FREELIST_IS_EMPTY;
			goto exit;
		}
    
		/* get last item */
		item=queue->tail;
    
		/* shift queue */
		queue->tail=item->previous;
		if(queue->tail!=NULL)
			queue->tail->next=NULL;
		else
			queue->head=NULL;
    
		/* isolate dequeued item */
		item->next=NULL;
		item->previous=NULL;

		/* copy item data into output element */
		memcpy(data,item->data,length);

		/* TODO : zeroed data */

		/* release item to freelist */
		fstatus=xfreelist_release_item(freelist,item);
		
	}
	
exit:
	if(fstatus==XSUCCESS)
		pthread_cond_signal(&(queue->condition));

	pthread_cleanup_pop(1); /*   pthread_mutex_unlock(&(queue->mutex)) */

	EXIT_DEBUG_MARK(fstatus);
	return fstatus;
}

int
xqueue_dequeue(xqueue_t* queue,void* data,size_t length)
{
	return xqueue_dequeue_base(queue,data,length,1);
}

int
xqueue_enqueue_non_blocking(xqueue_t* queue,void* data,size_t length)
{
	return xqueue_enqueue_base(queue,data,length,0);
}

int
xqueue_dequeue_non_blocking(xqueue_t* queue,void* data,size_t length)
{
	return xqueue_dequeue_base(queue,data,length,0);
}


int
xqueue_wait_4_emptiness(xqueue_t* queue)
{
	int fstatus=XERROR;
	char* function_name="xqueue_wait_4_emptiness";
	INIT_DEBUG_MARK();
	
	int empty_flag=0;
	int queue_length;
	
	do{
		fstatus=xqueue_get_length(queue,&queue_length);
		if ( fstatus != XSUCCESS ) {
			ERROR("unable to get queue length");
			break;
		}
		else{
			if(queue_length==0){
				VERBOSE("queue is empty");
				empty_flag=1;
			}
			else{
				VERBOSE("queue is not empty, sleeping...");
				sleep(1);
			}
		}
	}
	while(!empty_flag);
	
	EXIT_DEBUG_MARK(fstatus);
	return fstatus;
}


int
xqueue_get_length(xqueue_t* queue,int* length)
{
	int fstatus;
	char* function_name="xqueue_get_length";
	INIT_DEBUG_MARK();

	xfreelist_item_t* item;

	/* lock queue */
	fstatus=pthread_mutex_lock(&(queue->mutex));
	if(fstatus){
		ERROR("unable to lock queue while attempting to "
		      "get queue length");
		return XERROR_MUTEX_LOCK;
	}
	else{
		int queue_length = 0;
		item=queue->head;
		while(item!=NULL){
			queue_length++;
			item=item->next;
		}

		/* unlock queue */
		pthread_mutex_unlock(&(queue->mutex));
		
		*length=queue_length;
		fstatus=XSUCCESS;
	}
	
	EXIT_DEBUG_MARK(fstatus);
	return fstatus;
}
