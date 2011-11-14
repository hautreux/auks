/***************************************************************************\
 * xqueue.h - xqueue functions and structures definitions
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
#ifndef __XQUEUE_H_
#define __XQUEUE_H_

/* xqueue is implemented using a freelist */
#include "xfreelist.h"

/* multihtreading support */
#include <pthread.h>

/*! \addtogroup XTERNAL
 *  @{
 */

/*! \addtogroup XQUEUE
 *  @{
 */

/*!
 * \struct xqueue
 * \typedef xqueue_t
 * \brief External FIFO queue (based on freelist)
 */
typedef struct xqueue {

  xfreelist_t freelist;//!< freelist used for queue elements storage

  xfreelist_item_t* head;//!< first element
  xfreelist_item_t* tail;//!< last element

  pthread_mutex_t mutex;//!< mutex for thread safety
  pthread_cond_t condition;//!< condition for threads wake up

} xqueue_t;


/*!
 * \fn xqueue_init(xqueue_t* queue,unsigned int default_length,size_t item_size)
 * \brief create a xqueue
 *
 * \param queue pointer on the xqueue structure to initialize
 * \param default_length queue max number of element
 * \param item_size queue 's element size
 *
 * \retval XSUCCESS init succeed
 * \retval XERROR_MUTEX_INIT_FAILED unable to initialize queue mutex
 * \retval XERROR_CONDITION_INIT_FAILED unable to initiailize queue condition
 */
int
xqueue_init(xqueue_t* queue,unsigned int default_length,size_t item_size);

/*!
 * \fn xqueue_free_contents(xqueue_t* queue)
 * \brief free an xqueue contents
 *
 * \param queue xqueue to free contents of
 *
 * \retval XSUCCESS success
 * \retval XERROR generic error
 */
int
xqueue_free_contents(xqueue_t* queue);

/*!
 * \fn xqueue_enqueue(xqueue_t* queue,void* data,size_t length)
 * \brief enqueue an element into the queue
 *
 * \param queue xqueue to enqueue element in
 * \param data pointer on the data to add
 * \param length data size
 *
 * \retval XSUCCESS element successfully enqueued
 * \retval XERROR_MUTEX_LOCK_FAILED mutex lock failed
 * \retavl XERROR_QUEUE_FREELIST_IS_NULL freelist is null
 * \retval XERROR_FREELIST_IS_EMPTY freelist is empty
 * \retval XERROR_QUEUE_FREELIST_EXTRACT_ITEM unable to extract qn item from freelist
 *
 */
int
xqueue_enqueue(xqueue_t* queue,void* data,size_t length);

/*!
 * \fn xqueue_dequeue(xqueue_t* queue,void* data,size_t length)
 * \brief dequeue an element from the queue
 *
 * \param queue xqueue to dequeue from
 * \param data pointer on the element to fill with data
 * \param length data size
 *
 * \retval XSUCCESS element successfully copied and enqueued
 * \retval XERROR generic error
 * \retval XERROR_QUEUE_IS_EMPTY no more item to dequeue
 * \retval XERROR_QUEUE_FREELIST_IS_NULL queue's freelist is NULL
 * \retval XERROR_FREELIST_IS_EMPTY queue's freelist is empty
 * \retval XERROR_MUTEX_LOCK_FAILED mutex lock failed
 */
int
xqueue_dequeue(xqueue_t* queue,void* data,size_t length);

/*!
 * \fn xqueue_enqueue(xqueue_t* queue,void* data,size_t length)
 * \brief enqueue an element into the queue
 * non blocking : don't wait for element dequeue if queue is full
 * (xqueue associated freelist is empty)
 *
 * \param queue xqueue to enqueue element in
 * \param data pointer on the data to add
 * \param length data size
 *
 * \retval XSUCCESS element successfully enqueued
 * \retval XERROR_MUTEX_LOCK_FAILED mutex lock failed
 * \retavl XERROR_QUEUE_FREELIST_IS_NULL freelist is null
 * \retval XERROR_FREELIST_IS_EMPTY freelist is empty
 * \retval XERROR_QUEUE_FREELIST_EXTRACT_ITEM unable to extract qn item from freelist
 *
 */
int
xqueue_enqueue_non_blocking(xqueue_t* queue,void* data,size_t length);

/*!
 * \fn xqueue_dequeue(xqueue_t* queue,void* data,size_t length)
 * \brief dequeue an element from the queue
 * non blocking : don't wait for element enqueue if queue is empty 
 *
 * \param queue xqueue to dequeue from
 * \param data pointer on the element to fill with data
 * \param length data size
 *
 * \retval XSUCCESS element successfully copied and enqueued
 * \retval XERROR generic error
 * \retval XERROR_QUEUE_IS_EMPTY no more item to dequeue
 * \retval XERROR_QUEUE_FREELIST_IS_NULL queue's freelist is NULL
 * \retval XERROR_FREELIST_IS_EMPTY queue's freelist is empty
 * \retval XERROR_MUTEX_LOCK_FAILED mutex lock failed
 */
int
xqueue_dequeue_non_blocking(xqueue_t* queue,void* data,size_t length);

/*!
 * \fn xqueue_get_length(xqueue_t* queue,void* data,int* length)
 * \brief get the number of element in the queue
 *
 * \param queue xqueue to get information from
 * \param length pointer on the int that will be set to current xqueue item nb
 *
 * \retval XSUCCESS element successfully copied and enqueued
 * \retval XERROR generic error
 * \retval XERROR_MUTEX_LOCK_FAILED mutex lock failed
 */
int
xqueue_get_length(xqueue_t* queue,int* length);

/*!
 * \fn xqueue_wait_4_emptiness(xqueue_t* queue)
 * \brief wait until corresponding queue is empty
 *
 * \param queue xqueue to use
 *
 * \retval XSUCCESS element successfully copied and enqueued
 * \retval XERROR generic error
 * \retval XERROR_MUTEX_LOCK_FAILED mutex lock failed
 */
int
xqueue_wait_4_emptiness(xqueue_t* queue);

/*!
 * @}
*/

/*!
 * @}
*/

#endif
