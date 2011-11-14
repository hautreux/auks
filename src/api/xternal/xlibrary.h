/***************************************************************************\
 * xlibrary.h - xlibrary functions and structures definitions
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
#ifndef __XLIBRARY_H_
#define __XLIBRARY_H_

/* multihtreading support */
#include <pthread.h>

#include "xerror.h"

/* library implemented using a freelist */
#include "xfreelist.h"


/*! \addtogroup XTERNAL
 *  @{
 */

/*! \addtogroup XLIBRARY
 *  @{
 */

typedef void (*xlibrary_item_free_func_t) (void*);

#define XLIBRARY_REFERENCE_MAXLENGTH   128

/*!
 * \struct xlibrary_item
 * \typedef xlibrary_item_t
 * \brief external library basic element
 */
typedef struct xlibrary_item {

  char reference[XLIBRARY_REFERENCE_MAXLENGTH];//!< unique identifier of the item

  time_t timestamp;//!< time in seconds since EPOCH of last modification

  void* object;//!<pointer on a xfreelist item that contains associated data

  void* library;//!<pointer on the associated library

	int flag;//!< external purposes flag
} xlibrary_item_t;


/*!
 * \struct xlibrary
 * \typedef xlibrary_t
 * \brief external library implementation (based on freelist)
 */
typedef struct xlibrary {

  pthread_mutex_t mutex;//!< for thread safety
  pthread_cond_t condition;//!< for thread safety

  xfreelist_t ref_freelist;//!< freelist containing xlibrary items
  xfreelist_t obj_freelist;//!< freelist containing xlibrary items data objects

  void* root;//!< tree root of the library
  int item_nb;//!< items currently stored in the tree

  xlibrary_item_t** index;//!<workaround for tree indexation
  xlibrary_item_t** current;//!<workaround for tree indexation

  xlibrary_item_free_func_t free_item; //!< function used to free each stored object

} xlibrary_t;


/*!
 * \brief create an xlibrary
 *
 * \param library pointer on the xlibrary structure to initialize
 * \param default_length library default number of element
 * \param item_maxsize maximum length of an item associated data buffer
 * \param func function to called on library objects pointer to free their content 
 *        when removed
 *
 * \retval XSUCCESS                     success
 * \retval XERROR                       generic error
 * \retval XERROR_MUTEX_INIT_FAILED     unable to initialized repository mutex
 * \retval XERROR_CONDITION_INIT_FAILED unable to initialized repository condition
 * \retval XERROR_FREELIST_INIT_FAILED  unable to initialized freelist
 */
int
xlibrary_init(xlibrary_t* library,
	      size_t default_length,
	      size_t item_maxsize,
	      xlibrary_item_free_func_t func);

/*!
 * \brief free an xlibrary contents
 *
 * \param library xlibrary to free contents of
 *
 * \retval XSUCCESS                     success
 * \retval XERROR                       generic error
 */
int
xlibrary_free_contents(xlibrary_t* library);

/*!
 * \brief add an item to an xlibrary
 *
 * \param library pointer on the xlibrary previously initialized
 * \param reference unique identifier of the item
 * \param item pointer on the item data to add
 * \param item_size length of the data buffer to store
 *
 * \retval XSUCCESS                 success
 * \retval XERROR                   generic error
 * \retval XERROR_MUTEX_LOCK_FAILED unable to lock repository
 * \retval XERROR_FREELIST_IS_EMPTY freelist is empty
 * \retval XERROR_LIBRARY_ADD_FAILED   unable to add credential item to the tree
 */
int
xlibrary_add_item(xlibrary_t* library,
		  char* reference,
		  void* item,
		  size_t item_size);

/*!
 * \brief get an item from a repository based on associated reference
 *
 * \param library pointer on the xlibrary previously initialized and filled
 * \param reference unique identifier of the item
 * \param item pointer on the item data to get
 * \param item_size length of the data buffer to store
 *
 * \retval XSUCCESS                 success
 * \retval XERROR                   generic error
 * \retval XERROR_MUTEX_LOCK_FAILED unable to lock repository
 * \retval XERROR_ITEM_NOT_FOUND    item not found in repository
 * \retval XERROR_OBJECT_NOT_FOUND  data associated with the item not found
 */
int
xlibrary_get_item(xlibrary_t* library,
		  char* reference,
		  void* item,
		  size_t item_size);

/*!
 * \brief remove an item from a library based on associated reference
 *
 * \param library pointer on the xlibrary previously initialized and filled
 * \param reference unique identifier of the item
 *
 * \retval XSUCCESS                 success
 * \retval XERROR                   generic error
 * \retval XERROR_MUTEX_LOCK_FAILED unable to lock repository
 */
int
xlibrary_remove_item(xlibrary_t* library,
		     char* reference);

/*!
 * \brief add an item to an xlibrary (lockfree)
 *
 * \param library pointer on the xlibrary previously initialized
 * \param reference unique identifier of the item
 * \param item pointer on the item data to add
 * \param item_size length of the data buffer to store
 *
 * \retval XSUCCESS                 success
 * \retval XERROR                   generic error
 * \retval XERROR_MUTEX_LOCK_FAILED unable to lock repository
 * \retval XERROR_FREELIST_IS_EMPTY freelist is empty
 * \retval XERROR_LIBRARY_ADD_FAILED   unable to add credential item to the tree
 */
int
xlibrary_add_item_nolock(xlibrary_t* library,
			 char* reference,
			 void* item,
			 size_t item_size);

/*!
 * \brief get an item from a repository based on associated reference (lockfree)
 *
 * \param library pointer on the xlibrary previously initialized and filled
 * \param reference unique identifier of the item
 * \param item pointer on the item data to get
 * \param item_size length of the data buffer to store
 *
 * \retval XSUCCESS                 success
 * \retval XERROR                   generic error
 * \retval XERROR_MUTEX_LOCK_FAILED unable to lock repository
 * \retval XERROR_ITEM_NOT_FOUND    item not found in repository
 * \retval XERROR_OBJECT_NOT_FOUND  data associated with the item not found
 */
int
xlibrary_get_item_nolock(xlibrary_t* library,
			 char* reference,
			 void* item,
			 size_t item_size);

/*!
 * \brief remove an item from a library based on associated reference (lockfree)
 *
 * \param library pointer on the xlibrary previously initialized and filled
 * \param reference unique identifier of the item
 *
 * \retval XSUCCESS                 success
 * \retval XERROR                   generic error
 * \retval XERROR_MUTEX_LOCK_FAILED unable to lock repository
 */
int
xlibrary_remove_item_nolock(xlibrary_t* library,
			    char* reference);

/*!
 * \brief lock a library
 *
 * \param library pointer on the xlibrary to use
 *
 * \retval XSUCCESS                 success
 * \retval XERROR                   generic error
 * \retval XERROR_MUTEX_LOCK        mutex error
 */
int
xlibrary_lock(xlibrary_t* library);

/*!
 * \brief unlock a library
 *
 * \param library pointer on the xlibrary to use
 *
 * \retval XSUCCESS                 success
 * \retval XERROR                   generic error
 * \retval XERROR_MUTEX_LOCK        mutex error
 */
int
xlibrary_unlock(xlibrary_t* library);

/*!
 * \brief update the internal index of a library (should be locked)
 *
 * \param library pointer on the xlibrary previously initialized and filled
 *
 * \retval XSUCCESS                 success
 * \retval XERROR                   generic error
 */
int
xlibrary_update_index(xlibrary_t* library);

/*!
 * @}
*/

/*!
 * @}
*/

#endif
