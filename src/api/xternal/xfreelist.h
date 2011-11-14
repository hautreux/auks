/***************************************************************************\
 * xfreelist.h - freelist functions and structures
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
#ifndef __XFREELIST_H_
#define __XFREELIST_H_

/*! \addtogroup XTERNAL
 *  @{
 */

/*! \addtogroup XFREELIST
 *  @{
 */

/*!
 * \struct xfreelist_item
 * \typedef xfreelist_item_t
 * \brief External freelist basic element
 */
typedef struct xfreelist_item {

  int free;//!< flag indicating that an item is ready to be used or not

  void* data;//!< pointer on the data that is associated with the item
  size_t size;//!< size of the item 's associated data

  struct xfreelist_item* next;//!< pointer to the previous item or NULL if head
  struct xfreelist_item* previous;//!< pointer to the next item or NULL if tail

  struct xfreelist* freelist;//!< pointer to the corresponding freelist

} xfreelist_item_t;


/*!
 * \struct xfreelist
 * \typedef xfreelist_t
 * \brief external freelist implementation
 */
typedef struct xfreelist {

  xfreelist_item_t* head;//!< pointer to the first item or NULL if empty
  xfreelist_item_t* tail;//!< pointer to the last item or NULL if empty
  
  xfreelist_item_t* items;//!< pointer on the array of freelist items
  unsigned int item_nb;//!< number of items in the array

  void* heap;//!< pointer on memory allocated for items data storage
  size_t item_size;//!< size of each item data chunk
  
  void* next;//!< pointer on the next freelist or NULL if the freelist was not extended

} xfreelist_t;


/*!
 * \fn int xfreelist_init(xfreelist_t* list,unsigned int default_length,size_t item_size)
 * \brief initialize freelist \a list for \a default_length element of size \a item_size
 *
 * \param list pointer on a xfreelist_t type to initialize
 * \param default_length default number of items to create
 * \param item_size size of the data associated with each item
 *
 * \retval XSUCCESS success
 * \retval XERROR_MEMORY unable to allocate memory for data storage
 *  
 */
int
xfreelist_init(xfreelist_t* list,unsigned int default_length,size_t item_size);

/*!
 * \fn int xfreelist_free_contents(xfreelist_t* list)
 * \brief free a previously initialized freelist \a list
 *
 * \param list pointer on the xfreelist_t type to free contents of
 *
 * \retval XSUCCESS on success
 * \retval XERROR generic error
 *
 */
int
xfreelist_free_contents(xfreelist_t* list);

/*!
 * \fn int xfreelist_extend(xfreelist_t* list)
 * \brief extend a previously initialized freelist \a list
 *
 * \param list pointer on a xfreelist_t type to extend
 *
 * \retval XSUCCESS on success
 * \retval XERROR_MEMORY unable to allocate memory for data storage
 *
 */
int
xfreelist_extend(xfreelist_t* list);

/*!
 * \fn int xfreelist_extract_item(xfreelist_t* list,xfreelist_item_t** pitem)
 * \brief extract from a previously initialized freelist \a list an item
 *
 * \param list pointer on a xfreelist_t type to use for item extraction
 * \param pitem pointer on a freelist item pointer that will be filled with extracted item addr
 *
 * \retval XSUCCESS on success
 * \retval XERROR_FREELIST_IS_EMPTY freelist is currently empty...should retry later
 */
int
xfreelist_extract_item(xfreelist_t* list,xfreelist_item_t** pitem);

/*!
 * \fn int xfreelist_release_item(xfreelist_t* list,xfreelist_item_t* item)
 * \brief release an item
 *
 * \param list pointer on a xfreelist_t type to use for item extraction
 * \param item pointer on a freelist item that must be released
 *
 * \retval XSUCCESS on success
 * \retval XERROR_FREELIST_ITEM_ALREADY_FREE item was previously released
 * \retval XERROR_FREELIST_ITEM_NOT_FOUND item not found in list
 */
int
xfreelist_release_item(xfreelist_t* list,xfreelist_item_t* item);


/*!
 * @}
*/

/*!
 * @}
*/

#endif
