/***************************************************************************\
 * auks_message.h - AUKS communication messages functions and structures 
 * definitions
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
#ifndef __AUKS_MESSAGE_H_
#define __AUKS_MESSAGE_H_

/*! \addtogroup AUKS_MESSAGE
 *  @{
 */

#include <auks/auks_buffer.h>

enum AUKS_MESSAGE_TYPE {
	AUKS_PING_REQUEST = 0,
	AUKS_LIST_REQUEST,
	AUKS_ADD_REQUEST,
	AUKS_GET_REQUEST,
	AUKS_REMOVE_REQUEST,
	AUKS_CLOSE_REQUEST,
	AUKS_DUMP_REQUEST,

	AUKS_PING_REPLY = 20,
	AUKS_ERROR_REPLY,
	AUKS_LIST_REPLY,
	AUKS_ADD_REPLY,
	AUKS_GET_REPLY,
	AUKS_REMOVE_REPLY,
	AUKS_DUMP_REPLY,
};

typedef struct auks_message {
	int type;
	auks_buffer_t buffer;
} auks_message_t;

/*!
 * \brief Initialise an auks message structure
 *
 * \param msg pointer to the structure to initialise
 * \param type type of the message to initialize
 * \param buffer message body
 * \param length length of the message body
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 */
int auks_message_init(auks_message_t * msg,int type,
		      char *buffer,size_t length);

/*!
 * \brief Free an auks message structure contents
 *
 * \param msg pointer to the structure to free its contents
 *
 * \retval AUKS_SUCCESS operation successfully done
 * \retval AUKS_ERROR operation failed
 */
int auks_message_free_contents(auks_message_t * msg);

/*!
 * \brief Marshall an auks message
 *
 * \param msg auks message pointer
 * \param pbuffer pointer on a char buffer that will be allocated and 
 *        store message data
 * \param psize newly allocated buffer size
 *
 * \retval AUKS_SUCCES
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_MESSAGE_MALLOC
 * \retval AUKS_ERROR_MESSAGE_TYPE_MARSH
 * \retval AUKS_ERROR_MESSAGE_SIZE_MARSH
 * \retval AUKS_ERROR_MESSAGE_DATA_MARSH
 *
 */
int auks_message_marshall(auks_message_t * msg,char **pbuffer,
			  size_t * psize);

/*!
 * \brief Unmarshall an auks message
 *
 * \param msg auks message pointer
 * \param buffer marshalled buffer that represent the message
 * \param size marshalled buffer size
 *
 * \retval AUKS_SUCCESS operation successfully done
 * \retval AUKS_ERROR operation failed
 * \retval AUKS_ERROR_MESSAGE_NULL_BUFFER
 * \retval AUKS_ERROR_MESSAGE_TYPE_UNMARSH
 * \retval AUKS_ERROR_MESSAGE_SIZE_UNMARSH
 * \retval AUKS_ERROR_MESSAGE_MALLOC
 * \retval AUKS_ERROR_MESSAGE_DATA_UNMARSH
 */
int auks_message_unmarshall(auks_message_t * msg,char *buffer,
			    size_t size);


/*!
 * \brief Create an auks message using input buffer
 *
 * \param msg auks message pointer
 * \param buffer marshalled buffer that represent the message
 * \param size marshalled buffer size
 *
 * \retval AUKS_SUCCESS operation successfully done
 * \retval AUKS_ERROR operation failed
 */
int auks_message_load(auks_message_t * msg,char *buffer,size_t size);


/*!
 * \brief Get number of already packed bytes in the internal 
 *        buffer of the message
 *
 * \param msg auks message pointer
 *
 * \retval number of bytes
 */
size_t auks_message_packed(auks_message_t * msg);

/*!
 * \brief Get number of bytes ready to be used for packing into 
 *        the internal buffer of the message
 *
 * \param msg auks message pointer
 *
 * \retval number of bytes
 */
size_t auks_message_unpacked(auks_message_t * msg);

/*!
 * \brief Get the pointer on the internal buffer data of the
 *        message
 *
 * \param msg auks message pointer
 *
 * \retval pointer on the packed data
 */
char * auks_message_data(auks_message_t * msg);

/*!
 * \brief pack an integer into an auks message
 *
 * \param msg pointer to the structure to use
 * \param i integer value to pack
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_BUFFER_MALLOC
 * \retval AUKS_ERROR_BUFFER_REALLOC
 */
int
auks_message_pack_int(auks_message_t * msg,int i);

/*!
 * \brief unpack an integer from an auks message
 *
 * \param msg pointer to the structure to use
 * \param i pointer on an integer to unpack value to
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 */
int
auks_message_unpack_int(auks_message_t * msg,int * i);

/*!
 * \brief pack an uid value into an auks message
 *
 * \param msg pointer to the structure to use
 * \param u uid value to pack
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_BUFFER_MALLOC
 * \retval AUKS_ERROR_BUFFER_REALLOC
 */
int
auks_message_pack_uid(auks_message_t * msg,uid_t u);

/*!
 * \brief unpack an uid from an auks message
 *
 * \param msg pointer to the structure to use
 * \param u pointer on an uid_t to unpack value to
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 */
int
auks_message_unpack_uid(auks_message_t * msg,uid_t * u);

/*!
 * \brief pack data into an auks message
 *
 * \param msg pointer to the structure to use
 * \param data pointer on the array to pack
 * \param length length of the data to pack
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_BUFFER_MALLOC
 * \retval AUKS_ERROR_BUFFER_REALLOC
 */
int
auks_message_pack_data(auks_message_t * msg,char * data,size_t length);

/*!
 * \brief unpack data from an auks message
 *
 * \param msg pointer to the structure to use
 * \param data pointer on an array to unpack value to
 * \param length length of data to unpack
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 */
int
auks_message_unpack_data(auks_message_t * msg,char * data,size_t length);

/*!
 * @}
*/

#endif
