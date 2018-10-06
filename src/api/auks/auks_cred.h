/***************************************************************************\
 * auks_cred.c - auks_cred functions and structures definition
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
#ifndef __AUKS_CRED_H_
#define __AUKS_CRED_H_

#include <time.h>

#include "auks/auks_message.h"

/*! \addtogroup AUKS_CRED
 *  @{
 */

#define AUKS_PRINCIPAL_MAX_LENGTH  128
#define AUKS_CRED_INVALID_UID       -1
#define AUKS_CRED_INVALID_TIME       0
#define AUKS_CRED_FILE_MAX_LENGTH  128

#define AUKS_CRED_DATA_MAX_LENGTH 4096

typedef struct auks_cred_info {
	char principal[AUKS_PRINCIPAL_MAX_LENGTH + 1];
	uid_t uid;
	time_t starttime;
	time_t endtime;
	time_t renew_till;
	int addressless;
} auks_cred_info_t;

typedef struct auks_cred {
	auks_cred_info_t info;
	char data[AUKS_CRED_DATA_MAX_LENGTH];
	size_t length;
	size_t max_length;
	int status;
} auks_cred_t;

/*!
 * \brief Create an auks credential based on kerberos serialized credential
 *
 * \param credential pointer on an auks credential structure to init
 * \param data buffer that contains kerberos credential data
 * \param length buffer length
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_CRED_INIT_BUFFER_TOO_LARGE
 * \retval AUKS_ERROR_CRED_INIT_BUFFER_IS_NULL
 * \retval AUKS_ERROR_CRED_INIT_KRB_CTX_INIT
 * \retval AUKS_ERROR_CRED_INIT_KRB_AUTH_CTX_INIT
 * \retval AUKS_ERROR_CRED_INIT_KRB_RD_BUFFER
 * \retval AUKS_ERROR_CRED_INIT_KRB_RD_PRINC
 * \retval AUKS_ERROR_CRED_INIT_KRB_PRINC_TOO_LONG
 * \retval AUKS_ERROR_CRED_INIT_KRB_PRINC_TO_UNAME
 * \retval AUKS_ERROR_CRED_INIT_GETPWNAM
 */
int auks_cred_init(auks_cred_t* credential,char* data,size_t length);

/*!
 * \brief Free an auks credential contents
 *
 * \param credential auks credential to free contents of
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 */
int auks_cred_free_contents(auks_cred_t* credential);

/*!
 * \brief Extract an auks credential from a ccache file
 *
 * \param credential pointer on an auks credential structure to init
 * \param ccache credential cache file to read from
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_CRED_INIT_BUFFER_TOO_LARGE
 * \retval AUKS_ERROR_CRED_INIT_BUFFER_IS_NULL
 * \retval AUKS_ERROR_CRED_INIT_KRB_CTX_INIT
 * \retval AUKS_ERROR_CRED_INIT_KRB_AUTH_CTX_INIT
 * \retval AUKS_ERROR_CRED_INIT_KRB_RD_BUFFER
 * \retval AUKS_ERROR_CRED_INIT_KRB_RD_PRINC
 * \retval AUKS_ERROR_CRED_INIT_KRB_PRINC_TOO_LONG
 * \retval AUKS_ERROR_CRED_INIT_KRB_PRINC_TO_UNAME
 * \retval AUKS_ERROR_CRED_INIT_GETPWNAM
 * \retval AUKS_ERROR_KRB5_CRED_INIT_CTX
 * \retval AUKS_ERROR_KRB5_CRED_OPEN_CC
 * \retval AUKS_ERROR_KRB5_CRED_READ_CC
 * \retval AUKS_ERROR_KRB5_CRED_NO_TGT_FOUND
 * \retval AUKS_ERROR_KRB5_CRED_INIT_AUTH_CTX
 * \retval AUKS_ERROR_KRB5_CRED_MK_CRED
 * \retval AUKS_ERROR_KRB5_CRED_MALLOC
 */
int auks_cred_extract(auks_cred_t* credential,char* ccache);

/*!
 * \brief Store an auks credential into a ccache file
 *
 * \param credential pointer on the auks credential structure to write to ccache
 * \param ccache credential cache file to write to
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_...
 */
int auks_cred_store(auks_cred_t* credential,char* ccache);

/*!
 * \brief Renew an auks credential in place
 *
 * \param credential pointer on the auks credential structure to renew
 * \param flags additionnal flags for advanced options (0 means default)
 *        (1 means renew getting an addressless ticket)
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_...
 */
int auks_cred_renew(auks_cred_t* credential,int flags);

/*!
 * \brief Transform an auks credential in place to make it addressless
 *
 * \param credential pointer on the auks credential structure to renew
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_...
 */
int auks_cred_deladdr(auks_cred_t* credential);

/*!
 * \brief Display an auks credential info on log
 *
 * \param credential pointer on the auks credential structure to display
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_...
 */
int auks_cred_log(auks_cred_t* credential);

/*!
 * \brief pack an auks cred into an auks message
 *
 * \param cred pointer on the cred to pack
 * \param msg pointer to the message structure to use
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_BUFFER_MALLOC
 * \retval AUKS_ERROR_BUFFER_REALLOC
 */
int
auks_cred_pack(auks_cred_t* cred,auks_message_t * msg);

/*!
 * \brief unpack an auks cred from an auks message
 *
 * \param cred pointer on the cred structure to fill
 * \param msg pointer to the message structure to use
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 */
int
auks_cred_unpack(auks_cred_t* cred,auks_message_t * msg);

/*!
 * @}
*/

#endif
