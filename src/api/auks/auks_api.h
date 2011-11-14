/***************************************************************************\
 * auks_api.h - AUKS API function and structures definitions
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
#ifndef __AUKS_API_H_
#define __AUKS_API_H_

/*! \addtogroup AUKS_API
 *  @{
 */

#include "auks/auks_engine.h"
#include "auks/auks_cred.h"
#include "auks/auks_message.h"

#define AUKS_API_RENEW_ONCE    0
#define AUKS_API_RENEW_LOOP    1

/*!
 * \brief Initialise the Auks API
 *
 * \param engine pointer on the engine structure to initialize
 * \param conf_file optional configuration file to use
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_...
 */
int
auks_api_init(auks_engine_t* engine,char * conf_file);

/*!
 * \brief Set the kerberos credential cache to use for kerberos client ops
 *
 * \param engine pointer on the engine structure to use
 * \param ccache credential file to use
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 */
int
auks_api_set_ccache(auks_engine_t* engine,char * ccache);

/*!
 * \brief Set the logfile to use in the API
 *
 * \param engine pointer on the engine structure to use
 * \param logfile log destination file
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 */
int
auks_api_set_logfile(auks_engine_t* engine,char * logfile);

/*!
 * \brief Set the log level to use in the API
 *
 * \param engine pointer on the engine structure to use
 * \param loglevel level
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 */
int
auks_api_set_loglevel(auks_engine_t* engine,int loglevel);

/*!
 * \brief Close the Auks API
 *
 * \param engine pointer on the engine structure to free contents of
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_...
 */
int
auks_api_close(auks_engine_t* engine);

/*!
 * \brief Send a ping request to one of the Auks server
 *
 * \param engine pointer on the engine structure to use
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_...
 */
int
auks_api_ping(auks_engine_t * engine);

/*!
 * \brief Add a credential on one of the Auks server
 *
 * \param engine pointer on the engine structure to use
 * \param cred_cache optional file containing cred cache to add
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_...
 */
int
auks_api_add_cred(auks_engine_t * engine,char* cred_cache);

/*!
 * \brief Add a auks credential on one of the Auks server
 *
 * \param engine pointer on the engine structure to use
 * \param cred auks cred to send
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_...
 */
int
auks_api_add_auks_cred(auks_engine_t * engine,auks_cred_t* cred);

/*!
 * \brief Get a credential from one of the Auks server
 *
 * \param engine pointer on the engine structure to use
 * \param uid associated uid of the credential to get from Auks
 * \param cred_cache optional file in which to store the gotten credential
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_...
 */
int
auks_api_get_cred(auks_engine_t * engine,uid_t uid,char* cred_cache);

/*!
 * \brief Get a auks credential from one of the Auks server
 *
 * \param engine pointer on the engine structure to use
 * \param uid associated uid of the credential to get from Auks
 * \param cred_cache optional file in which to store the gotten credential
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_...
 */
int
auks_api_get_auks_cred(auks_engine_t * engine,uid_t uid,auks_cred_t* cred);

/*!
 * \brief Renew a credential using one of the Auks server
 *
 * \param engine pointer on the engine structure to use
 * \param cred_cache optional file in which to store the gotten credential
 * \param mode one of the following values
 *        AUKS_API_RENEW_ONCE
 *        AUKS_API_RENEW_UNTIL_EXPIRATION
 *        AUKS_API_RENEW_UNTIL_REMOVAL
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_...
 */
int
auks_api_renew_cred(auks_engine_t * engine,char* cred_cache,int mode);

/*!
 * \brief Send a remove request to one of the Auks server
 *
 * \param engine pointer on the engine structure to use
 * \param uid associated uid of the credential to remove from Auks
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_...
 */
int
auks_api_remove_cred(auks_engine_t * engine,uid_t uid);

/*!
 * \brief Send a dump request to one of the Auks server
 *
 * \param engine pointer on the engine structure to use
 * \param pcreds pointer on an array of auks cred that will be malloced
 *        in case of success
 * \param pcreds_nb pointer on an int that will be filled with creds nb
 *        in case of success
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_...
 */
int
auks_api_dump(auks_engine_t * engine,auks_cred_t** pcreds,int* pcreds_nb);

/*!
 * \brief Build auks cred array from a dump message
 *
 * \param msg msg that contains the dumped auks creds
 * \param pcreds pointer on an array of auks cred that will be malloced
 *        in case of success
 * \param pcreds_nb pointer on an int that will be filled with creds nb
 *        in case of success
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_...
 */
int
auks_api_dump_unpack(auks_message_t* msg,auks_cred_t** pcreds,int* pcreds_nb);

/*!
 * @}
*/
#endif
