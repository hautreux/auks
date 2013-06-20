/***************************************************************************\
 * auks_cred.h - AUKS kerberos credential repository functions and 
 * structures definitions
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
#ifndef __AUKS_CRED_REPO_H_
#define __AUKS_CRED_REPO_H_

/* multihtreading support */
#include <pthread.h>

/* cred repo implemented using a freelist */
#include "xternal/xlibrary.h"

#include "auks/auks_error.h"
#include "auks/auks_cred.h"
#include "auks/auks_message.h"

/*! \addtogroup AUKS_CRED_REPO
 *  @{
 */

#define AUKS_CRED_CACHE_FILE_PATTERN "%s/aukscc_%d"
#define AUKS_CRED_CACHE_FILE_MOTIF "aukscc_*"

typedef struct auks_cred_repo {
	pthread_mutex_t mutex;	//!< repo mutex
	pthread_cond_t condition;	//!< repo mutex condition
	char *cachedir;		//!< directory where creds are stored
	int read_only;		//!< flag that indicates if repo is in 
	                        //1< read-only mode
	xlibrary_t library;	//!< internal structure used to managed records
} auks_cred_repo_t;

/*!
 * \brief Create an auks cred repo
 *
 * \param cred_repo auks cred repo structure to init
 * \param cachedir directory for data cache
 * \param default_length default number of element
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_CRED_REPO_CACHEDIR_IS_NULL
 * \retval AUKS_ERROR_CRED_REPO_CACHEDIR_INIT
 * \retval AUKS_ERROR_CRED_REPO_MUTEX_INIT
 * \retval AUKS_ERROR_CRED_REPO_CONDITION_INIT
 * \retval AUKS_ERROR_LIBRARY_INIT
 *
 */
int auks_cred_repo_init(auks_cred_repo_t * cred_repo,
			char *cachedir, unsigned int default_length);

/*!
 * \brief Free an auks cred_repo contents
 *
 * \param cred_repo auks cred repo to free contents of
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 *
 */
int auks_cred_repo_free_contents(auks_cred_repo_t * cred_repo);

/*!
 * \brief Add an auks cred to a repo
 *
 * \param cred_repo pointer on the destination auks cred repo structure
 * \param cred cred to add to the repo
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_CRED_REPO_MUTEX_LOCK
 * \retval AUKS_ERROR_LIBRARY_ADD
 * \retval AUKS_ERROR_CRED_REPO_CCACHE_BUILD
 * \retval see auks_krb5_cred_store
 *
 */
int auks_cred_repo_add(auks_cred_repo_t * cred_repo, auks_cred_t * cred);

/*!
 * \brief Get an auks cred from a repo based on associated uid value
 *
 * \param cred_repo pointer on the destination auks cred repo structure
 * \param uid user uid of the requested cred
 * \param cred pointer on a cred structure to write data into
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_CRED_REPO_MUTEX_LOCK
 * \retval AUKS_ERROR_LIBRARY_UID_NOT_FOUND
 *
 */
int
auks_cred_repo_get(auks_cred_repo_t * cred_repo,
		   uid_t uid, auks_cred_t * cred);

/*!
 * \brief Remove an auks cred from a repo based on associated uid value
 *
 * \param cred_repo pointer on the auks cred repo structure to use
 * \param uid user uid of the requested cred
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_CRED_REPO_MUTEX_LOCK
 * \retval AUKS_ERROR_LIBRARY_UID_NOT_FOUND
 * \retval AUKS_ERROR_CRED_REPO_CCACHE_BUILD
 * \retval AUKS_ERROR_CRED_REPO_UNLINK
 *
 */
int auks_cred_repo_remove(auks_cred_repo_t * cred_repo, uid_t uid);

/*!
 * \brief Load cred repo content from data in cache
 *
 * \param cred_repo auks cred repo structure to use
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_CRED_REPO_CACHEDIR_IS_NULL
 * \retval AUKS_ERROR_CRED_REPO_CACHEDIR_OPEN
 *
 */
int
auks_cred_repo_load_cache(auks_cred_repo_t * cred_repo);

/*!
 * \brief Clean an auks cred repo (remove obsolete credentials)
 *
 * \param cred_repo pointer on the auks cred repo structure to clean
 * \param pnb pointer on the number of cleaned creds
 *
 * \retval nb > 0 the number of cleaned auks cred
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR...
 *
 */
int auks_cred_repo_clean(auks_cred_repo_t * cred_repo,int* pnb);

/*!
 * \brief Pack an auks cred repo into a message
 *
 * \param cred_repo pointer on the auks cred repo structure to use
 * \param msg msg that will receive packed creds
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR...
 *
 */
int auks_cred_repo_pack(auks_cred_repo_t * cred_repo,auks_message_t* msg);

/*!
 * \brief Lock an auks cred repository
 *
 * \param cred_repo auks cred repo structure to use
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_CRED_REPO_MUTEX_LOCK
 *
 */
int
auks_cred_repo_lock(auks_cred_repo_t * cr);

/*!
 * \brief Unlock an auks cred repository
 *
 * \param cred_repo auks cred repo structure to use
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_CRED_REPO_MUTEX_LOCK
 *
 */
int
auks_cred_repo_unlock(auks_cred_repo_t * cr);

/*!
 * \brief Build auks cred cache filename by uid
 *
 * \param cred_repo auks cred repo structure to use
 * \param uid uid of the auks cred cache user
 * \param filename char* to fill with auks cred cache filename
 * \param max_length max number of char that can be write
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_CRED_REPO_CCACHE_BUILD
 *
 */
int
auks_cred_repo_auks_credfile(auks_cred_repo_t * cr,uid_t uid,
			     char* filename,size_t max_length);

/*!
 * \brief Build auks renewer cred cache filename by id
 *
 * \param cred_repo auks cred repo structure to use
 * \param id id of the auks renewer
 * \param filename char* to fill with auks cred cache filename
 * \param max_length max number of char that can be write
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_CRED_REPO_CCACHE_BUILD
 *
 */
int
auks_cred_repo_renewer_credfile(auks_cred_repo_t * cr,int id,
				char* filename,size_t max_length);

/*!
 * \brief Add an auks cred to a repo
 * (lock free)
 *
 * \param cred_repo pointer on the destination auks cred repo structure
 * \param cred cred to add to the repo
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_CRED_REPO_MUTEX_LOCK
 * \retval AUKS_ERROR_LIBRARY_ADD
 * \retval AUKS_ERROR_LIBRARY_UID_TO_STR
 * \retval AUKS_ERROR_CRED_REPO_CCACHE_BUILD
 * \retval see auks_krb5_cred_store
 *
 */
int auks_cred_repo_add_nolock(auks_cred_repo_t * cred_repo, auks_cred_t * cred);

/*!
 * \brief Get an auks cred from a repo based on associated uid value
 * (lock free)
 *
 * \param cred_repo pointer on the destination auks cred repo structure
 * \param uid user uid of the requested cred
 * \param cred pointer on a cred structure to write data into
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_CRED_REPO_MUTEX_LOCK
 * \retval AUKS_ERROR_LIBRARY_UID_NOT_FOUND
 * \retval AUKS_ERROR_LIBRARY_UID_TO_STR
 *
 */
int
auks_cred_repo_get_nolock(auks_cred_repo_t * cred_repo,
			  uid_t uid, auks_cred_t * cred);

/*!
 * \brief Remove an auks cred from a repo based on associated uid value
 * (lock free)
 *
 * \param cred_repo pointer on the auks cred repo structure to use
 * \param uid user uid of the requested cred
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_CRED_REPO_MUTEX_LOCK
 * \retval AUKS_ERROR_LIBRARY_UID_NOT_FOUND
 * \retval AUKS_ERROR_LIBRARY_UID_TO_STR
 * \retval AUKS_ERROR_CRED_REPO_CCACHE_BUILD
 * \retval AUKS_ERROR_CRED_REPO_UNLINK
 *
 */
int auks_cred_repo_remove_nolock(auks_cred_repo_t * cred_repo, uid_t uid);

/*!
 * \brief Pack an auks cred repo into a message
 * (lock free)
 *
 * \param cred_repo pointer on the auks cred repo structure to use
 * \param msg msg that will receive packed creds
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR...
 *
 */
int auks_cred_repo_pack_nolock(auks_cred_repo_t * cred_repo,auks_message_t* msg);

/*!
 * \brief Clean an auks cred repo (remove obsolete credentials) 
 * (lock free)
 *
 * \param cred_repo pointer on the auks cred repo structure to clean
 * \param pnb pointer on the number of cleaned creds
 *
 * \retval nb > 0 the number of cleaned auks cred
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR...
 *
 */
int auks_cred_repo_clean_nolock(auks_cred_repo_t * cred_repo,int *pnb);

/*!
 * @}
*/

#endif
