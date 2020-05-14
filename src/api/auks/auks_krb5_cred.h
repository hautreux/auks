/***************************************************************************\
 * auks_krb5_cred.c - AUKS MIT Kerberos cred API wrapper functions and
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
#ifndef __AUKS_KRB5_CRED_H_
#define __AUKS_KRB5_CRED_H_

/*!
 * \brief Get credential from a credential cache and store it in output buffer
 * \internal
 *
 * \param cachefilename credential cache file (NULL if defaut one must be used)
 * \param p_buffer pointer on a char* buffer that will be allocated and will 
 *        store the credential content
 * \param p_buffer_length pointer on the size of the buffer that will be stored
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_KRB5_CRED_INIT_CTX
 * \retval AUKS_ERROR_KRB5_CRED_OPEN_CC
 * \retval AUKS_ERROR_KRB5_CRED_READ_CC
 * \retval AUKS_ERROR_KRB5_CRED_NO_TGT_FOUND
 * \retval AUKS_ERROR_KRB5_CRED_INIT_AUTH_CTX
 * \retval AUKS_ERROR_KRB5_CRED_MK_CRED
 * \retval AUKS_ERROR_KRB5_CRED_MALLOC
 *
 */
int auks_krb5_cred_get(char *cachefilename,
		       char **p_buffer,size_t *p_buffer_length);

/*!
 * \brief Get forwarded credential for server and store it in output buffer
 * \internal
 *
 * \param server name of the remote server that will be allowed to use the 
 *        credential
 * \param cachefilename credential cache file (NULL if defaut one must be used)
 * \param p_buffer pointer on a char* buffer that will be allocated and will 
 *        store the credential content
 * \param p_buffer_length pointer on the size of the buffer that will be stored
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_KRB5_CRED_INIT_CTX
 * \retval AUKS_ERROR_KRB5_CRED_OPEN_CC
 * \retval AUKS_ERROR_KRB5_CRED_GET_PRINC
 * \retval AUKS_ERROR_KRB5_CRED_INIT_AUTH_CTX
 * \retval AUKS_ERROR_KRB5_CRED_GET_FWD_CRED
 * \retval AUKS_ERROR_KRB5_CRED_RD_CRED
 * \retval AUKS_ERROR_KRB5_CRED_INIT_AUTH_CTX
 * \retval AUKS_ERROR_KRB5_CRED_MK_CRED
 * \retval AUKS_ERROR_KRB5_CRED_MALLOC
 *
 */
int auks_krb5_cred_get_fwd(char *server,char *cachefilename,
		      char **p_buffer,
		      size_t *p_buffer_length);

/*!
 * \brief Store buffered credential into a credential cache
 * \internal
 *
 * \param cachefilename credential cache file (NULL if defaut one must be used)
 * \param buffer pointer on a buffer that contain the credential
 * \param buffer_length buffer length
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_KRB5_CRED_INIT_CTX
 * \retval AUKS_ERROR_KRB5_CRED_INIT_AUTH_CTX
 * \retval AUKS_ERROR_KRB5_CRED_RD_CRED
 * \retval AUKS_ERROR_KRB5_CRED_OPEN_CC
 * \retval AUKS_ERROR_KRB5_CRED_INIT_CC
 * \retval AUKS_ERROR_KRB5_CRED_STORE_CRED
 *
 */
int auks_krb5_cred_store(char *cachefilename,char *buffer,
			 size_t buffer_length);

/*!
 * \brief Renew TGT that is stored in a credential cache
 * \internal
 *
 * \param cachefilename credential cache file (NULL if defaut one must be used)
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_KRB5_CRED_INIT_CTX
 * \retval AUKS_ERROR_KRB5_CRED_OPEN_CC
 * \retval AUKS_ERROR_KRB5_CRED_READ_CC
 * \retval AUKS_ERROR_KRB5_CRED_NO_TGT_FOUND
 * \retval AUKS_ERROR_KRB5_CRED_TGT_HAS_EXPIRED
 * \retval AUKS_ERROR_KRB5_CRED_CP_PRINC
 * \retval AUKS_ERROR_KRB5_CRED_TGT_RENEW
 *
 */
int auks_krb5_cred_renew(char *cachefilename);

/*!
 * \brief Renew TGT of input buffer into a newly allocated one
 * \internal
 *
 * \param in_buf input buffer
 * \param in_buf_len input buffer length
 * \param pout_buf pointer on the output buffer
 * \param pout_buf_len pointer on the output buffer length
 * \param flags additionnal flags for advanced options
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_KRB5_CRED_INIT_CTX
 * \retval AUKS_ERROR_KRB5_CRED_OPEN_CC
 * \retval AUKS_ERROR_KRB5_CRED_READ_CC
 * \retval AUKS_ERROR_KRB5_CRED_NO_TGT_FOUND
 * \retval AUKS_ERROR_KRB5_CRED_TGT_HAS_EXPIRED
 * \retval AUKS_ERROR_KRB5_CRED_CP_PRINC
 * \retval AUKS_ERROR_KRB5_CRED_TGT_RENEW
 *
 */
int auks_krb5_cred_renew_buffer(char *in_buf,size_t in_buf_len,
				char** pout_buf,size_t *pout_buf_len,
				int flags);

/*!
 * \brief Get an addressless forwarded TGT from input buffer into a newly 
 *        allocated one
 * \internal
 *
 * \param in_buf input buffer
 * \param in_buf_len input buffer length
 * \param pout_buf pointer on the output buffer
 * \param pout_buf_len pointer on the output buffer length
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_KRB5_CRED_INIT_CTX
 * \retval AUKS_ERROR_KRB5_CRED_OPEN_CC
 * \retval AUKS_ERROR_KRB5_CRED_READ_CC
 * \retval AUKS_ERROR_KRB5_CRED_NO_TGT_FOUND
 * \retval AUKS_ERROR_KRB5_CRED_TGT_HAS_EXPIRED
 * \retval AUKS_ERROR_KRB5_CRED_CP_PRINC
 * \retval AUKS_ERROR_KRB5_CRED_GET_FWD_CRED
 *
 */
int auks_krb5_cred_deladdr_buffer(char *in_buf,size_t in_buf_len,
				  char** pout_buf,size_t *pout_buf_len);


/*!
 * \brief Generates a new unique ccache usique krb5_cc_new_unique
 * \internal
 *
 * \param fullanme_out pointer on the newly created ccache.
                       Caller's responsibility to free it.
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_KRB5_CRED_INIT_CTX
 * \retval AUKS_ERROR_KRB5_CRED_OPEN_CC
 *
 */
int auks_krb_cc_new_unique(char ** fullname_out);

/*!
 * \brief Destroys the given ccache
 * \internal
 *
 * \param fullanme Name of the ccache to destroy
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_KRB5_CRED_INIT_CTX
 * \retval AUKS_ERROR_KRB5_CRED_OPEN_CC
 * \retval AUKS_ERROR_KRB5_CRED_READ_CC
 *
 */
int auks_krb_cc_destroy(char * fullname);

#endif
