/***************************************************************************\
 * auks_krb5_stream.c - AUKS MIT Kerberos communication API wrapper functions
 * and structures definitions
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
#ifndef __AUKS_KRB5_STREAM_H_
#define __AUKS_KRB5_STREAM_H_

#include <limits.h>

#define KRB5_PRIVATE 1
#include "krb5.h"

#define AUKS_KRB5_PROTOCOL_VERSION "0.1"

#define AUKS_PRINCIPAL_MAX_LENGTH     128
#define AUKS_KRB5_UNKNOWN_STREAM        0
#define AUKS_KRB5_CLIENT_STREAM         1
#define AUKS_KRB5_SERVER_STREAM         2

#define AUKS_KRB5_STREAM_NAT_TRAVERSAL 0x0001

typedef struct auks_krb5_stream {
	int type;  /* AUKS_KRB5_CLIENT_STREAM  |  AUKS_KRB5_SERVER_STREAM */
	int stream;
	krb5_context context;
	int context_flag;
	krb5_auth_context auth_context;
	int auth_context_flag;
	int authenticated;
	krb5_principal local_principal;
	int local_principal_flag;
	krb5_principal remote_principal;
	int remote_principal_flag;
	char remote_host[HOST_NAME_MAX + 1];
	krb5_ccache ccache;
	int ccache_flag;
	krb5_keytab keytab;
	int keytab_flag;
	int flags;
} auks_krb5_stream_t;


/*!
 * \brief Initialize auks_krb5_stream structure (client side)
 * \internal
 *
 * \param kstream auks_krb5_stream_t structure to initialize
 * \param stream stream established between client and server
 * \param principal string that represent Kerberos client identity 
 *        (Ex:john@REALM.ORG) to use
 * \param ccache string that represent Kerberos V credential file
 * \param flags additional flags for krb5 stream initialization
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_KRB5_STREAM_GETSOCKNAME
 * \retval AUKS_ERROR_KRB5_STREAM_GETPEERNAME
 * \retval AUKS_ERROR_KRB5_STREAM_INIT_CTX
 * \retval AUKS_ERROR_KRB5_STREAM_INIT_AUTH_CTX
 * \retval AUKS_ERROR_KRB5_STREAM_CTX_SETADDR
 * \retval AUKS_ERROR_KRB5_STREAM_CTX_SETFLAGS
 * \retval AUKS_ERROR_KRB5_STREAM_INIT_CC
 * \retval AUKS_ERROR_KRB5_STREAM_CTX_SETPRINC
 *  
 */
int
auks_krb5_stream_clnt_init(auks_krb5_stream_t * kstream, int stream,
			   char *principal, char *ccache,int flags);

/*!
 * \brief Initialize auks_krb5_stream structure (server side)
 * \internal
 *
 * \param kstream auks_krb5_stream_t structure to initialize
 * \param stream stream established between client and server
 * \param principal string that represent Kerberos server identity 
 *        (Ex:host/server@REALM.ORG)
 * \param keytab string that represent Kerberos V keytab file containing 
 *        server keys
 * \param flags additional flags for krb5 stream initialization
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_KRB5_STREAM_GETSOCKNAME
 * \retval AUKS_ERROR_KRB5_STREAM_GETPEERNAME
 * \retval AUKS_ERROR_KRB5_STREAM_INIT_CTX
 * \retval AUKS_ERROR_KRB5_STREAM_INIT_AUTH_CTX
 * \retval AUKS_ERROR_KRB5_STREAM_CTX_SETADDR
 * \retval AUKS_ERROR_KRB5_STREAM_CTX_SETFLAGS
 * \retval AUKS_ERROR_KRB5_STREAM_INIT_KT
 * \retval AUKS_ERROR_KRB5_STREAM_CTX_SETPRINC
 *  
 */
int
auks_krb5_stream_srv_init(auks_krb5_stream_t * kstream, int stream,
			  char *principal, char *keytab,int flags);

/*!
 * \brief Free auks_krb5_stream structure contents
 * \internal
 *
 * \param kstream auks_krb5_stream_t structure to free
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 *  
 */
int auks_krb5_stream_free_contents(auks_krb5_stream_t * kstream);

/*!
 * \brief Make Kerberos authentication stage using auks_krb5_stream structure
 * (on server side, remote principal can be accessed only after a valid 
 * authentication)
 * \internal
 *
 * \param kstream auks_krb5_stream_t structure to use for authentication
 * \param remote_principal string that represent Kerberos server identity 
 *        (used on client side only)
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_KRB5_STREAM_CTX_SETPRINC
 * \retval AUKS_ERROR_KRB5_STREAM_CTX_SENDAUTH
 * \retval AUKS_ERROR_KRB5_STREAM_CTX_RECVAUTH
 * \retval AUKS_ERROR_KRB5_STREAM_CTX_AUTH_TOKEN
 * \retval AUKS_ERROR_KRB5_STREAM_CP_PRINC
 *
 */
int
auks_krb5_stream_authenticate(auks_krb5_stream_t * kstream,
			      char *remote_principal);

/*!
 * \brief Get local principal name from auks_krb5_stream structure
 * \internal
 *
 * \param kstream auks_krb5_stream_t structure to use for authentication
 * \param principal_name output string
 * \param max_size maximum length of string that can be stored in principal_name
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_KRB5_STREAM_CTX_GETPRINC
 * \retval AUKS_ERROR_KRB5_STREAM_PRINC_TOO_LONG
 *
 */
int
auks_krb5_stream_get_lprinc(auks_krb5_stream_t * kstream,
			    char *principal_name, size_t max_size);

/*!
 * \brief Get remote principal name from auks_krb5_stream structure
 * \internal
 *
 * \param kstream auks_krb5_stream_t structure to use for authentication
 * \param principal_name output string
 * \param max_size maximum length of string that can be stored in principal_name
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_KRB5_STREAM_CTX_GETPRINC
 * \retval AUKS_ERROR_KRB5_STREAM_PRINC_TOO_LONG
 *
 */
int
auks_krb5_stream_get_rprinc(auks_krb5_stream_t * kstream,
			    char *principal_name, size_t max_size);

/*!
 * \brief Send data using auks_krb5_stream structure
 * \internal
 *
 * \param kstream auks_krb5_stream_t structure to use
 * \param data char* array to send
 * \param data_size number of element to send
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_KRB5_STREAM_NOT_AUTHENTICATED
 * \retval AUKS_ERROR_KRB5_STREAM_CTX_MKPRIV
 * \retval AUKS_ERROR_KRB5_STREAM_CTX_WRITE
 *
 */
int
auks_krb5_stream_send(auks_krb5_stream_t * kstream, char *data,
		      size_t data_size);

/*!
 * \brief Receive data using auks_krb5_stream structure
 * \internal
 *
 * \param kstream auks_krb5_stream_t structure to use
 * \param data char* array for reception
 * \param data_size number of element to receive
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_KRB5_STREAM_NOT_AUTHENTICATED
 * \retval AUKS_ERROR_KRB5_STREAM_CTX_READ
 * \retval AUKS_ERROR_KRB5_STREAM_CTX_RDPRIV
 * \retval AUKS_ERROR_KRB5_STREAM_DATA_TOO_LARGE
 *
 */
int
auks_krb5_stream_receive(auks_krb5_stream_t * kstream, char *data,
			 size_t data_size);

/*!
 * \brief Send a message using auks_krb5_stream structure
 * \internal
 *
 * \param kstream auks_krb5_stream_t structure to use
 * \param data char* message to send
 * \param data_size message length
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_KRB5_STREAM_NOT_AUTHENTICATED
 * \retval AUKS_ERROR_KRB5_STREAM_CTX_MKPRIV
 * \retval AUKS_ERROR_KRB5_STREAM_CTX_WRITE
 *
 */
int
auks_krb5_stream_send_msg(auks_krb5_stream_t * kstream, char *data,
			  size_t data_size);

/*!
 * \brief Receive a message using auks_krb5_stream structure
 * \internal
 *
 * \param kstream auks_krb5_stream_t structure to use
 * \param data char** pointer on the message that will be malloced
 * \param data_size pointer on the message length that will be modified
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 * \retval AUKS_ERROR_KRB5_STREAM_NOT_AUTHENTICATED
 * \retval AUKS_ERROR_KRB5_STREAM_CTX_READ
 * \retval AUKS_ERROR_KRB5_STREAM_CTX_RDPRIV
 * \retval AUKS_ERROR_KRB5_STREAM_MALLOC
 *
 */
int
auks_krb5_stream_receive_msg(auks_krb5_stream_t * kstream, char **data,
			     size_t *data_size);

#endif
