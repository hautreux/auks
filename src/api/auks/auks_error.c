/***************************************************************************\
 * auks_error.c - AUKS error messages implementation
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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <string.h>

#include "auks/auks_error.h"

const char *
auks_strerror(int error)
{

	switch ( error ) {
		
	case AUKS_SUCCESS :
		return "success" ;
		break ;
	case AUKS_ERROR :
		return "generic error" ;
		break ;

	/* -- LIBRARY */
	case AUKS_ERROR_LIBRARY_INIT :
		return "auks library : " "unable to init library structure" ;
		break ;
	case AUKS_ERROR_LIBRARY_UID_NOT_FOUND :
		return "auks library : " "cred with matching uid not found" ;
		break ;
	case AUKS_ERROR_LIBRARY_ADD :
		return "auks library : " "unable to add cred to library" ;
		break ;
	case AUKS_ERROR_LIBRARY_UID_TO_STR :
		return "auks library : " "cred uid to uid_str failure" ;
		break ;

	/* -- BUFFER */
	case AUKS_ERROR_BUFFER_MALLOC :
		return "auks buffer : " "unable to allocate memory" ;
		break ;
	case AUKS_ERROR_BUFFER_REALLOC :
		return "auks buffer : " "unable to reallocate memory" ;
		break ;

	/* -- ACL */
	case AUKS_ERROR_ACL_INIT :
		return "auks acl : " "unable to init acl structure" ;
		break ;
	case AUKS_ERROR_ACL_PARSING :
		return "auks acl : " "unable to parse acl file" ;
		break ;
	case AUKS_ERROR_ACL_IS_FULL :
		return "auks acl : " "acl structure is full" ;
		break ;
	case AUKS_ERROR_ACL_FILE_IS_EMPTY :
		return "auks acl : " "acl file is empty" ;
		break ;
	case AUKS_ERROR_ACL_FILE_IS_INVALID :
		return "auks acl : " "acl file is invalid" ;
		break ;
	case AUKS_ERROR_ACL_RULE_IS_INVALID :
		return "auks acl : " "acl rule is invalid" ;
		break ;

	/* -- AUKS CRED */
	case AUKS_ERROR_CRED_INIT_BUFFER_TOO_LARGE :
		return "auks cred : " "input buffer is too large" ;
		break ;
	case AUKS_ERROR_CRED_INIT_BUFFER_IS_NULL :
		return "auks cred : " "input buffer is null" ;
		break ;
	case AUKS_ERROR_CRED_INIT_KRB_CTX_INIT :
		return "auks cred : " "unable to init krb5 context" ;
		break ;
	case AUKS_ERROR_CRED_INIT_KRB_AUTH_CTX_INIT :
		return "auks cred : " "unable to init krb5 connection context" ;
		break ;
	case AUKS_ERROR_CRED_INIT_KRB_RD_BUFFER :
		return "auks cred : " "unable to read krb5 cred from buffer" ;
		break ;
	case AUKS_ERROR_CRED_INIT_KRB_RD_PRINC :
		return "auks cred : " "unable to unparse principal" ;
		break ;
	case AUKS_ERROR_CRED_INIT_KRB_PRINC_TOO_LONG :
		return "auks cred : " "principal is too long" ;
		break ;
	case AUKS_ERROR_CRED_INIT_KRB_PRINC_TO_UNAME :
		return "auks cred : " "unable to convert principal to local name" ;
		break ;
	case AUKS_ERROR_CRED_INIT_GETPWNAM :
		return "auks cred : " "getpwnam failed" ;
		break ;
	case AUKS_ERROR_CRED_NOT_RENEWABLE :
		return "auks cred : " "credential is not renewable" ;
		break ;
	case AUKS_ERROR_CRED_LIFETIME_TOO_SHORT :
		return "auks cred : " "credential lifetime is too short" ;
		break ;
	case AUKS_ERROR_CRED_EXPIRED :
		return "auks cred : " "credential expired" ;
		break ;
	case AUKS_ERROR_CRED_STILL_VALID :
		return "auks cred : " "credential is still valid" ;
		break ;

	/* -- AUKS CRED REPO*/
	case AUKS_ERROR_CRED_REPO_MUTEX_INIT :
		return "auks cred repo : " "unable to init mutex" ;
		break ;
	case AUKS_ERROR_CRED_REPO_MUTEX_LOCK :
		return "auks cred repo : " "unable to lock mutex" ;
		break ;
	case AUKS_ERROR_CRED_REPO_MUTEX_UNLOCK :
		return "auks cred repo : " "unable to unlock mutex" ;
		break ;
	case AUKS_ERROR_CRED_REPO_CONDITION_INIT :
		return "auks cred repo : " "unable to init condition" ;
		break ;
	case AUKS_ERROR_CRED_REPO_CACHEDIR_IS_NULL :
		return "auks cred repo : " "cachedir is null" ;
		break ;
	case AUKS_ERROR_CRED_REPO_CACHEDIR_INIT :
		return "auks cred repo : " "unable to duplicate cachedir" ;
		break ;
	case AUKS_ERROR_CRED_REPO_CACHEDIR_OPEN :
		return "auks cred repo : " "unable to open cachedir" ;
		break ;
	case AUKS_ERROR_CRED_REPO_CCACHE_BUILD :
		return "auks cred repo : " "unable to build ccache filename" ;
		break ;
	case AUKS_ERROR_CRED_REPO_UNLINK :
		return "auks cred repo : " "unable to unlink ccache" ;
		break ;
	case AUKS_ERROR_CRED_REPO_READONLY :
		return "auks cred repo : " "repo in read-only mode" ;
		break ;
	case AUKS_ERROR_CRED_REPO_UPDATE_INDEX :
		return "auks cred repo : " "unable to update index" ;
		break ;
	case AUKS_ERROR_CRED_REPO_PACK :
		return "auks cred repo : " "unable to pack" ;
		break ;
	case AUKS_ERROR_CRED_REPO_UNPACK :
		return "auks cred repo : " "unable to unpack" ;
		break ;
	case AUKS_ERROR_CRED_REPO_GET_CRED :
		return "auks cred repo : " "unable to get cred" ;
		break ;

	/* -- AUKS MESSAGE */
	case AUKS_ERROR_MESSAGE_MALLOC :
		return "auks msg : " "malloc failed" ;
		break ;
	case AUKS_ERROR_MESSAGE_NULL_BUFFER :
		return "auks msg : " "null buffer" ;
		break ;
	case AUKS_ERROR_MESSAGE_TYPE_MARSH :
		return "auks msg : " "type marshalling failed" ;
		break ;
	case AUKS_ERROR_MESSAGE_TYPE_UNMARSH :
		return "auks msg : " "type unmarshalling failed" ;
		break ;
	case AUKS_ERROR_MESSAGE_SIZE_MARSH :
		return "auks msg : " "size marshalling failed" ;
		break ;
	case AUKS_ERROR_MESSAGE_SIZE_UNMARSH :
		return "auks msg : " "size unmarshalling failed" ;
		break ;
	case AUKS_ERROR_MESSAGE_DATA_MARSH :
		return "auks msg : " "data marshalling failed" ;
		break ;
	case AUKS_ERROR_MESSAGE_DATA_UNMARSH :
		return "auks msg : " "data unmarshalling failed" ;
		break ;

	/* -- AUKS KRB5 CRED */
	case AUKS_ERROR_KRB5_CRED_MALLOC :
		return "krb5 cred : " "unable to allocate memory" ;
		break ;
	case AUKS_ERROR_KRB5_CRED_INIT_CTX :
		return "krb5 cred : " "unable to init context" ;
		break ;
	case AUKS_ERROR_KRB5_CRED_OPEN_CC :
		return "krb5 cred : " "unable to open credential cache" ;
		break ;
	case AUKS_ERROR_KRB5_CRED_READ_CC :
		return "krb5 cred : " "unable to read credential cache" ;
		break ;
	case AUKS_ERROR_KRB5_CRED_INIT_CC :
		return "krb5 cred : " "unable to init credential cache" ;
		break ;
	case AUKS_ERROR_KRB5_CRED_NO_TGT_FOUND :
		return "krb5 cred : " "no TGT found in credential cache" ;
		break ;
	case AUKS_ERROR_KRB5_CRED_INIT_AUTH_CTX :
		return "krb5 cred : " "unable to init connection context" ;
		break ;
	case AUKS_ERROR_KRB5_CRED_MK_CRED :
		return "krb5 cred : " "unable to dump credential to memory" ;
		break ;
	case AUKS_ERROR_KRB5_CRED_RD_CRED :
		return "krb5 cred : " "unable to load credential from memory" ;
		break ;
	case AUKS_ERROR_KRB5_CRED_STORE_CRED :
		return "krb5 cred : " "unable to store credential";
		break ;
	case AUKS_ERROR_KRB5_CRED_GET_PRINC :
		return "krb5 cred : " "unable to get principal" ;
		break ;
	case AUKS_ERROR_KRB5_CRED_CP_PRINC :
		return "krb5 cred : " "unable to copy principal" ;
		break ;
	case AUKS_ERROR_KRB5_CRED_GET_FWD_CRED :
		return "krb5 cred : " "unable to get forwarded credential" ;
		break ;
	case AUKS_ERROR_KRB5_CRED_TGT_HAS_EXPIRED :
		return "krb5 cred : " "TGT has expired";
		break ;
	case AUKS_ERROR_KRB5_CRED_TGT_RENEW :
		return "krb5 cred : " "unable to renew credential";
		break ;
	case AUKS_ERROR_KRB5_CRED_TGT_NOT_RENEWABLE :
		return "krb5 cred : " "TGT not renewable";
		break ;
	case AUKS_ERROR_KRB5_CRED_NO_HOST_SPECIFIED :
		return "krb5 cred : " "no host specified";
		break ;
	case AUKS_ERROR_KRB5_CRED_GET_FWD :
		return "krb5 cred : " "unable to get forwarded cred" ;
		break ;

	/* -- AUKS KRB5 STREAM */
	case AUKS_ERROR_KRB5_STREAM_GETSOCKNAME :
		return "krb5 stream : " "unable to get socket local endpoint information" ;
		break ;
	case AUKS_ERROR_KRB5_STREAM_GETPEERNAME :
		return "krb5 stream : " "unable to get socket remote endpoint information" ;
		break ;
	case AUKS_ERROR_KRB5_STREAM_INIT_CTX :
		return "krb5 stream : " "unable to init context" ;
		break ;
	case AUKS_ERROR_KRB5_STREAM_INIT_AUTH_CTX :
		return "krb5 stream : " "unable to init connection context" ;
		break ;
	case AUKS_ERROR_KRB5_STREAM_INIT_CC :
		return "krb5 stream : " "unable to open credential cache" ;
		break ;
	case AUKS_ERROR_KRB5_STREAM_INIT_KT :
		return "krb5 stream : " "unable to open keytab" ;
		break ;
	case AUKS_ERROR_KRB5_STREAM_CTX_SETADDR :
		return "krb5 stream : " "unable to set connection ctx addresses" ;
		break ;
	case AUKS_ERROR_KRB5_STREAM_CTX_SETFLAGS :
		return "krb5 stream : " "unable to set connection ctx flags" ;
		break ;
	case AUKS_ERROR_KRB5_STREAM_CTX_SETRCACHE :
		return "krb5 stream : " "unable to set connection replay cache" ;
		break ;
	case AUKS_ERROR_KRB5_STREAM_CTX_GETPRINC :
		return "krb5 stream : " "unable to get principal" ;
		break ;
	case AUKS_ERROR_KRB5_STREAM_CTX_SETPRINC :
		return "krb5 stream : " "unable to set principal" ;
		break ;
	case AUKS_ERROR_KRB5_STREAM_CTX_SENDAUTH :
		return "krb5 sendauth stage failed (client side)" ;
		break ;
	case AUKS_ERROR_KRB5_STREAM_CTX_RECVAUTH :
		return "krb5 stream : " "recvauth stage failed (server side)" ;
		break ;
	case AUKS_ERROR_KRB5_STREAM_CTX_AUTH_TOKEN :
		return "krb5 stream : " "unable to get connection authenticator (server side)" ;
		break ;
	case AUKS_ERROR_KRB5_STREAM_CP_PRINC :
		return "krb5 stream : " "unable to copy principal" ;
		break ;
	case AUKS_ERROR_KRB5_STREAM_PRINC_TOO_LONG :
		return "krb5 stream : " "principal is too long" ;
		break ;
	case AUKS_ERROR_KRB5_STREAM_CTX_MKPRIV :
		return "krb5 stream : " "unable to cyphered data" ;
		break ;
	case AUKS_ERROR_KRB5_STREAM_CTX_RDPRIV :
		return "krb5 stream : " "unable to decyphered data" ;
		break ;
	case AUKS_ERROR_KRB5_STREAM_CTX_WRITE :
		return "krb5 stream : " "unable to write data" ;
		break ;
	case AUKS_ERROR_KRB5_STREAM_CTX_READ :
		return "krb5 stream : " "unable to read data" ;
		break ;
	case AUKS_ERROR_KRB5_STREAM_DATA_TOO_LARGE :
		return "krb5 stream : " "transfered data too large" ;
		break ;
	case AUKS_ERROR_KRB5_STREAM_MALLOC :
		return "unable to allocate memory in krb5 stream" ;
		break ;
	case AUKS_ERROR_KRB5_STREAM_NOT_AUTHENTICATED :
		return "krb5 stream : " "not yet authenticated" ;
		break ;

	/* -- AUKS ENGINE */
	case AUKS_ERROR_ENGINE_CONFFILE_PARSING :
		return "unable to parse configuration file" ;
		break ;
	case AUKS_ERROR_ENGINE_CONFFILE_INVALID :
		return "no configuration blocks found in configuration file";
		break ;
	case AUKS_ERROR_ENGINE_CONFFILE_INCOMPLETE :
		return "configuration file is incomplete";
		break ;

	/* -- AUKS API */	
	case AUKS_ERROR_API_REQUEST_INIT :
		return "auks api : " "unable to init request" ;
		break ;
	case AUKS_ERROR_API_REQUEST_PROCESSING :
		return "auks api : " "request processing failed" ;
		break ;
	case AUKS_ERROR_API_REQUEST_PACK_UID :
		return "auks api : " "unable to pack uid" ;
		break ;
	case AUKS_ERROR_API_REQUEST_PACK_CRED :
		return "auks api : " "unable to pack credential" ;
		break ;
	case AUKS_ERROR_API_REPLY_PROCESSING :
		return "auks api : " "reply processing failed" ;
		break ;
	case AUKS_ERROR_API_EMPTY_REQUEST :
		return "auks api : " "request payload is empty" ;
		break ;
	case AUKS_ERROR_API_CONNECTION_FAILED :
		return "auks api : " "connection failed" ;
		break ;
	case AUKS_ERROR_API_INVALID_REPLY :
		return "auks api : " "reply type is invalid" ;
		break ;
	case AUKS_ERROR_API_CORRUPTED_REPLY :
		return "auks api : " "reply seems corrupted" ;
		break ;

	/* AUKSD */
	case AUKS_ERROR_DAEMON_NOT_VALID_SERVER :
		return "auksd : " "current host is not an auks server" ;
		break ;
	case AUKS_ERROR_DAEMON_STREAM_CREATION :
		return "auksd : " "unable to create stream socket" ;
		break ;
	case AUKS_ERROR_DAEMON_THREAD_CONFIG :
		return "auksd : " "unable to configure threads attr" ;
		break ;
	case AUKS_ERROR_DAEMON_THREAD_DATA :
		return "auksd : " "unable to create threads data" ;
		break ;

	case AUKS_ERROR_DAEMON_REQUEST_UNPACK_UID :
		return "auksd : " "unable to unpack uid" ;
		break ;
	case AUKS_ERROR_DAEMON_REQUEST_UNPACK_CRED :
		return "auksd : " "unable to unpack cred" ;
		break ;
	case AUKS_ERROR_DAEMON_REQUEST_DONE :
		return "auksd : " "request is done" ;
		break ;

	case AUKS_ERROR_DAEMON_UNKNOWN_REQUEST :
		return "auksd : " "unknown request type" ;
		break ;
	case AUKS_ERROR_DAEMON_CORRUPTED_REQUEST :
		return "auksd : " "request is corrupted" ;
		break ;
	case AUKS_ERROR_DAEMON_PROCESSING_REQUEST :
		return "auksd : " "error while processing request" ;
		break ;
	case AUKS_ERROR_DAEMON_PRINCIPALS_MISMATCH :
		return "auksd : " "requester principals mismatches cred 's one" ;
		break ;
	case AUKS_ERROR_DAEMON_NOT_AUTHORIZED :
		return "auksd : " "requester is not authorized to do that" ;
		break ;
	case AUKS_ERROR_DAEMON_ADDRESSFUL_CRED :
		return "auksd : " "received credential is not addressless" ;
		break ;

	case AUKS_ERROR_DAEMON_REPLY_INIT :
		return "auksd : " "reply init failed" ;
		break ;
	case AUKS_ERROR_DAEMON_REPLY_TRANSMISSION :
		return "auksd : " "reply transmission failed" ;
		break ;

	case AUKS_ERROR_DAEMON_RENEW_IN_PROGRESS :
		return "renew in progress" ;
		break ;

	default:
		return "unknown error";
		break;
	}

}
