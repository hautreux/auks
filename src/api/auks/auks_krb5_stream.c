/***************************************************************************\
 * auks_krb5_stream.c - AUKS MIT Kerberos communication API wrapper 
 * implementation
 * based on external xstream implementation
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

/* getpeername|getsockname|ntohl|htonl */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* kerberos support */
#define KRB5_PRIVATE 1
#include <krb5.h>

#include <errno.h>
extern int errno;
#define STR_ERROR_SIZE 512
#define DUMP_ERROR(e,s,S) if(strerror_r(e,s,S)) { s[0]='-';s[1]='\0';}

#define AUKS_LOG_HEADER "auks_krb5_stream: "
#define AUKS_LOG_BASE_LEVEL 4
#define AUKS_LOG_DEBUG_LEVEL 4

#include "auks/auks_error.h"
#include "auks/auks_krb5_stream.h"
#include "auks/auks_log.h"


/* private functions definitions */
#define LOCAL_PRINCIPAL 1
#define REMOTE_PRINCIPAL 2

int
auks_krb5_stream_init_base(auks_krb5_stream_t * kstream, int stream,
			   int flags);

int
auks_krb5_stream_clnt_auth(auks_krb5_stream_t * kstream,
			   char *remote_principal);

int
auks_krb5_stream_srv_auth(auks_krb5_stream_t * kstream,
			  char *remote_principal);

int
auks_krb5_stream_get_principal_name(auks_krb5_stream_t * kstream,
				    char *principal_name, size_t max_size,
				    int which_principal);

/* public functions implementations */
int auks_krb5_stream_free_contents(auks_krb5_stream_t * kstream)
{
	int fstatus = AUKS_ERROR ;

	krb5_error_code kstatus;

	if (kstream->local_principal_flag)
		krb5_free_principal(kstream->context,
				    kstream->local_principal);

	if (kstream->remote_principal_flag)
		krb5_free_principal(kstream->context,
				    kstream->remote_principal);

	if (kstream->ccache_flag)
		krb5_cc_close(kstream->context, kstream->ccache);

	if (kstream->keytab_flag)
		krb5_kt_close(kstream->context, kstream->keytab);

	if (kstream->auth_context_flag == 1) {
		krb5_auth_con_free(kstream->context,
				   kstream->auth_context);
	}

	if (kstream->context_flag == 1)
		krb5_free_context(kstream->context);

	/* nullify params flag */
	kstream->context_flag = 0;
	kstream->auth_context_flag = 0;
	kstream->local_principal_flag = 0;
	kstream->remote_principal_flag = 0;
	kstream->ccache_flag = 0;
	kstream->keytab_flag = 0;

	kstream->type = AUKS_KRB5_UNKNOWN_STREAM;
	kstream->stream = -1;
	kstream->authenticated = 0;

	fstatus = AUKS_SUCCESS ;

	return fstatus;
}


/*!
 * \brief Initialize auks_krb5_stream structure (client side)
 * \internal
 *
 * \param kstream auks_krb5_stream_t structure to initialize
 * \param stream stream established between client and server
 * \param principal string that represent Kerberos client identity 
 *        (Ex:john@REALM.ORG) to use
 * \param ccache string that represent Kerberos V credential file
 *
 * \retval 0 on success
 * \retval -1 on failure
 *  
 */
int
auks_krb5_stream_clnt_init(auks_krb5_stream_t * kstream, int stream,
			   char *principal, char *ccache, int flags)
{

	int fstatus;

	krb5_error_code kstatus;
	
	/* set kstream type */
	kstream->type = AUKS_KRB5_CLIENT_STREAM;
	
	/* init basic auks_krb5_stream infos */
	fstatus = auks_krb5_stream_init_base(kstream,stream,flags) ;
	if ( fstatus != AUKS_SUCCESS ) {
		auks_error("kstream basic initialisation failed");
		goto exit;
	}
	auks_log("kstream basic initialisation succeed");

	/* kerberos : initialize credential cache structure */
	if (ccache == NULL)
		kstatus = krb5_cc_default(kstream->context,
					  &kstream->ccache);
	else
		kstatus = krb5_cc_resolve(kstream->context, ccache,
					  &kstream->ccache);
	if (kstatus) {
		auks_error("ccache initialisation failed : %s",
		      error_message(kstatus));
		fstatus = AUKS_ERROR_KRB5_STREAM_INIT_CC ;
		goto init_exit;
	}
	kstream->ccache_flag = 1;
	auks_log("ccache initialisation succeed");

	/* kerberos : initialize client principal structure */
	if (principal == NULL)
		kstatus = krb5_cc_get_principal(kstream->context,
						kstream->ccache,
						&kstream->local_principal);
	else
		kstatus = krb5_parse_name(kstream->context,principal,
					  &kstream->local_principal);
	if (kstatus) {
		auks_error("principal initialisation failed : %s",
		      error_message(kstatus));
		fstatus = AUKS_ERROR_KRB5_STREAM_CTX_SETPRINC ;
		goto cc_exit;
	}
	kstream->local_principal_flag = 1;
	auks_log("client kstream initialisation succeed");

	fstatus = AUKS_SUCCESS ;

cc_exit:
	if ( fstatus != AUKS_SUCCESS ) {
		krb5_cc_close(kstream->context,kstream->ccache);
		kstream->ccache_flag = 0;
	}

init_exit:
	if ( fstatus != AUKS_SUCCESS )
		auks_krb5_stream_free_contents(kstream);

exit:
	return fstatus;

}


int
auks_krb5_stream_srv_init(auks_krb5_stream_t * kstream, int stream,
			  char *principal, char *keytab,int flags)
{

	int fstatus;

	krb5_error_code kstatus;

	/* set kstream type */
	kstream->type = AUKS_KRB5_SERVER_STREAM ;

	/* init basic auks_krb5_stream infos */
	fstatus = auks_krb5_stream_init_base(kstream,stream,flags);
	if (fstatus) {
		auks_error("kstream basic initialisation failed");
		goto exit;
	}
	auks_log("kstream basic initialisation succeed");

	/* kerberos : initialize credential cache structure */
	if (keytab == NULL)
		kstatus = krb5_kt_default(kstream->context,
					  &kstream->keytab);
	else
		kstatus = krb5_kt_resolve(kstream->context, keytab,
					  &kstream->keytab);
	if (kstatus) {
		auks_error("keytab initialisation failed : %s",
		      error_message(kstatus));
		fstatus = AUKS_ERROR_KRB5_STREAM_INIT_KT ;
		goto init_exit;
	}
	kstream->keytab_flag = 1;
	auks_log("keytab initialisation succeed");
	
	/* kerberos : initialize client principal structure */
	if (principal != NULL)
		kstatus = krb5_parse_name(kstream->context,principal,
					  &kstream->
					  local_principal);
	if (kstatus) {
		auks_error("principal initialisation failed : %s",
		      error_message(kstatus));
		fstatus = AUKS_ERROR_KRB5_STREAM_CTX_SETPRINC ;
		goto kt_exit;
	} else {
		kstream->local_principal_flag = 1;
		auks_log("server kstream initialisation succeed");
		fstatus = AUKS_SUCCESS ;
	}
	
kt_exit:
	if ( fstatus != AUKS_SUCCESS ) {
		krb5_kt_close(kstream->context,kstream->keytab);
		kstream->keytab_flag = 0;
	}

init_exit:
	if ( fstatus != AUKS_SUCCESS )
		auks_krb5_stream_free_contents(kstream);

exit:
	return fstatus;

}

int
auks_krb5_stream_authenticate(auks_krb5_stream_t * kstream,
			      char *remote_principal)
{
	int fstatus;

	krb5_error_code kstatus;
	krb5_address klocal_addr;
	krb5_address kremote_addr;

	switch (kstream->type) {
		
	case AUKS_KRB5_CLIENT_STREAM:
		fstatus =
			auks_krb5_stream_clnt_auth(kstream,remote_principal);
		break;
		
	case AUKS_KRB5_SERVER_STREAM:
		fstatus =
			auks_krb5_stream_srv_auth(kstream,remote_principal);
		break;
		
	default:
		break;
		
	}

	if ( fstatus == AUKS_SUCCESS ) {

		/* if NAT traversal is required, we have to use dummy */
		/* addresses because krb5 protocol check those addresses */
		/* while cyphering and decyphering data */
		if ( kstream->flags & AUKS_KRB5_STREAM_NAT_TRAVERSAL ) {
			klocal_addr.addrtype = AF_INET ;
			klocal_addr.length = 5 ;
			klocal_addr.contents = (krb5_octet *) "dummy" ;
			kremote_addr.addrtype = AF_INET ;
			kremote_addr.length = 5 ;
			kremote_addr.contents = (krb5_octet *) "dummy";
			auks_log("NAT traversal required, "
				 "setting dummy addresses");
			kstatus = krb5_auth_con_setaddrs(kstream->context,
							 kstream->auth_context,
							 &klocal_addr,
							 &kremote_addr);
			if (kstatus) {
				auks_error("authentication context dummy addrs"
					   " set up failed : %s",
					   error_message(kstatus));
			}
		}		
		
	}
	
	return fstatus;
}


int
auks_krb5_stream_clnt_auth(auks_krb5_stream_t * kstream,
			   char *remote_principal)
{
	int fstatus = AUKS_ERROR ;
	
	krb5_error_code kstatus;
	
	if (kstream->type != AUKS_KRB5_CLIENT_STREAM)
		goto exit;
		
	/* build remote principal */
	if (remote_principal != NULL)
		kstatus =
			krb5_parse_name(kstream->context,
					remote_principal,
					&kstream->remote_principal);
	else
		kstatus = 0;
	if (kstatus) {
		auks_error("server principal initialisation : %s",
		      error_message(kstatus));
		fstatus = AUKS_ERROR_KRB5_STREAM_CTX_SETPRINC ;
		goto exit;
	}
	kstream->remote_principal_flag = 1;

	/* kerberos authentication stage */
	kstatus = krb5_sendauth(kstream->context,
				&kstream->auth_context,
				(krb5_pointer) & kstream->stream,
				AUKS_KRB5_PROTOCOL_VERSION,
				kstream->local_principal,
				kstream->remote_principal,
				AP_OPTS_MUTUAL_REQUIRED |
				AP_OPTS_USE_SUBKEY, NULL, NULL,
				kstream->ccache, NULL, NULL,
				NULL);
	if (kstatus) {
		auks_error("authentication failed : %s",
		      error_message(kstatus));
		fstatus = AUKS_ERROR_KRB5_STREAM_CTX_SENDAUTH ;
	} else {
		kstream->authenticated = 1;
		fstatus = AUKS_SUCCESS ;
		auks_log("authentication succeed");
	}

exit:
	return fstatus;
}


int
auks_krb5_stream_srv_auth(auks_krb5_stream_t * kstream,
			  char *remote_principal)
{
	int fstatus = AUKS_ERROR ;

	krb5_error_code kstatus;
	krb5_authenticator *p_kauthenticator;

	if (kstream->type != AUKS_KRB5_SERVER_STREAM)
		goto exit;

	/* kerberos : authentication stage */
	kstatus = krb5_recvauth(kstream->context, &kstream->auth_context,
				(krb5_pointer) & kstream->stream,
				AUKS_KRB5_PROTOCOL_VERSION,
				kstream->local_principal, 0,
				kstream->keytab, NULL);
	if (kstatus) {
		auks_error("authentication failed : %s",
		      error_message(kstatus));
		fstatus = AUKS_ERROR_KRB5_STREAM_CTX_RECVAUTH ;
		goto exit;
	}
	auks_log("authentication succeed");

	/* kerberos : get connection authenticator */
	kstatus = krb5_auth_con_getauthenticator(kstream->context,
						 kstream->auth_context,
						 &p_kauthenticator);
	if (kstatus) {
		auks_error("connection authenticator extraction : %s",
		      error_message(kstatus));
		fstatus = AUKS_ERROR_KRB5_STREAM_CTX_AUTH_TOKEN ;
		goto exit;
	}
	auks_log("connection authenticator successfully extract");

	/* kerberos : get client identity */
	kstatus = krb5_copy_principal(kstream->context,
				      p_kauthenticator[0].client,
				      &kstream->remote_principal);
	if (kstatus) {
		auks_error("client principal storage : %s",
		      error_message(kstatus));
		fstatus = AUKS_ERROR_KRB5_STREAM_CP_PRINC ;
		goto auth_exit;
	}

	kstream->authenticated = 1;
	kstream->remote_principal_flag = 1;
	fstatus = AUKS_SUCCESS ;
	auks_log("client principal successfully stored");

auth_exit:
	krb5_free_authenticator(kstream->context,p_kauthenticator);

exit:
	return fstatus;
}

int
auks_krb5_stream_get_lprinc(auks_krb5_stream_t * kstream,
			    char *principal_name, size_t max_size)
{
	int fstatus;

	fstatus = auks_krb5_stream_get_principal_name(kstream, principal_name,
						      max_size, 
						      LOCAL_PRINCIPAL);

	return fstatus;
}

int
auks_krb5_stream_get_rprinc(auks_krb5_stream_t * kstream,
			    char *principal_name, size_t max_size)
{
	int fstatus;

	fstatus = auks_krb5_stream_get_principal_name(kstream, principal_name,
						      max_size,
						      REMOTE_PRINCIPAL);

	return fstatus;
}


int
auks_krb5_stream_send(auks_krb5_stream_t * kstream, char *data,
		      size_t data_size)
{

	int fstatus = AUKS_ERROR ;

	krb5_error_code kstatus;
	krb5_data kdata;
	krb5_data kcyphered_data;

	krb5_replay_data krdata;

	/* process only if already authenticated */
	if ( kstream->authenticated != 1 ) {
		fstatus = AUKS_ERROR_KRB5_STREAM_NOT_AUTHENTICATED ;
		goto exit;
	}

	memset(&kdata,'\0',sizeof(krb5_data));
	memset(&kcyphered_data,'\0',sizeof(krb5_data));
	memset(&krdata,'\0',sizeof(krb5_replay_data));

	kdata.data = data;
	kdata.length = data_size;

	kstatus = krb5_mk_priv(kstream->context, kstream->auth_context,
			       &kdata, &kcyphered_data, &krdata);
	if (kstatus) {
		auks_error("data encryption failed : %s",
		      error_message(kstatus));
		fstatus = AUKS_ERROR_KRB5_STREAM_CTX_MKPRIV ;
		goto exit;
	}
	auks_log("data encryption succeed");

	kstatus = krb5_write_message(kstream->context,
				     (krb5_pointer) & kstream->stream,
				     &kcyphered_data);
	if (kstatus) {
		auks_error("data transmission failed : %s",error_message(kstatus));
		fstatus = AUKS_ERROR_KRB5_STREAM_CTX_WRITE ;
	}
	else {
		auks_log("data transmission succeed : %d bytes sended",
			data_size);
		fstatus = AUKS_SUCCESS ;
	}

	krb5_free_data_contents(kstream->context,&kcyphered_data);

exit:
	return fstatus;
}

int
auks_krb5_stream_receive(auks_krb5_stream_t * kstream, char *data,
			 size_t data_size)
{

	int fstatus = AUKS_ERROR ;

	krb5_error_code kstatus;
	krb5_data kdata;
	krb5_data kcyphered_data;
	krb5_replay_data krdata;

	/* process only if already authenticated */
	if ( kstream->authenticated != 1 ) {
		fstatus = AUKS_ERROR_KRB5_STREAM_NOT_AUTHENTICATED ;
		goto exit;
	}

	memset(&kdata,'\0',sizeof(krb5_data));
	memset(&kcyphered_data,'\0',sizeof(krb5_data));
	memset(&krdata,'\0',sizeof(krb5_replay_data));

	kstatus = krb5_read_message(kstream->context,
				    (krb5_pointer) &kstream->stream,
				    &kcyphered_data);
	if (kstatus) {
		auks_error("data reception failed : %s",
		      error_message(kstatus));
		fstatus = AUKS_ERROR_KRB5_STREAM_CTX_READ ;
		goto exit;
	}
	auks_log("data reception succeed");

	kstatus = krb5_rd_priv(kstream->context,kstream->auth_context,
			       &kcyphered_data,&kdata,&krdata);
	if (kstatus) {
		auks_error("data decryption failed : %s",
		      error_message(kstatus));
		fstatus = AUKS_ERROR_KRB5_STREAM_CTX_RDPRIV ;
		goto read_exit;
	}
	auks_log("data decryption succeed");
	
	if (data_size < kdata.length) {
		auks_error("received data is too long");
		fstatus = AUKS_ERROR_KRB5_STREAM_DATA_TOO_LARGE ;
	} else {
		memcpy(data, kdata.data,kdata.length);
		auks_log("data transmission succeed : %d bytes received",
			kdata.length);
		fstatus = AUKS_SUCCESS ;
	}

	krb5_free_data_contents(kstream->context,&kdata);
	
read_exit:
	krb5_free_data_contents(kstream->context,&kcyphered_data);
	
exit:
	return fstatus;
}

int
auks_krb5_stream_send_msg(auks_krb5_stream_t * kstream, char *data,
			  size_t data_size)
{
	int fstatus = AUKS_ERROR ;
	
	krb5_error_code kstatus;
	krb5_data kdata;
	krb5_data kcyphered_data;
	krb5_replay_data krdata;

	/* process only if already authenticated */
	if ( kstream->authenticated != 1 ) {
		fstatus = AUKS_ERROR_KRB5_STREAM_NOT_AUTHENTICATED ;
		goto exit;
	}

	memset(&kdata,'\0',sizeof(krb5_data));
	memset(&kcyphered_data,'\0',sizeof(krb5_data));
	memset(&krdata,'\0',sizeof(krb5_replay_data));

	kdata.data = data;
	kdata.length = data_size;
	
	kstatus = krb5_mk_priv(kstream->context,kstream->auth_context,
			       &kdata,&kcyphered_data,&krdata);
	if (kstatus) {
		auks_error("message encryption failed : %s",
		      error_message(kstatus));
		fstatus = AUKS_ERROR_KRB5_STREAM_CTX_MKPRIV ;
		goto exit;
	}
	auks_log("message encryption succeed");
	
	kstatus = krb5_write_message(kstream->context,
				     (krb5_pointer) & kstream->stream,
				     &kcyphered_data);
	if (kstatus) {
		auks_log("message transmission failed : %s",
			error_message(kstatus));
		fstatus = AUKS_ERROR_KRB5_STREAM_CTX_WRITE ;
	} else {
		auks_log("message transmission succeed : %d bytes sended",
			data_size);
		fstatus = AUKS_SUCCESS ;
	}

	krb5_free_data_contents(kstream->context,&kcyphered_data);

exit:
	return fstatus;
}

int
auks_krb5_stream_receive_msg(auks_krb5_stream_t * kstream, char **data,
			     size_t * data_size)
{

	int fstatus = AUKS_ERROR ;

	krb5_error_code kstatus;
	krb5_data kdata;
	krb5_data kcyphered_data;
	krb5_replay_data krdata;

	/* process only if already authenticated */
	if ( kstream->authenticated != 1 ) {
		fstatus = AUKS_ERROR_KRB5_STREAM_NOT_AUTHENTICATED ;
		goto exit;
	}

	memset(&kdata,'\0',sizeof(krb5_data));
	memset(&kcyphered_data,'\0',sizeof(krb5_data));
	memset(&krdata,'\0',sizeof(krb5_replay_data));

	kstatus = krb5_read_message(kstream->context,
				    (krb5_pointer) & kstream->stream,
				    &kcyphered_data);
	if (kstatus) {
		auks_error("message reception failed : %s",error_message(kstatus));
		fstatus = AUKS_ERROR_KRB5_STREAM_CTX_READ ;
		goto exit;
	}
	auks_log("message reception succeed");
		
	kstatus = krb5_rd_priv(kstream->context,
			       kstream->auth_context,
			       &kcyphered_data, &kdata, &krdata);
	if (kstatus) {
		auks_error("message decryption failed : %s",
		      error_message(kstatus));
		fstatus = AUKS_ERROR_KRB5_STREAM_CTX_RDPRIV ;
		goto read_exit;
	}
	auks_log("message decryption succeed");

	*data_size = kdata.length;
	*data = (char *) malloc(*data_size * sizeof(char));
	if (*data == NULL) {
		auks_error("unable to allocate %d bytes to store received message",
		      kdata.length);
		fstatus = AUKS_ERROR_KRB5_STREAM_MALLOC ;
	} else {
		memcpy(*data, kdata.data,kdata.length);
		auks_log("message reception succeed : %d bytes stored",
			kdata.length);
		fstatus = AUKS_SUCCESS ;
	}
	
	krb5_free_data_contents(kstream->context,&kdata);

read_exit:
	krb5_free_data_contents(kstream->context,&kcyphered_data);

exit:
	return fstatus;
}



/* private functions implementations */
int
auks_krb5_stream_init_base(auks_krb5_stream_t * kstream, int stream,int flags)
{
	int fstatus = AUKS_ERROR ;
	int status;

	char *remote_host;

	/* stream related variables */
	struct sockaddr_in local_addr, remote_addr;
	socklen_t addrlen;

	krb5_error_code kstatus;
	krb5_address klocal_addr;
	krb5_address kremote_addr;
	krb5_flags kflags;

	/* nullify params flag */
	kstream->context_flag = 0;
	kstream->auth_context_flag = 0;
	kstream->local_principal_flag = 0;
	kstream->remote_principal_flag = 0;
	kstream->ccache_flag = 0;
	kstream->keytab_flag = 0;

	kstream->stream = stream;
	kstream->authenticated = 0;

	kstream->remote_host[0] = '\0';
	kstream->remote_host[HOST_NAME_MAX] = '\0';

	kstream->flags = flags;

	char str_error[STR_ERROR_SIZE];

	/* fill sockaddr_in structures with stream endpoints informations */
	addrlen = sizeof(local_addr);
	status = getsockname(stream, (struct sockaddr *) &local_addr,
			     &addrlen);
	if (status < 0 || addrlen != sizeof(local_addr)) {
		DUMP_ERROR(errno, str_error, STR_ERROR_SIZE);
		auks_error("local endpoint stream %u informations request "
		      "failed : %s",stream,str_error);
		fstatus = AUKS_ERROR_KRB5_STREAM_GETSOCKNAME ;
		goto exit;
	}
	auks_log("local endpoint stream %u informations request succeed",
		 stream);

	addrlen = sizeof(remote_addr);
	status = getpeername(stream, (struct sockaddr *) &remote_addr,
			     &addrlen);
	if (status < 0 || addrlen != sizeof(remote_addr)) {
		DUMP_ERROR(errno, str_error, STR_ERROR_SIZE);
		auks_error("remote endpoint stream %u informations"
		      " request failed : %s",stream, str_error);
		fstatus = AUKS_ERROR_KRB5_STREAM_GETPEERNAME ;
		goto exit;
	}
	auks_log("remote endpoint stream %u informations request succeed",
		 stream);

	remote_host = inet_ntoa((remote_addr.sin_addr));
	if (remote_host)
		strncpy(kstream->remote_host, remote_host,
			HOST_NAME_MAX);
	auks_log("remote host is %s",remote_host);

	memset(&kstream->context,'\0',sizeof(krb5_context));
	memset(&kstream->auth_context,'\0',sizeof(krb5_auth_context));

	/* kerberos : context initialization */
	kstatus = krb5_init_context(&kstream->context);
	if (kstatus) {
		auks_error("context initialisation failed : %s",
		      error_message(kstatus));
		fstatus = AUKS_ERROR_KRB5_STREAM_INIT_CTX ;
		goto exit;
	}
	kstream->context_flag = 1;
	auks_log("context initialization succeed");

	/* kerberos : connection authentication context */
	kstatus = krb5_auth_con_init(kstream->context,&kstream->auth_context);
	if (kstatus) {
		auks_error("connection authentication context initialisation "
		      "failed : %s",error_message(kstatus));
		fstatus = AUKS_ERROR_KRB5_STREAM_INIT_AUTH_CTX ;
		goto ctx_exit;
	}
	kstream->auth_context_flag = 1;
	auks_log("connection authentication context initialisation succeed");

	/* kerberos : set auth context endpoints */
	klocal_addr.addrtype = local_addr.sin_family;
	klocal_addr.length = sizeof(local_addr.sin_addr);
	klocal_addr.contents = (krb5_octet *) & local_addr.sin_addr;
	kremote_addr.addrtype = remote_addr.sin_family;
	kremote_addr.length = sizeof(remote_addr.sin_addr);
	kremote_addr.contents = (krb5_octet *) & remote_addr.sin_addr;
	kstatus = krb5_auth_con_setaddrs(kstream->context,kstream->auth_context,
					 &klocal_addr, &kremote_addr);
	if (kstatus) {
		auks_error("authentication context addrs"
		      " set up failed : %s",error_message(kstatus));
		fstatus = AUKS_ERROR_KRB5_STREAM_CTX_SETADDR ;
		goto auth_ctx_exit;
	}
	auks_log("authentication context addrs set up succeed");

	/*
	 * Kerberos : connection replay options configuration
	 * if we use KRB5_AUTH_CONTEXT_DO_TIME or
	 * KRB5_AUTH_CONTEXT_DO_SEQUENCE, we have to use a replay cache
	 * if we set flags to 0 we don't have to
	 */
	kflags = 0 ;
	kflags |= KRB5_AUTH_CONTEXT_DO_SEQUENCE ;
	kstatus = krb5_auth_con_setflags(kstream->context,kstream->auth_context,
					 kflags);
	if (kstatus) {
		auks_error("connection authentication context flags"
		      " set up failed : %s",error_message(kstatus));
		fstatus = AUKS_ERROR_KRB5_STREAM_CTX_SETFLAGS ;
	} else {
		auks_log("default kstream initialisation succeed");
		fstatus = AUKS_SUCCESS ;
	}

auth_ctx_exit:
	/* kerberos : if problem, free auth con context */
	if ( fstatus != AUKS_SUCCESS ) {
		krb5_auth_con_free(kstream->context,kstream->auth_context);
	}

ctx_exit:
	/* kerberos : if problem, clean context */
	if ( fstatus != AUKS_SUCCESS ) {
		krb5_free_context(kstream->context);
	}

exit:
	return fstatus;
}


int
auks_krb5_stream_get_principal_name(auks_krb5_stream_t * kstream,
				    char *principal_name, size_t max_size,
				    int which_principal)
{
	int fstatus = AUKS_ERROR ;

	char *tmp_string = NULL;
	size_t tmp_size = max_size;
	
	krb5_principal *p_principal;
	krb5_error_code kstatus;
	
	switch (which_principal) {
		
	case LOCAL_PRINCIPAL:
		if (kstream->local_principal_flag)
			p_principal = &kstream->local_principal;
		else
			return fstatus;
		break;

	case REMOTE_PRINCIPAL:
		if (kstream->remote_principal_flag)
			p_principal = &kstream->remote_principal;
		else
			return fstatus;
		break;

	default:
		return fstatus;
	}

	/* kerberos : get principal identity */
	kstatus = krb5_unparse_name_ext(kstream->context, *p_principal,
					&tmp_string,
					(unsigned int *) &tmp_size);
	if (kstatus) {
		auks_error("principal name extraction failed : %s",
		      error_message(kstatus));
		fstatus = AUKS_ERROR_KRB5_STREAM_CTX_GETPRINC ;
		goto exit;
	}
		
	if (tmp_size <= max_size) {
		if (strncpy(principal_name, tmp_string, max_size)
		    == principal_name) {
			auks_log("principal name extraction succeed");
			fstatus = AUKS_SUCCESS ;
		}
	}
	else {
		auks_log("principal name is too long");	
		fstatus = AUKS_ERROR_KRB5_STREAM_PRINC_TOO_LONG ;
	}

	free(tmp_string);

exit:
	return fstatus;
}
