/***************************************************************************\
 * auks_cred.c - AUKS kerberos credential wrapper  implementation
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

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

/* getpwnam_r */
#include <sys/types.h>
#include <pwd.h>

/* kerberos stuff */
#include "krb5.h"

#define AUKS_LOG_HEADER "auks_cred: "
#define AUKS_LOG_BASE_LEVEL 4

#include "auks/auks_error.h"
#include "auks/auks_cred.h"
#include "auks/auks_krb5_cred.h"
#include "auks/auks_message.h"
#include "auks/auks_log.h"


int auks_cred_init(auks_cred_t * credential, char *data, size_t length)
{
	int fstatus = AUKS_ERROR ;

	char *tmp_string = NULL;
	size_t tmp_size = 0;

	/* kerberos related variables */
	krb5_error_code err_code;
	krb5_context context;
	krb5_auth_context auth_context;
	krb5_data kdata;
	krb5_creds **creds;
	krb5_replay_data krdata;

	char username[AUKS_PRINCIPAL_MAX_LENGTH + 1];
	struct passwd user_pwent;
	struct passwd *p_pwent;
	size_t pwnam_buffer_length = sysconf(_SC_GETPW_R_SIZE_MAX);
	char pwnam_buffer[pwnam_buffer_length];

	credential->info.principal[0] = '\0';
	credential->info.uid = AUKS_CRED_INVALID_UID;

	credential->info.starttime = AUKS_CRED_INVALID_TIME;
	credential->info.endtime = AUKS_CRED_INVALID_TIME;
	credential->info.renew_till = AUKS_CRED_INVALID_TIME;

	credential->info.addressless = 1;

	credential->data[1] = '\0';
	credential->length = 0;
	credential->max_length = AUKS_CRED_DATA_MAX_LENGTH;
	credential->status = AUKS_SUCCESS;

	/* check input buffer length versus auks credential internal buffer */
	/* max length */
	if ((unsigned int) length > (unsigned int) credential->max_length) {
		auks_error("input buffer is bigger than auks credential internal "
			   "buffer (%u versus %u)",length, credential->max_length);
		fstatus = AUKS_ERROR_CRED_INIT_BUFFER_TOO_LARGE ;
		goto exit;
	}

	/* extract informations from buffer */
	if (data == NULL) {
		auks_error("input buffer is NULL");
		fstatus = AUKS_ERROR_CRED_INIT_BUFFER_IS_NULL ;
		goto exit;
	}
	fstatus = AUKS_ERROR ;

	/* initialize kerberos context */
	err_code = krb5_init_context(&context);
	if (err_code) {
		auks_error("unable to initialize kerberos context : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_CRED_INIT_KRB_CTX_INIT ;
		goto exit;
	}
	auks_log("kerberos context successfully initialized");

	/* initialize a nullified kerberos authentication context 
	   in order to decode credential from buffer */
	err_code =
		krb5_auth_con_init(context,&auth_context);
	if (err_code) {
		auks_error("unable to initialize connection "
			   "authentication context : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_CRED_INIT_KRB_AUTH_CTX_INIT ;
		goto ctx_exit;
	}
	
	/* clear kerberos authentication context flags */
	krb5_auth_con_setflags(context,auth_context,0);
	/* set a kerberos data structure with input buffer */
	kdata.data = data ;
	kdata.length = (unsigned int) length ;

	/* build kerberos credential structure using this data structure */
	err_code = krb5_rd_cred(context,auth_context,&kdata, &creds,&krdata);
	if (err_code) {
		auks_error("unable to deserialize input buffer credential : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_CRED_INIT_KRB_RD_BUFFER ;
		goto auth_ctx_exit;
	}

	auks_log("input buffer credential successfully unserialized");
	err_code = krb5_unparse_name_ext(context,(*creds)->client,&tmp_string,
					 (unsigned int *) &tmp_size);
	if (err_code) {
		auks_error("unable to unparse principal : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_CRED_INIT_KRB_RD_PRINC ;
		goto creds_exit;
	} else if (tmp_size > AUKS_PRINCIPAL_MAX_LENGTH) {
		auks_error("unable to unparse principal : %s",
			   "principal is too long (more than %d characters)",
			   AUKS_PRINCIPAL_MAX_LENGTH);
		free(tmp_string);
		fstatus = AUKS_ERROR_CRED_INIT_KRB_PRINC_TOO_LONG ;
		goto creds_exit;
	}
	auks_log("principal successfully unparse");
	memcpy(credential->info.principal,tmp_string,tmp_size);
	credential->info.principal[tmp_size] = '\0';
	/* associated username from principal */
	err_code = krb5_aname_to_localname(context,(*creds)->client,
					   AUKS_PRINCIPAL_MAX_LENGTH,username);
	if (err_code) {
		auks_error("unable to get username from principal %s : %s",
			   credential->info.principal,error_message(err_code));
		fstatus = AUKS_ERROR_CRED_INIT_KRB_PRINC_TO_UNAME ;
		goto string_exit;
	}

	/* associated uid from username */
	fstatus = getpwnam_r(username,&user_pwent,pwnam_buffer,
			     pwnam_buffer_length,&p_pwent) ;
	if (fstatus) {
		auks_log("unable to get %s pwnam entry : %s",username,
			 strerror(fstatus)) ;
		fstatus = AUKS_ERROR_CRED_INIT_GETPWNAM ;
		goto string_exit;
	}

	/* uid information */
	credential->info.uid = user_pwent.pw_uid;

	credential->info.starttime = (time_t) (*creds)->times.starttime ;
	credential->info.endtime = (time_t) (*creds)->times.endtime ;
	credential->info.renew_till = (time_t) (*creds)->times.renew_till ;

	/* addresslessness */
	if (((*creds)->addresses) != NULL)
		credential->info.addressless = 0;

	/* duplicate input buffer */
	credential->length = (unsigned int) length;
	memcpy(credential->data,data,(unsigned int) length);

	fstatus = AUKS_SUCCESS;

string_exit:
	free(tmp_string);

creds_exit:
	krb5_free_creds(context,*creds);
	free(creds);

auth_ctx_exit:
	krb5_auth_con_free(context,auth_context);

ctx_exit:
	krb5_free_context(context);

exit:
	/* if valid buffer, store it */
	if (fstatus != 0) {
		/* bad credential buffer in input, clean this auks credential */
		auks_cred_free_contents(credential);
	}
	
	return fstatus;
}

int auks_cred_free_contents(auks_cred_t * credential)
{
	int fstatus;

	memset(credential->info.principal,'\0',
	       AUKS_PRINCIPAL_MAX_LENGTH + 1);
	credential->info.principal[0] = '\0';

	credential->info.uid = AUKS_CRED_INVALID_UID;

	credential->info.starttime = AUKS_CRED_INVALID_TIME;
	credential->info.endtime = AUKS_CRED_INVALID_TIME;
	credential->info.renew_till = AUKS_CRED_INVALID_TIME;

	credential->info.addressless = 1;

	memset(credential->data,'\0',AUKS_CRED_DATA_MAX_LENGTH);
	credential->length = 0;

	credential->status = AUKS_SUCCESS;

	fstatus = AUKS_SUCCESS ;
	return fstatus;
}

int auks_cred_extract(auks_cred_t* credential,char* ccache)
{
	int fstatus;
	
	char* buffer=NULL;
	size_t length;
	
	fstatus = auks_krb5_cred_get(ccache,&buffer,&length);
	if ( fstatus == AUKS_SUCCESS ) {
		fstatus = auks_cred_init(credential,buffer,length);
		free(buffer);
	}
	
	return fstatus;
}

int
auks_cred_store(auks_cred_t * credential,char* ccache)
{
	int fstatus;

	fstatus = auks_krb5_cred_store(ccache,credential->data,
				       credential->length);

	return fstatus;
}

int
auks_cred_renew_test(auks_cred_t * credential,int minlifetime)
{
	int fstatus = AUKS_ERROR ;

	time_t ctime;
	int delay,life;

	life = (int) credential->info.endtime - 
		(int) credential->info.starttime ;

	/* check for renewability */
	if ( life == 0 ) {
		fstatus = AUKS_ERROR_CRED_NOT_RENEWABLE ;
		return fstatus;
	}

	/* check for renewability */
	if ( life <= minlifetime ) {
		fstatus = AUKS_ERROR_CRED_LIFETIME_TOO_SHORT ;
		return fstatus;
	}
		
	/* get current time */
	time(&ctime);
		
	/* get delay in seconds before expiration */
	delay = (int) (credential->info.endtime - ctime) ;

	/* current time is higher than cred end time */
	/* auksd should remove it soon */
	if ( delay  < 0 ) {
		fstatus = AUKS_ERROR_CRED_EXPIRED ;
		return fstatus;
	}

	/* should it be renewed now ? */
	/* we renew it based on the min cred age */
	/* for example, min cred age is 5 minutes */
	/* we don't care of cred that have a lifetime lower than that */
	/* we renew creds when the delay until end of time is lower */
	/* than this amount of time */
	if ( delay > minlifetime ) {
		fstatus = AUKS_ERROR_CRED_STILL_VALID ;
		return fstatus;
	}

	fstatus = AUKS_SUCCESS ;

	return fstatus ;
}

int
auks_cred_renew(auks_cred_t * credential,int flags)
{
	int fstatus;

	char* rbuf = NULL ;
	size_t rbuf_len = 0 ;

	fstatus = auks_krb5_cred_renew_buffer(credential->data,
					      credential->length,
					      &rbuf,&rbuf_len,
					      flags);
	if ( fstatus == AUKS_SUCCESS ) {
		/* check output buffer length versus auks credential */
		/* internal buffer max length */
		if ( (unsigned int) rbuf_len > 
		     (unsigned int) credential->max_length) {
			fstatus = AUKS_ERROR_CRED_INIT_BUFFER_TOO_LARGE ;
		}
		else {
			auks_cred_free_contents(credential);
			fstatus = auks_cred_init(credential,rbuf,rbuf_len);
		}
		free(rbuf);
	}

	return fstatus;
}

int
auks_cred_deladdr(auks_cred_t * credential)
{
	int fstatus;

	char* rbuf = NULL ;
	size_t rbuf_len = 0 ;

	fstatus = auks_krb5_cred_deladdr_buffer(credential->data,
						credential->length,
						&rbuf,&rbuf_len);
	if ( fstatus == AUKS_SUCCESS ) {
		/* check output buffer length versus auks credential */
		/* internal buffer max length */
		if ( (unsigned int) rbuf_len > 
		     (unsigned int) credential->max_length) {
			fstatus = AUKS_ERROR_CRED_INIT_BUFFER_TOO_LARGE ;
		}
		else {
			auks_cred_free_contents(credential);
			fstatus = auks_cred_init(credential,rbuf,rbuf_len);
		}
		free(rbuf);
	}

	return fstatus;
}

int
auks_cred_log(auks_cred_t * credential)
{
	int fstatus = AUKS_SUCCESS ;

	auks_log("##############");
	auks_log("# principal  : %s",credential->info.principal);
	auks_log("# uid        : %u",(unsigned int)
		 credential->info.uid);
	auks_log("# starttime  : %u",(unsigned int)
		 credential->info.starttime);
	auks_log("# endtime    : %u",(unsigned int)
		 credential->info.endtime);
	auks_log("# renew till : %u",(unsigned int)
		 credential->info.renew_till);
	auks_log("# addressless: %s",(credential->info.addressless == 0)?
		 "no":"yes");
	auks_log("# data size  : %u",(unsigned int)
		 credential->length);
	auks_log("# status     : %s",auks_strerror(credential->status));
	auks_log("##############");

	return fstatus;
}


int auks_cred_pack(auks_cred_t* cred,auks_message_t * msg)
{
	int fstatus;

	/* pack principal name */
	fstatus = auks_message_pack_int(msg,
					(int)AUKS_PRINCIPAL_MAX_LENGTH + 1);
	if ( fstatus != AUKS_SUCCESS )
		return fstatus;

	fstatus = auks_message_pack_data(msg,cred->info.principal,
					 AUKS_PRINCIPAL_MAX_LENGTH + 1);
	if ( fstatus != AUKS_SUCCESS )
		return fstatus;

	/* pack uid */
	fstatus = auks_message_pack_uid(msg,cred->info.uid);
	if ( fstatus != AUKS_SUCCESS )
		return fstatus;

	/* pack cred times */
	fstatus = auks_message_pack_int(msg,(int)cred->info.starttime);
	if ( fstatus != AUKS_SUCCESS )
		return fstatus;
	fstatus = auks_message_pack_int(msg,(int)cred->info.endtime);
	if ( fstatus != AUKS_SUCCESS )
		return fstatus;
	fstatus = auks_message_pack_int(msg,(int)cred->info.renew_till);
	if ( fstatus != AUKS_SUCCESS )
		return fstatus;
	
	/* pack cred flags */
	fstatus = auks_message_pack_int(msg,(int)cred->info.addressless);
	if ( fstatus != AUKS_SUCCESS )
		return fstatus;

	/* pack cred data */
	fstatus = auks_message_pack_int(msg,(int)cred->max_length);
	if ( fstatus != AUKS_SUCCESS )
		return fstatus;
	fstatus = auks_message_pack_int(msg,(int)cred->length);
	if ( fstatus != AUKS_SUCCESS )
		return fstatus;
	fstatus = auks_message_pack_data(msg,cred->data,cred->max_length);
	if ( fstatus != AUKS_SUCCESS )
		return fstatus;

	/* pack cred status */
	fstatus = auks_message_pack_int(msg,cred->status);

	return fstatus;
}

int auks_cred_unpack(auks_cred_t* cred,auks_message_t * msg)
{
	int fstatus;
	
	int i;

	/* fill auks cred struct with zero */
	memset(cred,'\0',sizeof(auks_cred_t));

	/* unpack principal name */
	fstatus = auks_message_unpack_int(msg,&i);
	if ( fstatus != AUKS_SUCCESS ||
	     i != AUKS_PRINCIPAL_MAX_LENGTH + 1 )
		return fstatus;
	fstatus = auks_message_unpack_data(msg,cred->info.principal,
					   AUKS_PRINCIPAL_MAX_LENGTH + 1);
	if ( fstatus != AUKS_SUCCESS )
		return fstatus;

	/* unpack uid */
	fstatus = auks_message_unpack_uid(msg,&(cred->info.uid));
	if ( fstatus != AUKS_SUCCESS )
		return fstatus;

	/* unpack cred times */
	fstatus = auks_message_unpack_int(msg,(int*)&(cred->info.starttime));
	if ( fstatus != AUKS_SUCCESS )
		return fstatus;
	fstatus = auks_message_unpack_int(msg,(int*)&(cred->info.endtime));
	if ( fstatus != AUKS_SUCCESS )
		return fstatus;
	fstatus = auks_message_unpack_int(msg,(int*)&(cred->info.renew_till));
	if ( fstatus != AUKS_SUCCESS )
		return fstatus;
	
	/* pack cred flags */
	fstatus = auks_message_unpack_int(msg,(int*)&(cred->info.addressless));
	if ( fstatus != AUKS_SUCCESS )
		return fstatus;

	/* pack cred data */
	fstatus = auks_message_unpack_int(msg,&i);
	if ( fstatus != AUKS_SUCCESS ||
		i != AUKS_CRED_DATA_MAX_LENGTH )
		return fstatus;
	cred->max_length=(size_t)i;
	fstatus = auks_message_unpack_int(msg,(int*)&(cred->length));
	if ( fstatus != AUKS_SUCCESS ||
	     cred->length > AUKS_CRED_DATA_MAX_LENGTH )
		return fstatus;
	fstatus = auks_message_unpack_data(msg,cred->data,cred->max_length);
	if ( fstatus != AUKS_SUCCESS )
		return fstatus;

	/* pack cred status */
	fstatus = auks_message_unpack_int(msg,&(cred->status));
	
	return fstatus;
}
