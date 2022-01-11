/***************************************************************************\
 * auks_krb5_cred.c - AUKS MIT Kerberos cred API wrapper implementation
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

#include <stdarg.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <string.h>

#define KRB5_PRIVATE 1
#include <krb5.h>
#ifndef OPTS_FORWARD_CREDS
#define OPTS_FORWARD_CREDS           0x00000020
#endif
#ifndef OPTS_FORWARDABLE_CREDS
#define OPTS_FORWARDABLE_CREDS       0x00000010
#endif

#define AUKS_LOG_HEADER "auks_krb5_cred: "
#define AUKS_LOG_BASE_LEVEL 4
#define AUKS_LOG_DEBUG_LEVEL 4

#include "auks/auks_error.h"
#include "auks/auks_krb5_cred.h"
#include "auks/auks_log.h"

/* Some data comparison and conversion functions.  */
static inline int
_krb_data_eq(krb5_data d1, krb5_data d2)
{
	return (d1.length == d2.length && (d1.length == 0 ||
					   !memcmp(d1.data, d2.data, d1.length)));
}

static inline int
_krb_data_eq_string (krb5_data d, const char *s)
{
	return (d.length == strlen(s) && (d.length == 0 ||
					  !memcmp(d.data, s, d.length)));
}

/* Return true if princ is the local krbtgt principal for local_realm. */
static krb5_boolean
_krb_is_local_tgt(krb5_principal princ, krb5_data *realm)
{
	return princ->length == 2 && _krb_data_eq(princ->realm, *realm) &&
		_krb_data_eq_string(princ->data[0], KRB5_TGS_NAME) &&
		_krb_data_eq(princ->data[1], *realm);
}

int
auks_krb5_cc_new_unique(char ** fullname_out)
{
	int fstatus;

	krb5_context context;
	krb5_ccache ccache;

	char *ccache_type = NULL, *ccache_name = NULL;

	/* Initialize KRB5 context */
	fstatus = krb5_init_context(&context);
	if (fstatus) {
		auks_error("unable to initialize kerberos context : %s",
			   error_message(fstatus));
		fstatus = AUKS_ERROR_KRB5_CRED_INIT_CTX ;
		return fstatus;
	}

	/* Get the default ccache */
	fstatus = krb5_cc_default(context, &ccache);
	if (fstatus) {
	        auks_error("error while getting default ccache : %s",
			   error_message(fstatus));
		fstatus = AUKS_ERROR_KRB5_CRED_OPEN_CC ;
		goto out;
	}

	/* Get the default ccache type */
	ccache_type = krb5_cc_get_type(context, ccache);

	/* Generate a new unique ccache */
	fstatus = krb5_cc_new_unique(context, ccache_type, NULL, &ccache);
	if (fstatus) {
		auks_error("error while creating new unique ccache of "
			   "type %s : %s", ccache_type, error_message(fstatus));
		fstatus = AUKS_ERROR_KRB5_CRED_OPEN_CC ;
		goto out;
	}

	/* Get ccache full name */
	fstatus = krb5_cc_get_full_name(context, ccache, &ccache_name);
	if (fstatus) {
		auks_error("error while getting ccache full name : %s",
			   error_message(fstatus));
		fstatus = AUKS_ERROR_KRB5_CRED_OPEN_CC ;
		krb5_cc_destroy(context, ccache);
		goto out;
	}

	/* Set output var */
	*fullname_out = strdup(ccache_name);

	/* Close ccache handles */
	krb5_cc_close(context, ccache);

 out:
	krb5_free_string(context, ccache_name);

	/* Free KRB5 context */
	krb5_free_context(context);
	return (fstatus);
}

int
auks_krb5_cc_switch(char *ccache_name)
{
	int fstatus;

	krb5_context context;
	krb5_ccache ccache = NULL;
	char *ccache_type = NULL;

	/* initialize krb5 context */
	fstatus = krb5_init_context(&context);
	if (fstatus) {
		auks_error("unable to initialize kerberos context : %s",
			   error_message(fstatus));
		fstatus = AUKS_ERROR_KRB5_CRED_INIT_CTX;
		return (fstatus);
	}

	/* resolve provided cred ccache */
	fstatus = krb5_cc_resolve(context, ccache_name, &ccache);
	if (fstatus) {
		auks_error("error while resolving credcache %s : %s",
			   ccache_name, error_message(fstatus));
		fstatus = AUKS_ERROR_KRB5_CRED_OPEN_CC ;
		goto out;
	}

	/* get the associated ccache type */
	ccache_type = krb5_cc_get_type(context, ccache);

	/* call krb5_cc_switch for ccache if supported, skip otherwise */
	if (krb5_cc_support_switch(context, ccache_type)) {
		fstatus = krb5_cc_switch(context, ccache);
		if (fstatus) {
			auks_error("error while calling krb5_cc_switch for "
				   "ccache %s : %s", ccache_name,
				   error_message(fstatus));
			fstatus = AUKS_ERROR_KRB5_CRED_OPEN_CC ;
		} else
			auks_log("krb5_cc_switch to ccache %s", ccache_name);
	} else {
		auks_log("krb5_cc_switch to ccache %s skipped : not supported "
			 "for type ccache type %s", ccache_name, ccache_type);
		fstatus = 0;
	}

	krb5_cc_close(context, ccache);

out:
	krb5_free_context(context);
	return (fstatus);
}

int
auks_krb5_cc_destroy(char * fullname)
{
        int fstatus;

	krb5_context context;
	krb5_ccache ccache = NULL;


	/* Initialize KRB5 context */
	fstatus = krb5_init_context(&context);
	if (fstatus) {
		auks_error("unable to initialize kerberos context : %s",
			   error_message(fstatus));
		fstatus = AUKS_ERROR_KRB5_CRED_INIT_CTX;
		return (fstatus);
	}

	/* Find and destroy ccache */
	fstatus = krb5_cc_resolve(context, fullname, &ccache);
	if (fstatus) {
		auks_error("error while resolving credcache %s : %s",
			   fullname, error_message(fstatus));
		fstatus = AUKS_ERROR_KRB5_CRED_OPEN_CC ;
		goto cc_exit;
	}

	fstatus = krb5_cc_destroy(context, ccache);
	if (fstatus && fstatus != KRB5_FCC_NOFILE) {
		auks_error("error while destroying cache %s : %s",
			   fullname, error_message(fstatus));
		fstatus = AUKS_ERROR_KRB5_CRED_READ_CC;
		goto out;
	}

        auks_log("destroyed ccache %s", fullname);

 out:
	/* Free KRB5 context */
	krb5_free_context(context);

	return (fstatus);

 cc_exit:
	/* Close ccache handles */
	krb5_cc_close(context, ccache);

	goto out;
}

int
auks_krb5_cred_get(char *ccachefilename,char **pbuffer,
		   size_t * plength)
{
	int fstatus = AUKS_ERROR ;

	/* kerberos related variables */
	krb5_error_code err_code;
	krb5_context context;
	krb5_auth_context auth_context;
	krb5_ccache ccache;
	krb5_creds read_cred;
	krb5_cc_cursor cc_cursor;
	krb5_data *p_outbuf;
	krb5_replay_data krdata;
	krb5_principal princ;

	int read_cred_was_used = 0;
	int read_cred_is_tgt = 0;

	char *buffer;
	size_t length;

	/* initialize kerberos context */
	err_code = krb5_init_context(&context);
	if (err_code) {
		auks_error("unable to initialize kerberos context : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_INIT_CTX ;
		goto exit;
	}
	auks_log("kerberos context successfully initialized");

	/* initialize kerberos credential cache structure */
	if (ccachefilename == NULL)
		err_code = krb5_cc_default(context, &ccache);
	else
		err_code = krb5_cc_resolve(context, ccachefilename,&ccache);
	if (err_code) {
		auks_error("unable to resolve credential cache : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_OPEN_CC ;
		goto ctx_exit ;
	}
	auks_log("credential cache successfully resolved");

	/* start credential cache sequential reading */
	err_code = krb5_cc_start_seq_get(context, ccache,&cc_cursor);
	if (err_code) {
		auks_error("unable to start credential cache sequential "
			   "read : %s",error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_READ_CC ;
		goto cc_exit;
	}
	auks_log("credential cache sequential read successfully started");


	/* Get principal name */
	if (krb5_cc_get_principal(context, ccache, &princ) != 0) {
		auks_error("Unable to retrieve principal name");
		goto ctx_exit;
	}

	/* look for the first TGT of the cache */
	do {
		err_code = krb5_cc_next_cred(context,ccache,
					     &cc_cursor,&read_cred);
		if (!err_code) {
			/* mark read_cred variable as used */
			read_cred_was_used = 1;
			if (_krb_is_local_tgt(read_cred.server, &princ->realm)) {
				read_cred_is_tgt = 1 ;
				break;
			}
		}
	}
	while (!err_code);

	/* stop credential cache sequential reading */
	err_code = krb5_cc_end_seq_get(context,ccache,&cc_cursor);
	if (err_code) {
		auks_error("unable to stop credential cache sequential "
			   "read : %s",error_message(err_code));
	} else
		auks_log("credential cache sequential read "
			 "successfully stopped");

	/* extract credential if a TGT was found */
	if (!read_cred_is_tgt) {
		auks_error("no TGT found in credential cache");
		fstatus = AUKS_ERROR_KRB5_CRED_NO_TGT_FOUND ;
		goto seq_exit;
	}
	auks_log("TGT found in credential cache");

	/* initialize a nullified kerberos authentication context in order */
	/* to serialize credential into buffer */
	err_code = krb5_auth_con_init(context,&auth_context);
	if (err_code) {
		auks_error("unable to initialize kerberos authentication "
			   "context : %s",error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_INIT_AUTH_CTX ;
		goto seq_exit;
	}
	auks_log("kerberos authentication context successfully initialized");

	/* clear kerberos authentication context flags */
	krb5_auth_con_setflags(context,auth_context,0);

	/* extract credential data */
	err_code = krb5_mk_1cred(context,auth_context,&read_cred,
				 &p_outbuf,&krdata);
	if (err_code) {
		auks_error("unable to dump credential into working buffer : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_MK_CRED ;
		goto auth_ctx_exit;
	}
	auks_log("credential successfully dumped into buffer");

	/* allocate output buffer */
	length = p_outbuf->length;
	buffer = (char *) malloc(length * sizeof(char));
	if (buffer == NULL) {
		auks_error("unable to allocate memory for credential data "
			   "storage");
		fstatus = AUKS_ERROR_KRB5_CRED_MALLOC ;
		goto cred_exit;
	}

	/* copy credential data into output buffer */
	memcpy(buffer,p_outbuf->data,length);
	*pbuffer = buffer;
	*plength = length;
	auks_log("credential successfully stored in output buffer");
	fstatus = AUKS_SUCCESS ;

cred_exit:
	krb5_free_data(context,p_outbuf);

auth_ctx_exit:
	/* free kerberos authentication context */
	krb5_auth_con_free(context,auth_context);

seq_exit:
	/* free credential contents */
	if (read_cred_was_used)
		krb5_free_cred_contents(context,&read_cred);

cc_exit:
	krb5_cc_close(context, ccache);

ctx_exit:
	krb5_free_context(context);

exit:
	return fstatus;
}


int
auks_krb5_cred_store(char *cachefilename, char *buffer,
		     size_t buffer_length)
{
	int fstatus = AUKS_ERROR ;

	/* kerberos related variables */
	krb5_error_code err_code;
	krb5_context context;
	krb5_auth_context auth_context;
	krb5_ccache ccache;
	krb5_creds **creds;
	krb5_data data;
	krb5_replay_data krdata;

	/* initialize kerberos context */
	err_code = krb5_init_context(&context);
	if (err_code) {
		auks_error("unable to initialize kerberos context : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_INIT_CTX ;
		goto exit;
	}
	auks_log("kerberos context successfully initialized");

	/* initialize a nullified kerberos authentication context in order */
	/* to decode credential from buffer */
	err_code = krb5_auth_con_init(context, &auth_context);
	if (err_code) {
		auks_error("unable to initialize kerberos authentication"
			   " context : %s",error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_INIT_AUTH_CTX ;
		goto ctx_exit;
	}
	auks_log("kerberos authentication context successfully initialized");

	/* clear kerberos authentication context flags */
	krb5_auth_con_setflags(context, auth_context, 0);

	/* build a kerberos data structure with input buffer */
	data.data = buffer;
	data.length = buffer_length;

	/* build kerberos credential structure using this data structure */
	err_code = krb5_rd_cred(context, auth_context, &data,&creds,&krdata);
	if (err_code) {
		auks_error("unable to deserialize credential data : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_RD_CRED ;
		goto auth_ctx_exit;

	}
	auks_log("credential data successfully deserialized");

	/* resolve kerberos credential cache */
	if (cachefilename == NULL)
		err_code = krb5_cc_default(context,&ccache);
	else
		err_code = krb5_cc_resolve(context,cachefilename,&ccache);
	if (err_code) {
		auks_error("unable to resolve credential cache : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_OPEN_CC ;
		goto cred_exit;
	}
	auks_log("credential cache successfully resolved");

	/* initialize kerberos credential structure */
	err_code = krb5_cc_initialize(context,ccache,(*creds)->client);
	if (err_code) {
		auks_error("unable to initialize credential cache : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_INIT_CC ;
		goto cc_exit;

	}
	auks_log("credential cache successfully initialized",cachefilename);

	/* store credential in credential cache */
	err_code = krb5_cc_store_cred(context,ccache,*creds);
	if (err_code) {
		auks_error("unable to store credential in credential "
			   "cache : %s",error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_STORE_CRED ;
	} else {
		auks_log("credential successfully stored in credential "
			 "cache %s", cachefilename);
		fstatus = AUKS_SUCCESS ;
	}

cc_exit:
	krb5_cc_close(context, ccache);

cred_exit:
	krb5_free_creds(context, *creds);
	free(creds);

auth_ctx_exit:
	krb5_auth_con_free(context, auth_context);

ctx_exit:
	krb5_free_context(context);

exit:
	return fstatus;
}

int
auks_krb5_cred_get_fwd(char *ccachefilename, char *serverName,
		       char **p_buffer,
		       size_t * p_buffer_length)
{

	int fstatus = AUKS_ERROR ;

	/* kerberos related variables */
	krb5_error_code err_code;
	krb5_context context;
	krb5_ccache ccache;
	krb5_principal principal;
	krb5_creds **out_creds_array = NULL;
	krb5_auth_context auth_context;
	krb5_flags authopts;
	krb5_data outbuf;
	krb5_data *p_outbuf;
	krb5_replay_data krdata;

	authopts = AP_OPTS_MUTUAL_REQUIRED;
	authopts &= (~OPTS_FORWARD_CREDS);
	authopts &= (~OPTS_FORWARDABLE_CREDS);

	if ( serverName == NULL ) {
		auks_error("no host specified");
		fstatus = AUKS_ERROR_KRB5_CRED_NO_HOST_SPECIFIED ;
		goto exit;
	}

	/* initialize kerberos context */
	err_code = krb5_init_context(&context);
	if (err_code) {
		auks_error("unable to initialize kerberos context : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_INIT_CTX ;
		goto exit;
	}
	auks_log("kerberos context successfully initialized");

	/* initialize kerberos credential cache structure */
	if (ccachefilename == NULL)
		err_code = krb5_cc_default(context, &ccache);
	else
		err_code = krb5_cc_resolve(context,ccachefilename,&ccache);
	if (err_code) {
		auks_error("unable to resolve credential cache : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_OPEN_CC ;
		goto ctx_exit ;
	}
	auks_log("credential cache successfully resolved");

	/* get principal using credential cache */
	err_code = krb5_cc_get_principal(context,ccache,&principal);
	if (err_code) {
		auks_error("unable to get principal from credential cache : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_GET_PRINC ;
		goto cc_exit ;
	}
	auks_log("principal successfully extracted from credential cache");

	/* initialize kerberos authentication context */
	err_code = krb5_auth_con_init(context,&auth_context);
	if (err_code) {
		auks_error("unable to initialize kerberos authentication "
			   "context : %s",error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_INIT_AUTH_CTX ;
		goto princ_exit;
	}
	auks_log("kerberos authentication context successfully initialized");

	/* do replay detection using timestamps */
	krb5_auth_con_setflags(context,auth_context,KRB5_AUTH_CONTEXT_RET_TIME);

	/* get forwarded credential for server */
	err_code = krb5_fwd_tgt_creds(context,auth_context,serverName,
				      principal,NULL,NULL,authopts,&outbuf);
	if (err_code) {
		auks_error("unable to get serialized and crypted forwarded "
			   "credential for %s from KDC : %s",
			   serverName,error_message(err_code));
		fstatus =  AUKS_ERROR_KRB5_CRED_GET_FWD_CRED ;
		goto auth_ctx_exit;
	}
	auks_log("serialized and crypted forwarded credential for %s "
		 "successfully got from KDC",serverName);

	/* desactive replay detection */
	krb5_auth_con_setflags(context,auth_context,0);

	/* decrypt (using session key stored in auth context) and */
	/* unserialized forwarded credential in a kerberos credential */
	/* structure */
	err_code = krb5_rd_cred(context,auth_context,&outbuf,&out_creds_array,
				&krdata);
	if (err_code) {
		auks_error("unable to unserialize and decrypt forwarded "
			   "credential for %s : %s",serverName,
			   error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_RD_CRED ;
		goto fwd_exit;
	}
	auks_log("unserialization and decryption of forwarded "
		 "credential for %s succesfully done",serverName);

	/* Reinitialize kerberos authentication context in order to */
	/* write credential to output buffer */
	krb5_auth_con_free(context,auth_context);
	err_code = krb5_auth_con_init(context,&auth_context);
	if (err_code) {
		auks_error("unable to reinitialize kerberos connection "
			   "authentication context : %s",error_message
			   (err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_INIT_AUTH_CTX ;
		goto rd_cred_exit;
	}
	auks_log("kerberos connection authentication context "
		 "reinitialization successfully done");

	/* no flags */
	krb5_auth_con_setflags(context,auth_context,0);

	/* serialize forwarded credential (no encryption because auth */
	/* context session key is nullified) */
	err_code = krb5_mk_1cred(context,auth_context,*out_creds_array,
				 &p_outbuf,&krdata);
	if (err_code) {
		auks_error("unable to serialize forwarded credential for "
			   "%s : %s",serverName,error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_MK_CRED ;
		goto rd_cred_exit;
	}
	auks_log("forwarded credential for %s successfully serialized",
		 serverName);

	/* allocate output buffer and store serialized credential */
	(*p_buffer) = (char *) malloc(p_outbuf->length * sizeof(char));
	if ((*p_buffer) == NULL) {
		auks_error("unable to allocate serialized credential output "
			   "buffer for %s",serverName);
		*p_buffer_length = 0 ;
		fstatus = AUKS_ERROR_KRB5_CRED_MALLOC ;
	} else {
		/* copy data */
		memcpy(*p_buffer,p_outbuf->data,p_outbuf->length);
		*p_buffer_length = p_outbuf->length;
		auks_log("forwarded credential successfully stored "
			 "in output buffer");
		fstatus	= AUKS_SUCCESS ;
	}

	krb5_free_data(context,p_outbuf);

rd_cred_exit:
	krb5_free_creds(context,*out_creds_array);
	free(out_creds_array);

fwd_exit:
	krb5_free_data_contents(context, &outbuf);

auth_ctx_exit:
	krb5_auth_con_free(context,auth_context);

princ_exit:
	krb5_free_principal(context, principal);

cc_exit:
	krb5_cc_close(context, ccache);

ctx_exit:
	krb5_free_context(context);

exit:
	return fstatus;
}

int
auks_krb5_cred_renew(char *ccachefilename)
{
	int fstatus = AUKS_ERROR ;

	int read_cred_is_tgt = 0;
	int read_cred_is_renewable = 0;

	/* kerberos related variables */
	krb5_context context;
	krb5_error_code err_code;
	krb5_ccache ccache;
	krb5_creds *p_cred_out = NULL;
	krb5_creds read_cred;
	krb5_creds renew_cred;
	krb5_cc_cursor cc_cursor;
	krb5_principal princ;

	/* initialize kerberos context */
	err_code = krb5_init_context(&context);
	if (err_code) {
		auks_error("unable to initialize kerberos context : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_INIT_CTX ;
		goto exit;
	}
	auks_log("kerberos context successfully initialized");

	/* initialize kerberos credential cache structure */
	if (ccachefilename == NULL)
		err_code = krb5_cc_default(context,&ccache);
	else
		err_code = krb5_cc_resolve(context,ccachefilename,&ccache);
	if (err_code) {
		auks_error("unable to resolve credential cache : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_OPEN_CC ;
		goto ctx_exit ;
	}
	auks_log("credential cache successfully resolved");

	/* Get principal name */
	if (krb5_cc_get_principal(context, ccache, &princ) != 0) {
		auks_error("Unable to retrieve principal name");
		goto ctx_exit;
	}

	/* start credential cache sequential reading */
	err_code = krb5_cc_start_seq_get(context, ccache,&cc_cursor);
	if (err_code) {
		auks_error("unable to start credential cache sequential "
			   "read : %s",error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_READ_CC ;
		goto cc_exit;
	}
	auks_log("credential cache sequential read successfully started");

	/* try to get the first renewable TGT of the cache */
	do {
		err_code = krb5_cc_next_cred(context,ccache,
					     &cc_cursor,&read_cred);
		if (!err_code) {
			if (_krb_is_local_tgt(read_cred.server, &princ->realm)) {
				read_cred_is_tgt = 1;
				if (read_cred.ticket_flags
				    & TKT_FLG_RENEWABLE) {
					read_cred_is_renewable = 1;
					break;
				}
			}
		}
	}
	while (!err_code);

	/* stop credential cache sequential reading */
	err_code = krb5_cc_end_seq_get(context, ccache,&cc_cursor);
	if (err_code) {
		auks_error("unable to stop credential cache sequential "
			   "read : %s",error_message(err_code));
	} else
		auks_log("credential cache sequential read "
			 "successfully stopped");

	/* try to do renewal if a TGT was found */
	if (!read_cred_is_tgt) {
		auks_error("no TGT found in credential cache");
		fstatus = AUKS_ERROR_KRB5_CRED_NO_TGT_FOUND ;
		goto seq_exit;
	}

	/* try to do renewal if a renewable TGT was found */
	if (!read_cred_is_renewable) {
		auks_error("no renewable TGT found in credential cache");
		fstatus = AUKS_ERROR_KRB5_CRED_TGT_NOT_RENEWABLE ;
		goto seq_exit;
	}
	auks_log("renewable TGT found in credential cache");

	/* test if renewal is possible */
	if (read_cred.times.endtime >=
	    read_cred.times.renew_till) {
		auks_error("TGT can't be renew anymore");
		fstatus = AUKS_ERROR_KRB5_CRED_TGT_HAS_EXPIRED ;
		goto seq_exit;
	}
	auks_log("TGT is still renewable");

	/* renew credential cache TGT */
	memset(&renew_cred, 0,sizeof(renew_cred));

	/* copy client principal in futur credential */
	err_code = krb5_copy_principal(context,read_cred.client,
				       &renew_cred.client);
	if (err_code) {
		auks_error("unable to put client principal into "
			   "request cred : %s",error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_CP_PRINC ;
		goto cred_exit;
	}
	auks_log("client principal successfully put into request cred");

	/* copy krbtgt/... principal in futur credential as required */
	/* server principal for TGS */
	err_code = krb5_copy_principal(context,read_cred.server,
				       &renew_cred.server);
	if (err_code) {
		auks_error("unable to put server principal into "
			   "request cred : %s",error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_CP_PRINC ;
		goto cred_exit;
	}
	auks_log("server principal successfully put into request cred");

	/* renew credential cache TGT */
/* 	err_code = krb5_get_credentials_renew(context,KDC_OPT_RENEW,ccache, */
/* 					      &renew_cred,&p_cred_out); */
	err_code = krb5_get_cred_via_tkt(context,&read_cred,KDC_OPT_RENEW,
					 NULL,&renew_cred,&p_cred_out);

	if (err_code) {
		auks_error("unable to renew credential cache TGT : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_TGT_RENEW ;
	} else {
		auks_log("credential cache TGT successfully renewed");
		krb5_free_creds(context,p_cred_out);
		fstatus = AUKS_SUCCESS ;
	}

cred_exit:
	/* potential bug to check */
	krb5_free_cred_contents(context,&renew_cred);

seq_exit:
	krb5_free_cred_contents(context,&read_cred);

cc_exit:
	krb5_cc_close(context, ccache);

ctx_exit:
	krb5_free_context(context);

exit:
	return fstatus;
}


int
auks_krb5_cred_renew_buffer(char *in_buf,size_t in_buf_len,
			    char** pout_buf,size_t *pout_buf_len,
			    int flags)
{
	int fstatus = AUKS_ERROR ;

	/* kerberos related variables */
	krb5_error_code err_code;
	krb5_context context;
	krb5_auth_context auth_context;

	krb5_creds **creds;
	krb5_data data;
	krb5_replay_data krdata;

	krb5_data *p_outbuf;

	krb5_creds renew_cred;
	krb5_creds *p_cred_out = NULL;

	krb5_address **addresses;

	char* buffer;
	size_t length;

	/* initialize kerberos context */
	err_code = krb5_init_context(&context);
	if (err_code) {
		auks_error("unable to initialize kerberos context : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_INIT_CTX ;
		goto exit;
	}
	auks_log("kerberos context successfully initialized");

	/* initialize a nullified kerberos authentication context in order */
	/* to decode credential from buffer */
	err_code = krb5_auth_con_init(context, &auth_context);
	if (err_code) {
		auks_error("unable to initialize kerberos authentication"
			   " context : %s",error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_INIT_AUTH_CTX ;
		goto ctx_exit;
	}
	auks_log("kerberos authentication context successfully initialized");

	/* clear kerberos authentication context flags */
	krb5_auth_con_setflags(context, auth_context, 0);

	/* build a kerberos data structure with input buffer */
	data.data = in_buf;
	data.length = in_buf_len;

	/* build kerberos credential structure using this data structure */
	err_code = krb5_rd_cred(context, auth_context, &data,&creds,&krdata);
	if (err_code) {
		auks_error("unable to deserialize credential data : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_RD_CRED ;
		goto auth_ctx_exit;
	}
	auks_log("credential data successfully deserialized");

	/* renew credential cache TGT */
	memset(&renew_cred, 0,sizeof(renew_cred));

	/* copy client principal in futur credential */
	err_code = krb5_copy_principal(context,(*creds)->client,
				       &renew_cred.client);
	if (err_code) {
		auks_error("unable to put client principal into "
			   "request cred : %s",error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_CP_PRINC ;
		goto cred_exit;
	}
	auks_log("client principal successfully put into request cred");

	/* copy krbtgt/... principal in futur credential as required */
	/* server principal for TGS */
	err_code = krb5_copy_principal(context,(*creds)->server,
				       &renew_cred.server);
	if (err_code) {
		auks_error("unable to put server principal into "
			   "request cred : %s",error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_CP_PRINC ;
		goto cred_exit;
	}
	auks_log("server principal successfully put into request cred");

	/* by default renew for same addresses */
	/* otherwise renew getting a addressless ticket */
	if ( flags == 0 )
		addresses = (*creds)->addresses ;
	else
		addresses = NULL ;

	/* renew credential */
	err_code = krb5_get_cred_via_tkt(context,(*creds),
					 ( KDC_OPT_CANONICALIZE |
					   KDC_OPT_RENEW |
					   ( (*creds)->ticket_flags &
					     KDC_TKT_COMMON_MASK )  ),
					 addresses,
					 &renew_cred,&p_cred_out);
	if (err_code) {
		auks_error("unable to renew auks cred buffer : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_TGT_RENEW ;
		goto cred_exit;
	}
	auks_log("auks cred buffer successfully renewed");

	/* extract credential data */
	err_code = krb5_mk_1cred(context,auth_context,p_cred_out,
				 &p_outbuf,&krdata);
	if (err_code) {
		auks_error("unable to dump credential into working buffer : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_MK_CRED ;
		goto renew_exit;
	}
	auks_log("credential successfully dumped into buffer");

	/* allocate output buffer */
	length = p_outbuf->length;
	buffer = (char *) malloc(length * sizeof(char));
	if (buffer == NULL) {
		auks_error("unable to allocate memory for credential data "
			   "storage");
		fstatus = AUKS_ERROR_KRB5_CRED_MALLOC ;
		goto mk_exit;
	}

	/* copy credential data into output buffer */
	memcpy(buffer,p_outbuf->data,length);
	*pout_buf = buffer;
	*pout_buf_len = length;
	auks_log("credential successfully stored in output buffer");
	fstatus = AUKS_SUCCESS ;

	auks_log("in length : %u | out length : %u",
		 in_buf_len,
		 p_outbuf->length);
mk_exit:
	krb5_free_data(context,p_outbuf);

renew_exit:
	krb5_free_creds(context,p_cred_out);

cred_exit:
	krb5_free_cred_contents(context,&renew_cred);
	krb5_free_creds(context, *creds);
	free(creds);

auth_ctx_exit:
	krb5_auth_con_free(context, auth_context);

ctx_exit:
	krb5_free_context(context);

exit:
	return fstatus;
}



int
auks_krb5_cred_deladdr_buffer(char *in_buf,size_t in_buf_len,
			      char** pout_buf,size_t *pout_buf_len)
{
	int fstatus = AUKS_ERROR ;

	/* kerberos related variables */
	krb5_error_code err_code;
	krb5_context context;
	krb5_auth_context auth_context;

	krb5_creds **creds;
	krb5_data data;
	krb5_replay_data krdata;

	krb5_data *p_outbuf;

	krb5_creds fwd_cred;
	krb5_creds *p_cred_out = NULL;

	krb5_address **addresses;

	char* buffer;
	size_t length;

	/* initialize kerberos context */
	err_code = krb5_init_context(&context);
	if (err_code) {
		auks_error("unable to initialize kerberos context : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_INIT_CTX ; 
		goto exit;
	}
	auks_log("kerberos context successfully initialized");

	/* initialize a nullified kerberos authentication context in order */
	/* to decode credential from buffer */
	err_code = krb5_auth_con_init(context, &auth_context);
	if (err_code) {
		auks_error("unable to initialize kerberos authentication"
			   " context : %s",error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_INIT_AUTH_CTX ;
		goto ctx_exit;
	}
	auks_log("kerberos authentication context successfully initialized");

	/* clear kerberos authentication context flags */
	krb5_auth_con_setflags(context, auth_context, 0);

	/* build a kerberos data structure with input buffer */
	data.data = in_buf;
	data.length = in_buf_len;

	/* build kerberos credential structure using this data structure */
	err_code = krb5_rd_cred(context, auth_context, &data,&creds,&krdata);
	if (err_code) {
		auks_error("unable to deserialize credential data : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_RD_CRED ;
		goto auth_ctx_exit;
	}
	auks_log("credential data successfully deserialized");

	memset(&fwd_cred, 0,sizeof(fwd_cred));

	/* copy client principal in futur credential */
	err_code = krb5_copy_principal(context,(*creds)->client,
				       &fwd_cred.client);
	if (err_code) {
		auks_error("unable to put client principal into "
			   "request cred : %s",error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_CP_PRINC ;
		goto cred_exit;
	}
	auks_log("client principal successfully put into request cred");

	/* copy krbtgt/... principal in futur credential as required */
	/* server principal for TGS */
	err_code = krb5_copy_principal(context,(*creds)->server,
				       &fwd_cred.server);
	if (err_code) {
		auks_error("unable to put server principal into "
			   "request cred : %s",error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_CP_PRINC ;
		goto cred_exit;
	}
	auks_log("server principal successfully put into request cred");

	/* get addressless forwarded ticket */
	err_code = krb5_get_cred_via_tkt(context,(*creds),
					 ( KDC_OPT_CANONICALIZE |
					   KDC_OPT_FORWARDED |
					   ( (*creds)->ticket_flags &
					     KDC_TKT_COMMON_MASK )  ),
					 addresses=NULL,
					 &fwd_cred,&p_cred_out);
	if (err_code) {
		auks_error("unable to get addressless forwarded cred from auks"
			   " cred buffer : %s",error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_GET_FWD_CRED ;
		goto cred_exit;
	}
	auks_log("addressless forwarded cred successfully"
		 " got using auks cred buffer");

	/* extract credential data */
	err_code = krb5_mk_1cred(context,auth_context,p_cred_out,
				 &p_outbuf,&krdata);
	if (err_code) {
		auks_error("unable to dump credential into working buffer : %s",
			   error_message(err_code));
		fstatus = AUKS_ERROR_KRB5_CRED_MK_CRED ;
		goto fwd_exit;
	}
	auks_log("credential successfully dumped into buffer");

	/* allocate output buffer */
	length = p_outbuf->length;
	buffer = (char *) malloc(length * sizeof(char));
	if (buffer == NULL) {
		auks_error("unable to allocate memory for credential data "
			   "storage");
		fstatus = AUKS_ERROR_KRB5_CRED_MALLOC ;
		goto mk_exit;
	}

	/* copy credential data into output buffer */
	memcpy(buffer,p_outbuf->data,length);
	*pout_buf = buffer;
	*pout_buf_len = length;
	auks_log("credential successfully stored in output buffer");
	fstatus = AUKS_SUCCESS ;

	auks_log("in length : %u | out length : %u",
		 in_buf_len,
		 p_outbuf->length);
mk_exit:
	krb5_free_data(context,p_outbuf);

fwd_exit:
	krb5_free_creds(context,p_cred_out);

cred_exit:
	krb5_free_cred_contents(context,&fwd_cred);
	krb5_free_creds(context, *creds);
	free(creds);

auth_ctx_exit:
	krb5_auth_con_free(context, auth_context);

ctx_exit:
	krb5_free_context(context);

exit:
	return fstatus;
}
