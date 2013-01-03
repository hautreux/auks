/***************************************************************************\
 * auks_api.c - AUKS API implementation
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

#include "xternal/xstream.h"

#define AUKS_LOG_HEADER "auks_api: "
#define AUKS_LOG_BASE_LEVEL 2
#define AUKS_LOG_DEBUG_LEVEL 2
#include "auks/auks_log.h"
#include "auks/auks_error.h"
#include "auks/auks_buffer.h"
#include "auks/auks_message.h"
#include "auks/auks_cred.h"
#include "auks/auks_engine.h"
#include "auks/auks_krb5_stream.h"

#include "auks/auks_api.h"

char*
auks_api_version()
{
#ifdef PACKAGE_VERSION
	return PACKAGE_VERSION ;
#else
	return "unknown" ;
#endif
}

int
auks_api_init(auks_engine_t* engine,char * conf_file)
{
	int fstatus ;

	fstatus = auks_engine_init_from_config_file(engine,conf_file);

	return fstatus;
}

int
auks_api_set_ccache(auks_engine_t* engine,char * ccache)
{
	int fstatus ;

	if(engine->ccache!=NULL)
		free(engine->ccache);

	engine->ccache = strdup(ccache) ;

	if ( engine->ccache == NULL ) {
		fstatus = AUKS_ERROR ;
	}
	else
		fstatus = AUKS_SUCCESS ;

	return fstatus;
}

int
auks_api_set_logfile(auks_engine_t* engine,char* logfile)
{
	return auks_engine_set_logfile(engine,logfile);
}

int
auks_api_set_loglevel(auks_engine_t* engine,int loglevel)
{
	return auks_engine_set_loglevel(engine,loglevel);
}

int
auks_api_close(auks_engine_t* engine)
{
	int fstatus;

	fstatus = auks_engine_free_contents(engine);

	return fstatus;
}

int
auks_api_request(auks_engine_t* engine,auks_message_t* req,
		 auks_message_t* rep)
{
	int fstatus = AUKS_ERROR ;
	int rstatus = AUKS_ERROR ;

	int i;

	/* auksd server options */
	char* server;
	char* port;
	char* principal;
	int retry;
	int max_retries;
	time_t timeout;
	time_t delay;
  
	/* auksd stream */
	int stream;  
	int kflags = 0 ;
	auks_krb5_stream_t kstream;

	/* request data */
	char* snd_buffer;
	size_t snd_length;
	char* rcv_buffer;
	size_t rcv_length;

	/* request done msg */
	auks_message_t ack_msg;

	max_retries = engine->retries;
	timeout = engine->timeout;
	delay = engine->delay;
 
	/* check request validity */
	snd_length = auks_message_packed(req);
	if ( snd_length == 0 ) {
		fstatus = AUKS_ERROR_API_EMPTY_REQUEST ;
		return fstatus;
	}
	snd_buffer = auks_message_data(req);

	/* pre build close msg */
	fstatus = auks_message_init(&ack_msg,AUKS_CLOSE_REQUEST,NULL,0);
	if ( fstatus != AUKS_SUCCESS ) {
		auks_log3("unable to initialize close request message : %s",
			  auks_strerror(fstatus));
		fstatus = AUKS_ERROR_API_REQUEST_INIT;
		return fstatus;
	}

	/* loop while retries are authorized */
	retry=1;
	while(retry<=max_retries){

		auks_log3("starting retry %d of %d",retry,max_retries);

		/* loop on primary and secondary */
		for(i=1;i<=2;i++){

			/* set connection options */
			if(i%2 == 1){
				server = engine->primary_address ;
				port = engine->primary_port;
				principal = engine->primary_principal;
			}
			else{
				server = engine->secondary_address ;
				port = engine->secondary_port;
				principal = engine->secondary_principal;
			}

			/* try to connect primary server */
			fstatus = AUKS_ERROR ;
			stream = xstream_connect(server,port,timeout*1000);
			if(stream < 0){
				auks_log3("unable to connect to auks server "
					  "%s:%s",server,port);
				fstatus = AUKS_ERROR_API_CONNECTION_FAILED ;
				continue;
			}
			auks_log3("successfully connected to auks server %s:%s",
				  server,port);

			if ( engine->nat_traversal == 1 ) {
				kflags |= AUKS_KRB5_STREAM_NAT_TRAVERSAL ;
			}

			/* initialize auks krb5 stream */
			fstatus = auks_krb5_stream_clnt_init(&kstream,stream,
							     NULL,
							     engine->ccache,
							     kflags);
			if( fstatus != AUKS_SUCCESS ){
				auks_log3("error while initializing "
					  "auks_krb5_stream : %s",
					  auks_strerror(fstatus));
				goto stream_end;
			}
	    
			/* authentication stage */
			fstatus = auks_krb5_stream_authenticate(&kstream,
								principal);
			if( fstatus != AUKS_SUCCESS ){
				auks_log3("authentication failed : %s",
					  auks_strerror(fstatus));
				goto kstream_end;
			}
	      
			/* send request */
			rstatus = auks_krb5_stream_send_msg(&kstream,
							    snd_buffer,
							    snd_length);
			if ( rstatus != AUKS_SUCCESS ) {
				auks_log3("unable to send request : %s",
					  auks_strerror(rstatus));
				goto auth_end;
			}
		
			rstatus = auks_krb5_stream_receive_msg(&kstream,
							       &rcv_buffer,
							       &rcv_length);
			if( rstatus != AUKS_SUCCESS ) {
				auks_log3("unable to receive reply : %s",
					  auks_strerror(rstatus));
				goto auth_end;
			}

			/* send close request to the server before closing */
			/* socket in order to keep the TIME_WAIT end point of */
			/* the TCP connection locally and avoid contention on */
			/* the server side */
			if ( AUKS_SUCCESS !=
			     auks_krb5_stream_send_msg(
				     &kstream,
				     auks_message_data(&ack_msg),
				     auks_message_packed(&ack_msg)) ) {
				auks_log3("unable to send close request : %s",
					  auks_strerror(rstatus));
			}

			rstatus = auks_message_load(rep,rcv_buffer,
						    rcv_length);
			if( rstatus != AUKS_SUCCESS ) {
				auks_log3("unable to unmarshall reply : %s",
					  auks_strerror(rstatus));
			}
			
			free(rcv_buffer);

		auth_end:
			fstatus = AUKS_SUCCESS ;

		kstream_end:
			auks_krb5_stream_free_contents(&kstream);
			
		stream_end:
			xstream_close(stream);
			
			/* connection succeed, break regardless */
			/* of request result */
			if ( fstatus == AUKS_SUCCESS )
				break;
			
		} /* for */
		
		/* connection succeed, break regardless of request result */
		if ( fstatus == AUKS_SUCCESS )
			break;

		/* delay next retry if not currently doing the last */
		if(retry<max_retries)
			sleep(delay);

		/* incremente retry */
		retry++;

	} /* while */

	/* free close msg */
	auks_message_free_contents(&ack_msg);

	/* if connection succeed, return request status (rstatus) */
	if ( fstatus == AUKS_SUCCESS )
		return rstatus;
	else
		return fstatus;
}

int
auks_api_ping(auks_engine_t * engine)
{
	int fstatus;
  
	auks_message_t req;
	auks_message_t rep;

	/* initialize ping message */
	fstatus = auks_message_init(&req,AUKS_PING_REQUEST,NULL,0);
	if ( fstatus != AUKS_SUCCESS ) {
		auks_log2("unable to initialize ping request message : %s",
			  auks_strerror(fstatus));
		fstatus = AUKS_ERROR_API_REQUEST_INIT;
		goto exit;
	}

	/* do request */
	fstatus=auks_api_request(engine,&req,&rep);
	if ( fstatus != AUKS_SUCCESS ) {
		auks_log2("ping request processing failed : %s",
			  auks_strerror(fstatus));
		fstatus = AUKS_ERROR_API_REQUEST_PROCESSING ;
		goto req_exit;
	}

	/* check reply */
	switch(rep.type){
		
	case AUKS_PING_REPLY :
		fstatus = AUKS_SUCCESS ;
		break;
		
	default :
		auks_log2("ping request failed : bad reply type (%d)",
			  rep.type);
		fstatus = AUKS_ERROR_API_INVALID_REPLY ;
		break;
		
	}
	auks_message_free_contents(&rep);
	
req_exit:
	auks_message_free_contents(&req);
	
exit:
	return fstatus;
}

int
auks_api_dump_unpack(auks_message_t* msg,auks_cred_t** pcreds,int* pcreds_nb)
{
	int fstatus;

	int creds_nb,i;
	auks_cred_t* creds;

	/* extract creds number */
	fstatus = auks_message_unpack_int(msg,&creds_nb);
	if ( fstatus != AUKS_SUCCESS ) {
		auks_log2("dump unpack failed : unable to unpack creds nb");
		return fstatus;
	}

	/* allocate memory */
	creds = (auks_cred_t*) malloc(creds_nb*sizeof(auks_cred_t));
	if ( creds == NULL ) {
		auks_log2("dump unpack failed : mem allocation failed for "
			  "creds storage");
		return fstatus;
	}

	/* unpack creds */
	for ( i=0 ; i < creds_nb ; i++) {

		fstatus = auks_cred_unpack(&creds[i],msg);
		if ( fstatus != AUKS_SUCCESS ) {
			auks_log2("dump unpack failed : unable to unpack " 
				  "cred[%d] : %s",i,auks_strerror(fstatus));
			break;
		}
		
		auks_cred_log(&creds[i]);

	}
	
	if ( fstatus != AUKS_SUCCESS )
		free(creds);
	else {
		auks_log3("dump unpack : %d creds unpacked",creds_nb);
		*pcreds=creds;
		*pcreds_nb=creds_nb;
	}

	return fstatus;
}

int
auks_api_dump(auks_engine_t * engine,auks_cred_t** pcreds,int* pcreds_nb)
{
	int fstatus;
  
	auks_message_t req;
	auks_message_t rep;

	/* initialize dump message */
	fstatus = auks_message_init(&req,AUKS_DUMP_REQUEST,NULL,0);
	if ( fstatus != AUKS_SUCCESS ) {
		auks_log2("unable to initialize dump request message : %s",
			  auks_strerror(fstatus));
		fstatus = AUKS_ERROR_API_REQUEST_INIT;
		goto exit;
	}

	/* do request */
	fstatus=auks_api_request(engine,&req,&rep);
	if ( fstatus != AUKS_SUCCESS ) {
		auks_log2("dump request processing failed : %s",
			  auks_strerror(fstatus));
		fstatus = AUKS_ERROR_API_REQUEST_PROCESSING ;
		goto req_exit;
	}

	/* check reply */
	switch(rep.type){
		
	case AUKS_DUMP_REPLY :
		fstatus = AUKS_SUCCESS ;
		break;
		
	default :
		auks_log2("dump request failed : bad reply type (%d)",
			  rep.type);
		fstatus = AUKS_ERROR_API_INVALID_REPLY ;
		break;
		
	}

	if ( fstatus != AUKS_SUCCESS )
		goto rep_exit;

	/* unpack dump reply */
	fstatus = auks_api_dump_unpack(&rep,pcreds,pcreds_nb);

rep_exit:
	auks_message_free_contents(&rep);
	
req_exit:
	auks_message_free_contents(&req);
	
exit:
	return fstatus;
}

int
auks_api_add_cred(auks_engine_t * engine,char* cred_cache)
{
	int fstatus;

	auks_cred_t cred;
	
	/* extract auks cred from given cache */
	/* (or default one if ccache is NULL) */
	fstatus = auks_cred_extract(&cred,cred_cache);
	if ( fstatus != AUKS_SUCCESS ) {
		auks_log2("auks cred extraction failed : %s",
			  auks_strerror(fstatus));
		goto exit;
	}

	/* call add function for the auks cred */
	fstatus = auks_api_add_auks_cred(engine,&cred);

	if ( fstatus == AUKS_SUCCESS )
		auks_log3("auks cred added using %s",
			  (cred_cache==NULL)?"default file":cred_cache);


	/* free auks cred */
	auks_cred_free_contents(&cred);
	
exit:
	return fstatus;
}

int
auks_api_add_auks_cred(auks_engine_t * engine,auks_cred_t* cred)
{
	int fstatus = AUKS_ERROR ;

	auks_message_t req;
	auks_message_t rep;

	/* check that current cred is addressless */
	/* make it addressless if not */
	if ( cred->info.addressless != 1 ) {
		
		fstatus = auks_cred_deladdr(cred);
		if ( fstatus != AUKS_SUCCESS ) {
			auks_log2("auks cred can not transformed in an "
				  "addressless one : %s",
				  auks_strerror(fstatus));
			goto exit;
		}
		auks_log3("auks cred transformed in an addressless one");

	}

	/* initialize add message */
	fstatus = auks_message_init(&req,AUKS_ADD_REQUEST,
				    cred->data,cred->length);
	if ( fstatus != AUKS_SUCCESS ) {
		auks_log2("unable to initialize add request message : %s",
			  auks_strerror(fstatus));
		fstatus = AUKS_ERROR_API_REQUEST_INIT;
		goto exit;
	}

	/* do request */
	fstatus = auks_api_request(engine,&req,&rep);
	if ( fstatus != AUKS_SUCCESS ) {
		auks_log2("add request processing failed : %s",
			  auks_strerror(fstatus));
		goto req_exit;
	}

	/* check reply */
	switch(rep.type){
	case AUKS_ADD_REPLY :
		fstatus = AUKS_SUCCESS;
		break;
	default :
		auks_log2("add request failed : bad reply type (%d)",
			  rep.type);
		fstatus = AUKS_ERROR_API_INVALID_REPLY ;
		break;
	}
	auks_message_free_contents(&rep);

req_exit:	
	auks_message_free_contents(&req);

exit:
	return fstatus;
}

int
auks_api_get_cred(auks_engine_t * engine,uid_t uid,char* cred_cache)
{
	int fstatus;

	auks_cred_t cred;

	fstatus = auks_api_get_auks_cred(engine,uid,&cred);
	if( fstatus ) {
		auks_log2("unable to unpack auks cred from reply : %s",
			  auks_strerror(fstatus));
		fstatus = AUKS_ERROR_API_CORRUPTED_REPLY ;
		goto exit;
	}

	fstatus = auks_cred_store(&cred,cred_cache);
	if ( fstatus != AUKS_SUCCESS ) {
		auks_log2("unable to store cred in file '%s' : %s",
			  cred_cache,auks_strerror(fstatus));
		fstatus = AUKS_ERROR_API_REPLY_PROCESSING ;
	}
	else {
		auks_log3("auks cred successfully stored in file '%s'",
			  cred_cache);
		fstatus = AUKS_SUCCESS;
	}
	
	auks_cred_free_contents(&cred);

exit:
	return fstatus;
}

int
auks_api_get_auks_cred(auks_engine_t * engine,uid_t uid,auks_cred_t* cred)
{
	int fstatus;

	auks_message_t req;
	auks_message_t rep;

	/* initialize get message */
	fstatus = auks_message_init(&req,AUKS_GET_REQUEST,NULL,0);
	if ( fstatus != AUKS_SUCCESS ) {
		auks_log2("unable to initialize get request message : %s",
			  auks_strerror(fstatus));
		fstatus = AUKS_ERROR_API_REQUEST_INIT;
		goto exit;
	}

	/* pack uid into message */
	fstatus = auks_buffer_pack_uid(&req.buffer,uid);
	if ( fstatus != AUKS_SUCCESS ) {
		auks_log2("unable to pack uid in get request message");
		fstatus = AUKS_ERROR_API_REQUEST_PACK_UID;
		goto req_exit;
	}
	
	/* do request */
	fstatus = auks_api_request(engine,&req,&rep);
	if ( fstatus !=AUKS_SUCCESS ) {
		auks_log2("get request processing failed : %s",
			  auks_strerror(fstatus));
		fstatus = AUKS_ERROR_API_REQUEST_PROCESSING;
		goto req_exit;
	}
	
	/* check reply */
	switch(rep.type){
	case AUKS_GET_REPLY :
		
		fstatus = auks_cred_unpack(cred,&rep) ;
		if( fstatus ) {
			auks_log2("unable to unpack auks cred from reply : %s",
				  auks_strerror(fstatus));
			fstatus = AUKS_ERROR_API_CORRUPTED_REPLY ;
			break;
		}

		break;

	default :
		auks_log2("get request failed : bad reply type (%d)",
			  rep.type);
		fstatus = AUKS_ERROR_API_INVALID_REPLY ;
		break;
	}
	
	auks_message_free_contents(&rep);

req_exit:  
	auks_message_free_contents(&req);

exit:
	return fstatus;
}

int
auks_api_renew_cred(auks_engine_t * engine,char* cred_cache,int mode)
{
	int fstatus = AUKS_ERROR ;

	auks_cred_t cred;

	int loop = 1;

	while ( loop == 1 ) {

		/* prevent from looping if mode is "once" */
		if ( mode == AUKS_API_RENEW_ONCE )
			loop = 0;

		/* extract auks cred from given cache */
		/* (or default one if ccache is NULL) */
		fstatus = auks_cred_extract(&cred,cred_cache);
		if ( fstatus != AUKS_SUCCESS ) {
			auks_log2("auks cred extraction failed : %s",
				  auks_strerror(fstatus));
			break;
		}
		
		/* test if cred needs to be renew now */
		fstatus = auks_cred_renew_test(&cred,engine->renewer_minlifetime);
		if ( fstatus != AUKS_SUCCESS && 
		     fstatus != AUKS_ERROR_CRED_STILL_VALID ) {
			
			auks_log3("%s's cred renew time test failed : %s",
				  cred.info.principal,
				  auks_strerror(fstatus));
			loop=0;
			goto end_loop;
		}
		else if ( fstatus == AUKS_ERROR_CRED_STILL_VALID ) {
			auks_log3("%s's cred renew time test : %s",
				  cred.info.principal,
				  auks_strerror(fstatus));
			goto sleep;
		}


		/* call add function for the auks cred */
		fstatus = auks_api_renew_auks_cred(engine,&cred,mode);
		if ( fstatus == AUKS_SUCCESS )
			auks_log3("auks cred renewed using %s",
				  (cred_cache==NULL)?"default file":cred_cache);
		else {
			loop=0;
			goto end_loop;
		}
		
		/* store renewed cred */
		fstatus = auks_cred_store(&cred,cred_cache);
		if ( fstatus != AUKS_SUCCESS ) {
			auks_log2("unable to store cred in file '%s' : %s",
				  cred_cache,auks_strerror(fstatus));
			fstatus = AUKS_ERROR_API_REPLY_PROCESSING ;
			loop=0;
			goto end_loop;
		}
		else {
			auks_log3("auks cred successfully stored in file '%s'",
				  cred_cache);
			fstatus = AUKS_SUCCESS;
		}

	sleep:
		if ( loop == 1 )
			sleep(engine->renewer_delay);
		
	end_loop:
		
		/* free auks cred */
		auks_cred_free_contents(&cred);
		
	}
	
exit:
	return fstatus;
}

int
auks_api_renew_auks_cred(auks_engine_t * engine,auks_cred_t* cred2r,int mode)
{
	int fstatus;

	auks_cred_t cred;
	
	fstatus = auks_api_get_auks_cred(engine,cred2r->info.uid,&cred);
	if ( fstatus == AUKS_SUCCESS ) {
		
		auks_log3("%s's cred renewed using auksd with uid=%u",
			  cred2r->info.principal,cred2r->info.uid);
		
		/* copy gotten cred into in/out one */
		auks_cred_free_contents(cred2r);
		memcpy(cred2r,&cred,sizeof(auks_cred_t));
		auks_cred_free_contents(&cred);
		
	}
	else {
		
		auks_log3("unable to get %s's cred from auksd using "
			  "uid=%u : %s",cred2r->info.principal,
			  cred2r->info.uid,auks_strerror(fstatus));
		auks_log3("trying to renew %s's cred using Kerberos"
			  " KDC",cred2r->info.principal);
		
		fstatus = auks_cred_renew(cred2r,1);
		if ( fstatus == AUKS_SUCCESS )
			auks_log3("%s's cred renewed using KDC",
				  cred2r->info.principal,
				  cred2r->info.uid);
		
	}
	
	return fstatus;
}

int
auks_api_remove_cred(auks_engine_t * engine,uid_t uid)
{
	int fstatus;

	auks_message_t req;
	auks_message_t rep;

	/* initialize remove message */
	fstatus = auks_message_init(&req,AUKS_REMOVE_REQUEST,NULL,0);
	if ( fstatus != AUKS_SUCCESS ) {
		auks_log2("unable to initialize remove request message : %s",
			  auks_strerror(fstatus));
		fstatus = AUKS_ERROR_API_REQUEST_INIT;
		goto exit;
	}

	/* pack uid into message */
	fstatus = auks_buffer_pack_uid(&req.buffer,uid);
	if ( fstatus != AUKS_SUCCESS ) {
		auks_log2("unable to pack uid in remove request message");
		fstatus = AUKS_ERROR_API_REQUEST_PACK_UID;
		goto req_exit;
	}

	/* do request */
	fstatus = auks_api_request(engine,&req,&rep);
	if ( fstatus != AUKS_SUCCESS ) {
		auks_log2("remove request processing failed : %s",
			  auks_strerror(fstatus));
		fstatus = AUKS_ERROR_API_REQUEST_PROCESSING;
		goto req_exit;
	}
	
	/* check reply */
	switch(rep.type){
	case AUKS_REMOVE_REPLY :
		fstatus = AUKS_SUCCESS;
		break;
	default :
		auks_log2("remove request failed : bad reply type (%d)",
			  rep.type);
		fstatus = AUKS_ERROR_API_INVALID_REPLY ;
		break;
	}

	auks_message_free_contents(&rep);

req_exit:      
	auks_message_free_contents(&req);

exit:  
	return fstatus;
}
