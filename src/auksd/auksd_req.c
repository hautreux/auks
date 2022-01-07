/***************************************************************************\
 * auksd_req.c - request processor functions of the AUKS daemon
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

#include <getopt.h>
#include <signal.h>

#include <limits.h>

#include <string.h>

#define AUKS_LOG_BASE_LEVEL 2
#define AUKS_LOG_DEBUG_LEVEL 2
#include "auks/auks_log.h"
#include "auks/auks_error.h"
#include "auks/auks_engine.h"

#include "auks/auks_cred.h"
#include "auks/auks_cred_repo.h"

#include "auks/auks_message.h"

#include "auks/auks_krb5_stream.h"

#include "auksd_req.h"

#define XFREE(a) if( a != NULL) { free(a); a=NULL;};

/* private functions declaration */
int
_auksd_process_msg(void* p_args,char* principal,int role,
		   auks_krb5_stream_t* kstream);
int
_auksd_ping_req(void* p_args,char* principal,int role,
		auks_message_t* req,auks_message_t* rep);
int
_auksd_add_req(void* p_args,char* principal,int role,
	       auks_message_t* req,auks_message_t* rep);
int
_auksd_get_req(void* p_args,char* principal,int role,
	       auks_message_t* req,auks_message_t* rep);
int
_auksd_remove_req(void* p_args,char* principal,int role,
		  auks_message_t* req,auks_message_t* rep);
int
_auksd_list_req(void* p_args,char* principal,int role,
		auks_message_t* req,auks_message_t* rep);

int
_auksd_dump_req(void* p_args,char* principal,int role,
		auks_message_t* req,auks_message_t* rep);

int
_auksd_check_rw_right(void* p_args,char* principal,int role,
		      auks_cred_t * cred);

/* public function implementation */
int auksd_process_req(void* p_args,int socket)
{
	int fstatus = AUKS_ERROR ;

	auksd_worker_args_t* wargs;
	auksd_engine_t* engine;

	char * server_principal;
	char* server_keytab;

	int kflags = 0 ;
	auks_krb5_stream_t kstream;
	char client_principal[AUKS_PRINCIPAL_MAX_LENGTH+1];

	enum AUKS_ACL_ROLE role = AUKS_ACL_ROLE_UNKNOWN ;
	char* role_string;

	wargs=(auksd_worker_args_t*)p_args;
	if(wargs==NULL){
		return -1;
	}
  
	engine=wargs->engine;

	/* get kerberos conf */
	switch ( engine->role ) {
	case PRIMARY :
		server_principal = engine->primary_principal ;
		server_keytab = engine->primary_keytab ;
		break;
	case SECONDARY :
		server_principal = engine->secondary_principal ;
		server_keytab = engine->secondary_keytab ;		
		break;
	default:
		fstatus = AUKS_ERROR_DAEMON_NOT_VALID_SERVER ;
		return fstatus ;
		break;
	}
	
	/* set kerberos stream flags according to engine conf */
	if ( engine->nat_traversal == 1 ) {
		kflags |= AUKS_KRB5_STREAM_NAT_TRAVERSAL ;
	}

	/* initialize kerberos stream using incoming socket */
	fstatus = auks_krb5_stream_srv_init(&kstream,socket,server_principal,
					    server_keytab,kflags);
	if ( fstatus != AUKS_SUCCESS ) {
		auks_log("worker[%d] : unable to "
			 "initialize krb5 stream : %s",wargs->id,
			 auks_strerror(fstatus));
		goto exit;
	}
	auks_log2("worker[%d] : krb5 stream successfully "
		  "initialized for socket %d",wargs->id,socket);
	
	/* authenticate incoming connection */
	fstatus = auks_krb5_stream_authenticate(&kstream,NULL) ;
	if ( fstatus != AUKS_SUCCESS ) {
		auks_log("worker[%d] : authentication failed on socket %d (%s)"
			 " : %s",wargs->id,socket,kstream.remote_host,
			 auks_strerror(fstatus));
		goto kstream_exit;
	}
	auks_log2("worker[%d] : authentication succeed on socket %d (%s)",
		  wargs->id,socket,kstream.remote_host);
	
	
	/* get remote principal */
	fstatus = auks_krb5_stream_get_rprinc(&kstream,
					      client_principal,
					      AUKS_PRINCIPAL_MAX_LENGTH);
	if(fstatus){
		auks_log("worker[%d] : unable to get client principal : %s",
			 wargs->id,auks_strerror(fstatus));
		goto kstream_exit;
	}
	auks_log2("worker[%d] : %s connected on socket %d (%s)",wargs->id,
		  client_principal,kstream.stream,kstream.remote_host);
	
	/* get client role */
	fstatus = auks_acl_get_role(&(engine->acl),client_principal,"*",&role);
	if(fstatus){
		auks_log("worker[%d] : unable to get client role from ACL : %s",
			 wargs->id, auks_strerror(fstatus));
		goto kstream_exit;
	}

	/* check client role */
	if(role==AUKS_ACL_ROLE_GUEST){
		role_string="guest";
	}
	else if(role==AUKS_ACL_ROLE_USER){
		role_string="user";
	}
	else if(role==AUKS_ACL_ROLE_ADMIN){
		role_string="admin";
	}
	else{
		role_string="unknown";
		fstatus = AUKS_ERROR_DAEMON_NOT_AUTHORIZED ;
	}
	auks_log2("worker[%d] : %s role is %s",wargs->id,client_principal,
		 role_string);

	/* drop request if client is not allowed to talk */
	/* with the server */
	if ( fstatus != AUKS_SUCCESS ) {
		auks_log("worker[%d] : access denied to %s, aborting",
			 wargs->id,client_principal);
		goto kstream_exit;
	}

	/* process request messages */
	do {
		fstatus = _auksd_process_msg(p_args,client_principal,
					     role,&kstream);
	}
	while ( fstatus == AUKS_SUCCESS );

	/* treat done request error as a success */
	if ( fstatus == AUKS_ERROR_DAEMON_REQUEST_DONE )
		fstatus = AUKS_SUCCESS ;
	
kstream_exit:
	auks_krb5_stream_free_contents(&kstream);
	
exit:
	return fstatus;
}

/* private functions implementations */
int
_auksd_process_msg(void* p_args,char* principal,int role,
		   auks_krb5_stream_t* kstream) {

	int fstatus = AUKS_ERROR ;

	auksd_worker_args_t* wargs;
	auksd_engine_t* engine;
	
	char* buffer;
	size_t length;
	auks_message_t req;
	auks_message_t rep;

	char * req_type = "invalid";

	wargs=(auksd_worker_args_t*)p_args;
	if(wargs==NULL){
		return fstatus ;
	}
	engine=wargs->engine;


	/* receive request */
	fstatus = auks_krb5_stream_receive_msg(kstream,&buffer,&length);
	if( fstatus != AUKS_SUCCESS ){
		auks_log("worker[%d] : marshalled request reception failed "
			 ": %s",wargs->id,auks_strerror(fstatus));
		goto exit;
	}
	auks_log3("worker[%d] : marshalled request reception succeed",
		  wargs->id);

	/* unmarshall request */
	fstatus=auks_message_load(&req,buffer,length);
	if(fstatus){
		auks_log("worker[%d] : unable to unmarshall received "
			 "marshalled request : %s",wargs->id,
			 auks_strerror(fstatus));
		goto req_exit;
	}
	
	/* process request */
	switch(req.type){
	case AUKS_PING_REQUEST :
		req_type = "ping";
		fstatus = _auksd_ping_req(p_args,principal,role,
					 &req,&rep);
		break;
	case AUKS_LIST_REQUEST :
		req_type = "list";
		fstatus = _auksd_list_req(p_args,principal,role,
					  &req,&rep);
		break;
	case AUKS_ADD_REQUEST :
		req_type = "add";
		fstatus = _auksd_add_req(p_args,principal,role,
					&req,&rep);
		break;
	case AUKS_GET_REQUEST :
		req_type = "get";
		fstatus = _auksd_get_req(p_args,principal,role,
					&req,&rep);
		break;
	case AUKS_REMOVE_REQUEST :
		req_type = "remove";
		fstatus = _auksd_remove_req(p_args,principal,role,
					   &req,&rep);
		break;
	case AUKS_DUMP_REQUEST :
		req_type = "dump";
		fstatus = _auksd_dump_req(p_args,principal,role,
					  &req,&rep);
		break;

	case AUKS_CLOSE_REQUEST :
		req_type = "close";
		fstatus = AUKS_ERROR_DAEMON_REQUEST_DONE ;
		break;

	default :
		fstatus = AUKS_ERROR_DAEMON_UNKNOWN_REQUEST ;
		break;
	}
	
	if( fstatus == AUKS_SUCCESS) {
		auks_log("worker[%d] : %s from %s : %s request succeed",
			 wargs->id,principal,
			 kstream->remote_host,req_type);
	}
	else if ( fstatus == AUKS_ERROR_DAEMON_REQUEST_DONE ) {
		auks_log2("worker[%d] : %s from %s : %s request succeed",
			  wargs->id,principal,
			  kstream->remote_host,req_type);
	}
	else {
		auks_log("worker[%d] : %s from %s : %s request failed : %s",
			 wargs->id,principal,
			 kstream->remote_host,req_type,
			 auks_strerror(fstatus));
		
		fstatus = auks_message_init(&rep,AUKS_ERROR_REPLY,NULL,0);
		if( fstatus != AUKS_SUCCESS ) {
			auks_log("worker[%d] : %s from %s : unable to init"
				 " error reply message",wargs->id,principal,
				 kstream->remote_host);
			fstatus = AUKS_ERROR_DAEMON_REPLY_INIT ;
			goto msg_exit;
		}
	}
	
	/* don't send reply in case of close request */
	if ( req.type == AUKS_CLOSE_REQUEST )
		goto msg_exit;

	/* send reply message */
	fstatus = auks_krb5_stream_send_msg(kstream,
					    auks_message_data(&rep),
					    auks_message_packed(&rep));
	if(fstatus){
		auks_log("worker[%d] : %s from %s : unable to send reply",
			 wargs->id,principal,
			 kstream->remote_host,req_type);
		fstatus = AUKS_ERROR_DAEMON_REPLY_TRANSMISSION ;
	}
	else {
		auks_log2("worker[%d] : %s from %s : reply successfully sent",
			  wargs->id,principal,kstream->remote_host,req_type);
		fstatus = AUKS_SUCCESS;
	}

	auks_message_free_contents(&rep);
	
msg_exit:
	auks_message_free_contents(&req);
	
req_exit:
	free(buffer);
exit:	
	return fstatus;
}

int
_auksd_ping_req(void* p_args,char* principal,int role,
		auks_message_t* req,auks_message_t* rep)
{
	int fstatus;
	
	/* initialized ping reply message */
	fstatus = auks_message_init(rep,AUKS_PING_REPLY,NULL,0);

	return fstatus;
}


int
_auksd_add_req(void* p_args,char* principal,int role,
	       auks_message_t* req,auks_message_t* rep)
{
	int fstatus = AUKS_ERROR ;

	auksd_worker_args_t* wargs;
	auksd_engine_t* engine;
	
	auks_cred_t cred;
	
	size_t length;
	size_t unpacked;

	wargs=(auksd_worker_args_t*)p_args;
	if(wargs==NULL){
		return fstatus ;
	}
	engine=wargs->engine;

	fstatus = auks_buffer_unpack_int(&req->buffer,(int*)&length);
	if(fstatus){
		auks_log2("worker[%d] : unable to get cred length from "
			  "add request",wargs->id);
		fstatus = AUKS_ERROR_DAEMON_CORRUPTED_REQUEST ;
		goto exit;
	}
	
	unpacked = auks_message_unpacked(req) ;
	if ( (int) length >  (int) unpacked ) {
		auks_log2("worker[%d] : add request is corrupted : "
			  "cred length=%u | unpacked data=%u",wargs->id,
			  length,unpacked);
		fstatus = AUKS_ERROR_DAEMON_CORRUPTED_REQUEST ;
		goto exit;
	}
	
	fstatus=auks_cred_init(&cred,&req->buffer.data[req->buffer.processed],
			       length);
	if(fstatus){
		auks_log2("worker[%d] : unable to initialize '%s' auks cred",
			  wargs->id,principal);
		goto exit;
	}

	/* check that input cred is an addressless one (not addressful) */
	if ( cred.info.addressless == 0 ) {
		fstatus = AUKS_ERROR_DAEMON_ADDRESSFUL_CRED ;
		goto cred_exit;
	}

	/* add cred to repository */
	/* we don't have to check role as any role here */
	/* is valid for addition (guest, user, admin) */
	/* we just check that cred principal equals requester principal */
	/* if role is not admin */
	switch(role) {

	case AUKS_ACL_ROLE_ADMIN : 
		fstatus = AUKS_SUCCESS ;
		break;
		
	default :
		if ( strncmp(cred.info.principal,principal,
			     AUKS_PRINCIPAL_MAX_LENGTH) == 0 ) {
			auks_log3("worker[%d] : to add cred principal ('"
				  "%s') equals requester's one ('%s')",
				  wargs->id,cred.info.principal,principal);
			fstatus = AUKS_SUCCESS ;
		}
		else{
			auks_log3("worker[%d] : to add cred principal ('%s')"
				  " differs from requester's one ('%s')",
				  wargs->id,cred.info.principal,principal);
			fstatus = AUKS_ERROR_DAEMON_PRINCIPALS_MISMATCH ;
			goto cred_exit;
		}
		break;
	}

	if ( fstatus != AUKS_SUCCESS )
		goto cred_exit;

	fstatus=auks_cred_repo_add(wargs->cred_repo,
				   &cred);
	if( fstatus != AUKS_SUCCESS ){
		auks_log2("worker[%d] : unable to add cred to repo : "
			  "%s",wargs->id,auks_strerror(fstatus));
		goto cred_exit;
	}

	auks_log2("worker[%d] : %s cred successfully add to repo",wargs->id,
		  cred.info.principal);
	
	
	/* initialized reply message */
	fstatus = auks_message_init(rep,AUKS_ADD_REPLY,NULL,0);
	
cred_exit:
	auks_cred_free_contents(&cred);

exit:
	return fstatus;
}


int
_auksd_get_req(void* p_args,char* principal,int role,
	       auks_message_t* req,auks_message_t* rep)
{
	int fstatus = AUKS_ERROR ;

	auksd_worker_args_t* wargs;
	auksd_engine_t* engine;
	
	auks_cred_t cred;
	int clean_cred=0;
	
	uid_t requested_uid;
	
	wargs=(auksd_worker_args_t*)p_args;
	if(wargs==NULL){
		return AUKS_ERROR ;
	}
	engine=wargs->engine;
	
	/* unpack requested uid from request */
	fstatus = auks_buffer_unpack_uid(&req->buffer,
					 &requested_uid);
	if ( fstatus != AUKS_SUCCESS ) {
		fstatus = AUKS_ERROR_DAEMON_REQUEST_UNPACK_UID;
		return fstatus;
	}
	
	/* get cred from repository */
	fstatus = auks_cred_repo_get(wargs->cred_repo,requested_uid,&cred);
	if(fstatus){
		auks_log2("worker[%d] : unable to get '%d' cred from repo : "
			  "%s",wargs->id,requested_uid,auks_strerror(fstatus));
	}
	else{
		clean_cred=1;
		auks_log3("worker[%d] : '%d' cred successfully got from repo",
			  wargs->id,requested_uid);
		
		/* here should stay a forward mechanism if adddressfull */
		/* tickets are required... */
		/*...*/

		/* test authorization to do a rw action */
		fstatus = _auksd_check_rw_right(p_args,principal,role,&cred);

	}

	/* initialized reply message */
	if( fstatus == AUKS_SUCCESS )
		fstatus = auks_message_init(rep,AUKS_GET_REPLY,
					    NULL,0);

	/* pack credential */
	if ( fstatus == AUKS_SUCCESS ) {
		fstatus = auks_cred_pack(&cred,rep);
		if ( fstatus != AUKS_SUCCESS ) {
			auks_message_free_contents(rep);
		}
	}

	/* clean cred if it was successfully extracted */
	if(clean_cred)
		auks_cred_free_contents(&cred);

	return fstatus;
}


int
_auksd_remove_req(void* p_args,char* principal,int role,
		  auks_message_t* req,auks_message_t* rep)
{
	int fstatus = AUKS_ERROR ;

	auksd_worker_args_t* wargs;
	auksd_engine_t* engine;
	
	auks_cred_t cred;
	int clean_cred=0;
	
	uid_t requested_uid;
	
	wargs=(auksd_worker_args_t*)p_args;
	if(wargs==NULL){
		return fstatus;
	}
	engine=wargs->engine;
	
	/* unpack requested uid from request */
	fstatus = auks_buffer_unpack_uid(&req->buffer,
					 &requested_uid);
	if ( fstatus!= AUKS_SUCCESS ) {
		fstatus = AUKS_ERROR_DAEMON_REQUEST_UNPACK_UID;
		return fstatus;
	}
	auks_log3("worker[%d] : get request is relative to '%d' cred",
		  requested_uid);

	fstatus=auks_cred_repo_get(wargs->cred_repo,
				   requested_uid,&cred);
	if(fstatus){
		auks_log2("worker[%d] : unable to get '%d' cred from repo : %s",
			  wargs->id,requested_uid,auks_strerror(fstatus));
	}
	else{
		clean_cred=1;
		
		/* test authorization to do a rw action */
		fstatus = _auksd_check_rw_right(p_args,principal,role,&cred);

	}

	/* we can remove the cred */
	if( fstatus == AUKS_SUCCESS ) {
		fstatus = auks_cred_repo_remove(wargs->cred_repo,
						requested_uid);
		if( fstatus != AUKS_SUCCESS ) {
			auks_log3("worker[%d] : unable to remove '%d' cred "
				  "(principal '%s')",wargs->id,
				  requested_uid,cred.info.principal);
			fstatus = AUKS_ERROR_DAEMON_PROCESSING_REQUEST ;
		}
		else {
			auks_log3("worker[%d] : '%d' cred (principal '%s') "
				  "successfully removed from repo",
				  wargs->id,
				  requested_uid,cred.info.principal);
		}
	}
	
	/* initialized reply message */
	if(fstatus == AUKS_SUCCESS)
		fstatus=auks_message_init(rep,AUKS_REMOVE_REPLY,NULL,0);
	
	/* clean cred if it was successfully extracted */
	if(clean_cred)
		auks_cred_free_contents(&cred); 

	return fstatus;
}


int
_auksd_list_req(void* p_args,char* principal,int role,
		auks_message_t* req,auks_message_t* rep)
{
	int fstatus;
	
	/* initialized ping reply message */
	fstatus = auks_message_init(rep,AUKS_PING_REPLY,NULL,0);

	return fstatus;
}

int
_auksd_dump_req(void* p_args,char* principal,int role,
		auks_message_t* req,auks_message_t* rep)
{
	int fstatus = AUKS_ERROR ;
	
	auksd_worker_args_t* wargs;

	wargs=(auksd_worker_args_t*)p_args;
	if(wargs==NULL){
		return AUKS_ERROR ;
	}
	
	switch(role){

	case AUKS_ACL_ROLE_ADMIN : 
		auks_log3("worker[%d] : %s is allowed to dump cred repository",
			  wargs->id,principal);
		fstatus = AUKS_SUCCESS;
		break;
		
	default :
		auks_log3("worker[%d] : %s is NOT allowed to dump cred "
			  "repository",wargs->id,principal);
		fstatus = AUKS_ERROR_DAEMON_NOT_AUTHORIZED ;
		break;

	}

	if( fstatus != AUKS_SUCCESS )
		return fstatus;

	/* initialized reply message */
	fstatus = auks_message_init(rep,AUKS_DUMP_REPLY,
				    NULL,0);
	if ( fstatus != AUKS_SUCCESS )
		return fstatus;

	/* pack repository into dump reply */
	fstatus = auks_cred_repo_pack(wargs->cred_repo,rep);
	if ( fstatus != AUKS_SUCCESS ) {
		auks_log3("worker[%d] : unable to pack repo : %s",
			  wargs->id,auks_strerror(fstatus));
		auks_message_free_contents(rep);
	}
	
	return fstatus;
}

int
_auksd_check_rw_right(void* p_args,char* principal,int role,
		      auks_cred_t * cred) {

	int fstatus = AUKS_ERROR ;

	auksd_worker_args_t* wargs;
	
	wargs=(auksd_worker_args_t*)p_args;
	if(wargs==NULL){
		return fstatus;
	}

	switch(role){

	case AUKS_ACL_ROLE_ADMIN : 
		auks_log3("worker[%d] : cred principal ('%s') is "
			  "administrated by requester ('%s')",wargs->id,
			  cred->info.principal,principal);
		fstatus = AUKS_SUCCESS;
		break;
		
	case AUKS_ACL_ROLE_USER :
		if ( strncmp(cred->info.principal,principal,
			     AUKS_PRINCIPAL_MAX_LENGTH) == 0 ) {
			auks_log3("worker[%d] : cred principal ('"
				  "%s') equals requester's one ('%s')",
				  wargs->id,cred->info.principal,principal);
			fstatus = AUKS_SUCCESS;
		}
		else{
			auks_log3("worker[%d] : cred principal ('%s') differs "
				  "from requester's one ('%s')",wargs->id,
				  cred->info.principal,principal);
			fstatus = AUKS_ERROR_DAEMON_PRINCIPALS_MISMATCH ;
		}
		break;

	case AUKS_ACL_ROLE_GUEST :
		auks_log3("worker[%d] : 'guest' role does not allow "
			  "'%s' to get a cred",wargs->id,principal);
		fstatus = AUKS_ERROR_DAEMON_NOT_AUTHORIZED ;
		break;
		
	default :
		auks_log3("worker[%d] : cred principal ('%s') can't be given "
			  "to requester ('%s')",wargs->id,cred->info.principal,
			  principal);
		fstatus = AUKS_ERROR_DAEMON_NOT_AUTHORIZED ;
		break;
	}
	
	return fstatus ;
}
