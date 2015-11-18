/***************************************************************************\
 * auksd.c - AUKS daemon in charge of auks client requests processing
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

#include "xternal/xstream.h"
#include "xternal/xqueue.h"

#define AUKS_LOG_BASE_LEVEL 1
#define AUKS_LOG_DEBUG_LEVEL 1
#include "auks/auks_log.h"
#include "auks/auks_error.h"
#include "auks/auks_engine.h"
#include "auks/auks_cred.h"
#include "auks/auks_cred_repo.h"

#include "auksd_req.h"

static volatile int eof_main_loop_flag;
static volatile int eof_worker_flag;
static volatile int print_stats_flag;
static volatile int exit_flag;

#define VERBOSE auks_log
#define VERBOSE2 auks_log2
#define VERBOSE3 auks_log3
#define ERROR VERBOSE
#define ERROR2 VERBOSE2
#define ERROR3 VERBOSE3
#define XFREE(a) if( a != NULL) { free(a); a=NULL;};

/*
 * private function definitions 
 *
 */

/* signal handler */
void signal_handler(int signum);

/* threads sub functions */
static void * worker_main_function(void* p_args);
static void * cleaner_main_function(void* p_args);
static void * processor_main_function(void* p_args);

/* main sub functions */
int auksd_main_loop(auksd_engine_t* engine);
int dispatcher_main_function(auksd_engine_t* engine,xqueue_t* socket_queue);

/*
 *
 * Signal Handler :
 *
 *  - SIGINT | SIGTERM : break main loop and exit program
 *  - SIGHUP : break main loop and reload configuration
 *  - SIGUSR2 : print stats
 *
 */
void
signal_handler(int signum)
{
	switch(signum){
	case SIGTERM :
	case SIGINT :
		exit_flag=1;
		eof_main_loop_flag=1;
		break;
	case SIGHUP :
		eof_main_loop_flag=1;
		print_stats_flag=1;
		break;
	case SIGUSR2 :
		print_stats_flag=1;
		break;
	default:
		break;
	}
}

/*
 * Processor Main Function :
 *
 *  - dequeue an incoming socket
 *  - disable thread cancellation
 *  - process incoming request
 *  - enable thread cancellation
 *  - test cancellation
 *  - loop or return on external trigger
 *
 */
static void *
processor_main_function(void* p_args)
{
	int fstatus = AUKS_ERROR ;

	auksd_worker_args_t* wargs;

	auksd_engine_t* engine;
	xqueue_t* squeue;

	int incoming_socket;
	int old_cancel_state;
	int old_cancel_state_bis;

	wargs=(auksd_worker_args_t*)p_args;
	if(wargs==NULL)
		return NULL;

	engine=wargs->engine;
	squeue=wargs->socket_queue;

	do {
		if (!eof_worker_flag) {
			fstatus=xqueue_dequeue(squeue,&incoming_socket,
					       sizeof(int));
			if ( fstatus != 0 )
				continue;
		}
		else {
			VERBOSE3("worker[%d] : purging socket queue ",
				 wargs->id,incoming_socket);
			fstatus=xqueue_dequeue_non_blocking(squeue,
							    &incoming_socket,
							    sizeof(int));
			if ( fstatus != 0 )
				break;
		}

		VERBOSE3("worker[%d] : incoming socket %d successfully "
			 "dequeued",wargs->id,incoming_socket);

		/* disable cancellation, kerberize the connection and */
		/* get the request */
		fstatus=pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,
					       &old_cancel_state);
		if(fstatus){
			ERROR2("worker[%d] : unable to disable cancellation");
		}
		else{

			/* process request */
			fstatus=auksd_process_req(p_args,incoming_socket);
			if(fstatus){
				ERROR3("worker[%d] : incoming socket %d "
				       "processing failed",wargs->id,
				       incoming_socket);
			}
			else{
				VERBOSE3("worker[%d] : incoming socket %d "
					 "processing succeed",wargs->id,
					 incoming_socket);
			}

			/* close incoming socket */
			close(incoming_socket);

			/* reenable cancellation */
			fstatus=pthread_setcancelstate(old_cancel_state,
						       &old_cancel_state_bis);
			if(fstatus){
				ERROR2("worker[%d] : unable to reenable old "
				       "cancellation state ");
			}

		}
		/*_*/ /* disable cancellation */

		pthread_testcancel();
	}
	while(1);

	return NULL;
}

/*
 *
 * Cleaner Main Function :
 *
 *  - remove expired cred from repository
 *  - sleep a little and loop
 *  - return on external trigger
 *
 */
static void *
cleaner_main_function(void* p_args)
{
	int fstatus = AUKS_ERROR ;

	auksd_worker_args_t* wargs;
	auksd_engine_t* engine;

	time_t start,end;

	int nbcred;

	wargs=(auksd_worker_args_t*)p_args;
	if(wargs==NULL)
		return NULL;

	engine=wargs->engine;

	while(!eof_worker_flag)
	{

		/* launch the clean process */
		time(&start);
		fstatus = auks_cred_repo_clean(wargs->cred_repo,&nbcred);
		time(&end);
		end=end-start;
		if( fstatus != AUKS_SUCCESS ) {
			ERROR("worker[%d] : unable to clean auks cred repo",
			      wargs->id,end);
		}
		else{
			VERBOSE2("worker[%d] : auks cred repo cleaned "
				 "in ~%us (%d creds removed)",wargs->id,
				 end,nbcred);
		}

		/* check end signal */
		if ( eof_worker_flag )
			break;

		/* wait a moment */
		sleep(engine->clean_delay);

	}

	return NULL;
}

/*
 *
 * Workers Main Function :
 *
 *  - if id == 0, execute Cleaner main function
 *  - otherwise, execute Processor main function
 *
 */
static void *
worker_main_function(void* p_args)
{
	auksd_worker_args_t* wargs;

	wargs=(auksd_worker_args_t*)p_args;
	if(wargs==NULL)
		return NULL;

	if(wargs->id==0){
		/* cleaner thread */
		cleaner_main_function(p_args);
	}
	else {
		/* processor threads */
		processor_main_function(p_args);
	}

	return NULL;
}


/*
 *
 * Dispatcher Main Function :
 *
 *  - bind a socket
 *  - listen for incoming connections
 *  - enqueue incoming sockets
 *  - return on external trigger
 *
 */
int
dispatcher_main_function(auksd_engine_t* engine,xqueue_t* socket_queue)
{
	int fstatus = AUKS_ERROR ;

	int socket;
	int incoming_socket;

	char* hostname;
	char* port;

	unsigned long successfull_dispatch=0;
	int queued_item_nb=0;

	switch ( engine->role ) {
	case PRIMARY :
		hostname = engine->primary_address ;
		port = engine->primary_port ;
		break;
	case SECONDARY :
		hostname = engine->secondary_address ;
		port = engine->secondary_port;
		break;
	default:
		fstatus = AUKS_ERROR_DAEMON_NOT_VALID_SERVER ;
		return fstatus ;
		break;
	}

	/* create stream */
	socket=xstream_create(hostname,port);
	if(socket<0){
		ERROR("dispatcher: unable to create stream on %s:%s",
		      hostname,port);
		fstatus = AUKS_ERROR_DAEMON_STREAM_CREATION ;
		goto exit;
	}
	VERBOSE("dispatcher: auksd stream created on %s:%s (fd is %d)",
		hostname,port,socket);

	/* configure stream */
	if(xstream_listen(socket,socket_queue->freelist.item_nb)){
		ERROR("dispatcher: unable to specify socket %d listening queue",
		      socket);
		goto create_exit;
	}
	VERBOSE("dispatcher: socket %d listening queue successfully specified",
		socket);

	/* stream accept loop */
	while(!eof_main_loop_flag){

		incoming_socket=xstream_accept(socket);
		if(incoming_socket<0 && !(eof_main_loop_flag || 
					  print_stats_flag)) {
			ERROR("dispatcher: error while waiting for incoming "
			      "socket");
		}
		else if(incoming_socket<0 && eof_main_loop_flag){
			VERBOSE("dispatcher: asked to no longer accept "
				"requests");
		}
		else if ( incoming_socket >= 0 ) {

			fstatus=xqueue_enqueue(socket_queue,&incoming_socket,
					       sizeof(int));
			if(fstatus){
				ERROR("dispatcher: unable to add incoming "
				      "connection to pending queue");
				close(incoming_socket);
			}
			else{
				VERBOSE3("dispatcher: incoming connection (%d)"
					 " successfully added to pending queue",
					 incoming_socket);
				successfull_dispatch++;
			}

		}
		/*_*/ /* accept event */

		if ( print_stats_flag ) {
			VERBOSE("dispatcher: %u connections dispatched",
				successfull_dispatch);
			xqueue_get_length(socket_queue,&queued_item_nb);
			VERBOSE("dispatcher: %d connections pending",
				queued_item_nb);
			print_stats_flag=0 ;
		}

	}

	/* print stats on exit */
	VERBOSE("dispatcher: %u connections dispatched",successfull_dispatch);
	fstatus = AUKS_SUCCESS ;

create_exit:
	close(socket);
exit:
	return fstatus;
}


/*!
 *
 * Main loop :
 *
 *  - start workers in background
 *  - launch dispatcher and wait for its end
 *  - wait for sockets queue emptiness
 *  - stop workers
 *  - return
 *
 */
int auksd_main_loop(auksd_engine_t* engine)
{

	int fstatus;
	int status;

	int i;

	auks_cred_repo_t cred_repo;
	xqueue_t socket_queue;

	eof_main_loop_flag=0;
	eof_worker_flag=0;

	int repo_size;
	int queue_size;
	int worker_nb;

	int queued_item_nb;
	int launched_worker_nb=0;
	pthread_attr_t worker_attr;
	size_t worker_stacksize= 3 * PTHREAD_STACK_MIN ;

	auksd_worker_args_t* worker_args;

	worker_nb = engine->threads_nb + 1; // add the cleaner thread
	queue_size = engine->queue_size ;
	repo_size = engine->repo_size ;

	/* initialize cred tree */
	fstatus = auks_cred_repo_init(&cred_repo,engine->cachedir,
				      repo_size);
	if( fstatus != AUKS_SUCCESS ){
		ERROR("auksd     : unable to initialize cred repo : %s",
		      auks_strerror(fstatus));
		goto exit;
	}

	/* initialize socket queue */
	fstatus=xqueue_init(&socket_queue,queue_size,sizeof(int));
	if(fstatus){
		ERROR("auksd     : unable to initialize workers socket queue");
		goto repo_exit;
	}

	/* initialize worker threads attributes */
	if(pthread_attr_init(&worker_attr)){
		ERROR("auksd     : unable to initialize worker threads "
		      "attributes");
		fstatus = AUKS_ERROR_DAEMON_THREAD_CONFIG;
		goto xqueue_exit;
	}

	/* set worker thread attributes */
	status=pthread_attr_setdetachstate(&worker_attr,
					   PTHREAD_CREATE_JOINABLE);
	if(status){
		ERROR("auksd     : unable to set joinable detach state "
		      "to worker threads attributes");
	}
	fstatus=status;
	status=pthread_attr_setstacksize(&worker_attr,worker_stacksize);
	if(status){
		ERROR("auksd     : unable to set worker threads stack size (%d) "
		      "attribute",worker_stacksize);
	}
	fstatus+=status;

	/* continue if previous set succeed */
	if(fstatus){
		fstatus = AUKS_ERROR_DAEMON_THREAD_CONFIG;
		goto p_attr_exit;
	}

	/* log stack size */
	size_t ss;
	pthread_attr_getstacksize(&worker_attr,&ss);
	VERBOSE("auksd     : worker threads stacksize is %u",ss);

	/* initialize worker args array */
	worker_args=(auksd_worker_args_t*)
		malloc(worker_nb*sizeof(auksd_worker_args_t));
	if(worker_args==NULL){
		ERROR("auksd     : unable to allocate worker args array");
		fstatus = AUKS_ERROR_DAEMON_THREAD_DATA ;
		goto p_sattr_exit;
	}
	VERBOSE("auksd     : worker args array successfully allocated");

	/* initialize and launch workers */
	for(i=0;i<worker_nb;i++){
		worker_args[i].id=i;
		worker_args[i].engine=engine;
		worker_args[i].socket_queue=&socket_queue;
		worker_args[i].cred_repo=&cred_repo;
		fstatus=pthread_create(&(worker_args[i].thread),
				       &worker_attr,
				       worker_main_function,&worker_args[i]);
		if(fstatus){
			ERROR2("auksd     : unable to launch worker[%d]",i);
		}
		else{
			VERBOSE2("auksd     : worker[%d] successfully launched",
				 i);
			launched_worker_nb++;
		}
	}
	VERBOSE("auksd     : %d/%d workers launched",worker_nb,
		launched_worker_nb);

	/* start main function socket dispatcher */
	fstatus = dispatcher_main_function(engine,&socket_queue);

	/* signal workers that they must enter the purge mode */
	eof_worker_flag=1;

	/* look for pending connections */
	if(xqueue_get_length(&socket_queue,&queued_item_nb)){
		ERROR("auksd     : unable to get pending connections number");
	}
	else{
		VERBOSE("auksd     : %d connections pending",queued_item_nb);
		/* wait until no more pending connection is present */
		if(queued_item_nb>0){
			VERBOSE("auksd     : waiting for queue emptiness");
			xqueue_wait_4_emptiness(&socket_queue);
		}
	}

	/* cancel worker threads */
	VERBOSE("auksd     : stopping workers");
	for(i=0;i<launched_worker_nb;i++){
		pthread_cancel(worker_args[i].thread);
	}
	/* join exited worker threads */
	for(i=0;i<launched_worker_nb;i++){
		pthread_join(worker_args[i].thread,NULL);
	}

	VERBOSE("auksd     : exiting");

	free(worker_args);

p_sattr_exit:
p_attr_exit:
	pthread_attr_destroy(&worker_attr);

xqueue_exit:
	xqueue_free_contents(&socket_queue);

repo_exit:
	auks_cred_repo_free_contents(&cred_repo);

exit:
	return fstatus;
}


int
main(int argc,char** argv)
{
	int fstatus=-1;

	int i;
	int background_flag=0;
	int foreground_flag=0;

	int debug_level=0;
	int verbose_level=0;
	char* conf_file_string;
	char* working_directory;

	/* options processing variables */
	char* progname;
	char* optstring="dvhf:F";
	char* short_options_desc="\nUsage : %s [-h] [-dv] [-F] [-f conffile]\n\n";
	char* addon_options_desc="\
\t-h\t\tshow this message\n \
\t-d\t\tincrease debug level (force foreground mode)\n \
\t-v\t\tincrease verbose level (force forground mode)\n \
\t-F\t\trun in foreground\n \
\t-f conffile\tConfiguration file\n\n";
	char  option;

	/* signal handling variables */
	struct sigaction saction;

	/* auksd engine */
	auksd_engine_t engine;

	/* logging */
	FILE* logfile=NULL;
	FILE* debugfile=NULL;

	/* get current program name */
	progname=rindex(argv[0],'/');
	if(progname==NULL)
		progname=argv[0];
	else
		progname++;

	conf_file_string = NULL;

	/* process options */
	while((option = getopt(argc,argv,optstring)) != -1)
	{
		switch(option)
		{
		case 'v' :
			verbose_level++;
			break;
		case 'd' :
			debug_level++;
			break;
		case 'f' :
			conf_file_string=strdup(optarg);
			break;
		case 'F' :
			foreground_flag = 1;
			break;
		case 'h' :
		default :
			fprintf(stdout,short_options_desc,progname);
			fprintf(stdout,"%s\n",addon_options_desc);
			exit(0);
			break;
		}
	}

	/* set verbosity and debug level */
	xdebug_setmaxlevel(debug_level);
	xverbose_setmaxlevel(verbose_level);

	/* set signal handlers */
	saction.sa_handler=signal_handler;
	sigemptyset(&(saction.sa_mask));
	saction.sa_flags=0;
	if(sigaction(SIGTERM,&saction,NULL)){
		// exit on SIGTERM
		ERROR("SIGTERM handler set up failed");
		exit_flag=1;
	}
	if(sigaction(SIGINT,&saction,NULL)){
		// exit on SIGINT
		ERROR("SIGINT handler set up failed");
		exit_flag=1;
	}
	if(sigaction(SIGHUP,&saction,NULL)){
		// reload on SIGUP
		ERROR("SIGHUP handler set up failed");
		exit_flag=1;
	}
	if(sigaction(SIGUSR2,&saction,NULL)){
		// prints stats on SIGUSR2
		ERROR("SIGUSR2 handler set up failed");
		exit_flag=1;
	}
	saction.sa_handler=SIG_IGN;
	if(sigaction(SIGCHLD,&saction,NULL)){
		// detach child
		ERROR("SIGCHLD handler set up failed");
		exit_flag=1;
	}
	if(sigaction(SIGPIPE,&saction,NULL)){
		// avoid cras in case of broken pipe
		ERROR("SIGPIPE handler set up failed");
		exit_flag=1;
	}

	/* work if needed */
	while(!exit_flag){
		/* load configuration */
		fstatus=auksd_engine_init_from_config_file(&engine,
							   conf_file_string);
		if(fstatus){
			ERROR("exiting : %s",
			      auks_strerror(fstatus));
			/* error while loading conf, exit */
			exit_flag=1;
			goto conf_exit;
		}

		/* no display required, jump into background */
		if(!verbose_level && !debug_level)
		{
			/* go to background mode if not already done */
			if(!background_flag && !foreground_flag)
			{
				/* fork, father goes away */
				if(fork() != 0)
					exit(EXIT_SUCCESS);

				/* go into working directory */
				if(strlen(engine.cachedir)>0)
				{
					working_directory=engine.cachedir;
				}
				else
					working_directory="/";
				chdir(working_directory);
				VERBOSE("working directory is now %s",
					working_directory);

				/* change session ID, fork and keep only son */
				setsid();
				if(fork() != 0)
					exit(EXIT_SUCCESS);

				/* close all open file descriptor */
				for(i=0;i<FOPEN_MAX;i++)
					close(i);

				/* set background flag in order to do all  */
				/* this job just once */
				background_flag=1;
			}


			/* in bg mode : (re)open logfile and debug file
			 * in fg mode : set log level according to conf file */
			if (!foreground_flag) {
				if (logfile != NULL){
					fclose(logfile);
					logfile = NULL;
				}
				if (debugfile != NULL){
					fclose(debugfile);
					debugfile = NULL;
				}
				if((strlen(engine.logfile) > 0) &&
				   engine.loglevel &&
				   (logfile = fopen(engine.logfile,"a+"))) {
					xverbose_setstream(logfile);
					xerror_setstream(logfile);
					xverbose_setmaxlevel(engine.loglevel);
					xerror_setmaxlevel(engine.loglevel);
				}
				else {
					xverbose_setmaxlevel(0);
					xerror_setmaxlevel(0);
				}
				if((strlen(engine.debugfile) > 0) &&
				   engine.debuglevel &&
				   (debugfile = fopen(engine.debugfile,"a+"))) {
					xdebug_setstream(debugfile);
					xdebug_setmaxlevel(engine.debuglevel);
				}
				else {
					xdebug_setmaxlevel(0);
				}
			}
			else {
				FILE* stream=stderr;
				xverbose_setstream(stream);
				xerror_setstream(stream);
				xdebug_setstream(stream);
				xverbose_setmaxlevel(engine.loglevel);
				xerror_setmaxlevel(engine.loglevel);
				xdebug_setmaxlevel(engine.debuglevel);
			}

		}

		/* launch main function */
		fstatus = auksd_main_loop(&engine) ;
		if ( fstatus != AUKS_SUCCESS )
			exit_flag=1;

		/* free engine contents */
		auksd_engine_free_contents(&engine);
		/*_*/

	}
	/*_*/

conf_exit:
	/* free config file */
	XFREE(conf_file_string);

	return fstatus;
}
