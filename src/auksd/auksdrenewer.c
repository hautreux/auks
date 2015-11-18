/***************************************************************************\
 * auksdrenewer.c - AUKS daemon in charge of credentials renewals
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

#define AUKS_LOG_HEADER "renewer: "
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

/* main sub functions */
int auksd_renewer_loop(auks_engine_t* engine);
int renewer_main_function(auks_engine_t* engine,int* renewed);

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
 * Renewer Main Function :
 *
 *  - dump auksd creds
 *  - renew and push those who need to be renewed
 *
 */
int
renewer_main_function(auks_engine_t* engine,int* pr)
{
	int fstatus;

	time_t ctime;

	int i;
	int delay,life;
	int renewed;

	auks_cred_t* creds;
	auks_cred_t* acred;
	int creds_nb;

	renewed=0;

	/* dump auks creds table */
	fstatus = auks_api_dump(engine,&creds,&creds_nb);
	if ( fstatus != AUKS_SUCCESS ) {
		auks_log("unable to dump auksd creds : %s",
			  auks_strerror(fstatus));
		goto end;
	}
	if ( creds_nb > 0 )
		auks_log("%d creds dumped",creds_nb);

	/* look at each cred and try to renew it if required */
	for ( i = 0 ; i < creds_nb ; i++ ) {

		if ( eof_main_loop_flag )
			break;

		acred = creds+i;

		life = (int) acred->info.endtime -
			(int) acred->info.starttime ;

		/* check for renewability */
		if ( life == 0 ) {
			auks_log3("%s's cred is not renewable",
				  acred->info.principal);
			continue;
		}

		/* check for renewability */
		if ( life <= engine->renewer_minlifetime ) {
			auks_log3("%s's cred lifetime is too short to "
				  "be renewed (%us<%us)",acred->info.principal,
				  life,engine->renewer_minlifetime);
			continue;
		}

		/* get current time */
		time(&ctime);

		/* get delay in seconds before expiration */
		delay = (int) (acred->info.endtime - ctime) ;

		/* current time is higher than cred end time */
		/* auksd should remove it soon */
		if ( delay  < 0 ) {
			auks_log3("%s 's cred is no longer usable",
				  acred->info.principal);
			continue;
		}

		/* should it be renewed now ? */
		/* we renew it based on the min cred age */
		/* for example, min cred age is 5 minutes */
		/* we don't care of cred that have a lifetime lower than that */
		/* we renew creds when the delay until end of time is lower */
		/* than this amount of time */
		if ( delay > engine->renewer_minlifetime ) {
			auks_log3("%s's cred doesn't need to be "
				  "renewed now",acred->info.principal);
			continue;
		}

		/* renew it in an adressless one */
		fstatus = auks_cred_renew(acred,1);
		if ( fstatus != AUKS_SUCCESS ) {
			auks_log2("%s's cred can not be renewed in an "
				  "addressless one : %s",
				  acred->info.principal,
				  auks_strerror(fstatus));
			continue;
		}
		auks_log3("%s's cred renewed in an addressless one",
			  acred->info.principal);

		/* add it to the auksd repo */
		fstatus = auks_api_add_auks_cred(engine,acred);
		if ( fstatus != AUKS_SUCCESS ) {
			auks_log2("%s's renewed cred can not be added "
				  "to auksd : %s",acred->info.principal,
				  auks_strerror(fstatus));
			continue;
		}
		auks_log2("%s's renewed cred successfully added to auksd",
			  acred->info.principal,auks_strerror(fstatus));



		/* increment renewed creds counter */
		renewed++;
	}

	free(creds);

	*pr=renewed;
end:
	return fstatus;
}


int
auksd_renewer_loop(auks_engine_t* engine)
{

	int fstatus = AUKS_SUCCESS ;

	time_t atime,btime;

	int pt;
	int renewed;

	/* TODO : should be gotten from conf file */
	int period = engine->renewer_delay ;

	eof_main_loop_flag=0;

	/* loop on renew stage as long as necessary */
	do {
		time(&atime);
		renewer_main_function(engine,&renewed);
		time(&btime);
		if ( renewed > 0 )
			auks_log("%d creds renewed in ~%us",
				 renewed,btime-atime);

		if ( ! eof_main_loop_flag ) {

			/* just sleep enough time to ensure */
			/* the period */
			pt = (int) btime - (int) atime ;
			pt = period - pt;
			if ( pt > 0 ) {
				auks_log2("sleeping %d seconds before next "
					  "renew",pt);
				sleep (pt) ;
			}
			else
				auks_log("delayed by previous run, directly "
					 "starting next renew");

		}

	}
	while ( eof_main_loop_flag == 0 ) ;

	auks_log("ending main loop");

exit:
	return fstatus ;
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

	int default_debug_level=0;
	int default_verbose_level=0;

	char* conf_file_string;
	char* working_directory;

	/* options processing variables */
	char* progname;
	char* optstring="dvhf:l:F";
	char* short_options_desc="\nUsage : %s [-h] [-dv] [-F] [-f conffile] [-l logfile]\n\n";
	char* addon_options_desc="\
\t-h\t\tshow this message\n \
\t-d\t\tincrease debug level (force foreground mode)\n \
\t-v\t\tincrease verbose level (force forground mode)\n \
\t-F\t\trun in foreground\n \
\t-f conffile\tConfiguration file\n \
\t-l logfile\tlog file\n\n";
	char  option;

	/* signal handling variables */
	struct sigaction saction;

	/* auksd engine */
	auks_engine_t engine;

	/* logging */
	char* logfile_str=NULL;
	char* default_logfile_str=NULL;
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
			default_verbose_level++;
			break;
		case 'd' :
			default_debug_level++;
			break;
		case 'f' :
			conf_file_string=strdup(optarg);
			break;
		case 'F' :
			foreground_flag = 1;
			break;
		case 'l' :
			default_logfile_str=strdup(optarg);
			if ( default_logfile_str == NULL ) {
				fprintf(stderr,"memory allocation failed"
					", aborting program\n");
				exit(1);
			}
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
	xdebug_setmaxlevel(default_debug_level);
	xverbose_setmaxlevel(default_verbose_level);

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
		fstatus=auks_api_init(&engine,conf_file_string);
		if(fstatus){
			ERROR("exiting : %s",
			      auks_strerror(fstatus));
			/* error while loading conf, exit */
			exit_flag=1;
			goto conf_exit;
		}

		/* no display required, jump into background */
		if( (!default_verbose_level && !default_debug_level) ||
		    default_logfile_str != NULL )
		{
			/* go to background mode if not already done */
			if(!background_flag && !foreground_flag)
			{
				/* fork, father goes away */
				if(fork() != 0)
					exit(EXIT_SUCCESS);

				/* go into working directory */
				working_directory="/";
				chdir(working_directory);

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

			if (default_verbose_level)
				verbose_level = default_verbose_level;
			else
				verbose_level = engine.renewer_loglevel;

			if (default_debug_level)
				debug_level = default_debug_level;
			else
				debug_level = engine.renewer_loglevel;

			/* in bg mode : (re)open logfile and debug file
			 * in fg mode : set log level according to conf file */
			if (!foreground_flag) {
				if(logfile != NULL){
					fclose(logfile);
					logfile=NULL;
				}
				if(debugfile != NULL){
					fclose(debugfile);
					debugfile=NULL;
				}

				if (default_logfile_str != NULL)
					logfile_str = default_logfile_str;
				else
					logfile_str = engine.renewer_logfile;

				if((strlen(logfile_str) > 0) && verbose_level
				   && (logfile = fopen(logfile_str,"a+"))) {
					xverbose_setstream(logfile);
					xerror_setstream(logfile);
					xverbose_setmaxlevel(verbose_level);
					xerror_setmaxlevel(verbose_level);
				}
				else {
					xverbose_setmaxlevel(0);
					xerror_setmaxlevel(0);
				}

				if((strlen(engine.renewer_debugfile) > 0) &&
				   debug_level &&
				   (debugfile = fopen(engine.renewer_debugfile,
						      "a+"))) {
					xdebug_setstream(debugfile);
					xdebug_setmaxlevel(debug_level);
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
				xverbose_setmaxlevel(verbose_level);
				xerror_setmaxlevel(verbose_level);
				xdebug_setmaxlevel(debug_level);
			}
		}

		/* launch main function */
		fstatus = auksd_renewer_loop(&engine);
		if ( fstatus != AUKS_SUCCESS )
			exit_flag=1;

		/* free engine contents */
		auks_api_close(&engine);

	}

	VERBOSE("exiting");

conf_exit:
	/* free config file */
	XFREE(conf_file_string);

	XFREE(default_logfile_str);

	return fstatus;
}
