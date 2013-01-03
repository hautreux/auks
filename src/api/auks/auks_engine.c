/***************************************************************************\
 * auks_engine.c - AUKS API and renewer daemon conf engines implementation
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
#include <limits.h>

#include "confparse/config_parsing.h"
extern char extern_errormsg[1024];

#define AUKS_LOG_HEADER "auks_engine: "
#define AUKS_LOG_BASE_LEVEL 2

#include "auks/auks_error.h"
#include "auks/auks_engine.h"
#include "auks/auks_log.h"

#define xfree(a) if(a!=NULL){free(a);a=NULL;}

#define DEFAULT_AUKS_RETRIES 3
#define DEFAULT_AUKS_TIMEOUT 10

#define init_strdup(a,b)			\
	if ( b == NULL )			\
		a = NULL ;			\
	else					\
		a = strdup(b) ;

int
auks_engine_free_contents(auks_engine_t * engine)
{
	int fstatus = AUKS_ERROR ;

	xfree(engine->ccache);

	xfree(engine->primary_hostname);
	xfree(engine->primary_address);
	xfree(engine->primary_port);
	xfree(engine->primary_principal);

	xfree(engine->secondary_hostname);
	xfree(engine->secondary_address);
	xfree(engine->secondary_port);
	xfree(engine->secondary_principal);

	xfree(engine->logfile);
	xfree(engine->debugfile);

	if ( engine->logfd != NULL ) {
		fclose(engine->logfd);
		engine->logfd = NULL;
	}
	if ( engine->debugfd != NULL ) {
		fclose(engine->debugfd);
		engine->debugfd = NULL;
	}

	engine->loglevel = 0;
	engine->debuglevel = 0;

	engine->retries = DEFAULT_AUKS_RETRIES ;
	engine->timeout = DEFAULT_AUKS_TIMEOUT ;

	engine->nat_traversal = DEFAULT_AUKS_NAT_TRAVERSAL ;

	xfree(engine->renewer_logfile);
	xfree(engine->renewer_debugfile);

	engine->renewer_loglevel = DEFAULT_AUKSDRENEWER_LOGLEVEL;
	engine->renewer_debuglevel = DEFAULT_AUKSDRENEWER_DEBUGLEVEL;

	engine->renewer_delay = DEFAULT_AUKSDRENEWER_DELAY ;
	engine->renewer_minlifetime = DEFAULT_AUKSDRENEWER_MINLIFETIME ;

	fstatus = AUKS_SUCCESS ;

	return fstatus;
}

int
auks_engine_init(auks_engine_t * engine,
		 char *primary_hostname,
		 char *primary_address,
		 char *primary_port,
		 char *primary_principal,
		 char *secondary_hostname,
		 char *secondary_address,
		 char *secondary_port,
		 char *secondary_principal,
		 char *logfile,int loglevel,
		 char *debugfile,int debuglevel,
		 int retries,time_t timeout,
		 time_t delay,int nat_traversal,
		 char* renewer_logfile,int renewer_loglevel,
		 char* renewer_debugfile,int renewer_debuglevel,
		 time_t renewer_delay,
		 time_t renewer_minlifetime)
{
	int fstatus = AUKS_ERROR ;

	engine->ccache=NULL;

	engine->logfd=NULL;
	engine->debugfd=NULL;

	init_strdup(engine->primary_hostname,
		    primary_hostname);
	if ( primary_address == NULL ) {
		init_strdup(engine->primary_address,
			    primary_hostname);
	}
	else {
		init_strdup(engine->primary_address,
			    primary_address);
	}
	init_strdup(engine->primary_port,
		    primary_port);
	init_strdup(engine->primary_principal,
		    primary_principal);

	init_strdup(engine->secondary_hostname,
		    secondary_hostname);
	if ( secondary_address == NULL ) {
		init_strdup(engine->secondary_address,
			    secondary_hostname);
	}
	else {
		init_strdup(engine->secondary_address,
			    secondary_address);
	}
	init_strdup(engine->secondary_port,
		    secondary_port);
	init_strdup(engine->secondary_principal,
		    secondary_principal);

	init_strdup(engine->logfile,logfile);
	engine->loglevel = loglevel;

	init_strdup(engine->debugfile,debugfile);
	engine->debuglevel = debuglevel;

	engine->retries = retries ;
	engine->timeout = timeout ;
	engine->delay = delay ;

	engine->nat_traversal = nat_traversal ;

	init_strdup(engine->renewer_logfile,renewer_logfile);
	engine->renewer_loglevel = renewer_loglevel;

	init_strdup(engine->renewer_debugfile,renewer_debugfile);
	engine->renewer_debuglevel = renewer_debuglevel;

	engine->renewer_delay = renewer_delay;
	engine->renewer_minlifetime = renewer_minlifetime;


	if (engine->primary_hostname == NULL ||
	    engine->primary_address == NULL ||
	    engine->primary_port == NULL ||
	    engine->primary_principal == NULL ||
	    engine->secondary_hostname == NULL ||
	    engine->secondary_address == NULL ||
	    engine->secondary_port == NULL ||
	    engine->secondary_principal == NULL ||
	    engine->logfile == NULL || 
	    engine->debugfile == NULL  ||
	    engine->renewer_logfile == NULL || 
	    engine->renewer_debugfile == NULL ) {
		auks_engine_free_contents(engine);
		fstatus = AUKS_ERROR_ENGINE_CONFFILE_INCOMPLETE ;
		return fstatus;
	}

	auks_log2("engine %s is '%s'",
		  "primary daemon",
		  engine->primary_hostname);
	auks_log2("engine %s is '%s'",
		  "primary daemon address",
		  engine->primary_address);
	auks_log2("engine %s is %s", "primary daemon port",
		  engine->primary_port);
	auks_log2("engine %s is %s",
		  "primary daemon principal",
		  engine->primary_principal);
	
	auks_log2("engine %s is '%s'",
		  "secondary daemon",
		  engine->secondary_hostname);
	auks_log2("engine %s is '%s'",
		  "secondary daemon address",
		  engine->secondary_address);
	auks_log2("engine %s is %s",
		  "secondary daemon port",
		  engine->secondary_port);
	auks_log2("engine %s is %s",
		  "secondary daemon principal",
		  engine->secondary_principal);

	auks_log2("engine %s is %s", "logfile",
		  engine->logfile);
	auks_log2("engine %s is %d", "loglevel",
		  engine->loglevel);
	auks_log2("engine %s is %s", "debugfile",
		  engine->debugfile);
	auks_log2("engine %s is %d", "debuglevel",
		  engine->debuglevel);

	auks_log2("engine %s is %d", "retry number",
		  engine->retries);
	auks_log2("engine %s is %d", "timeout",
		  engine->timeout);
	auks_log2("engine %s is %d", "delay",
		  engine->delay);
	auks_log2("engine %s is %s", "NAT traversal mode",
		  (engine->nat_traversal==0)?"disabled":"enabled");

	auks_log2("engine %s is %s", "renewer_logfile",
		  engine->renewer_logfile);
	auks_log2("engine %s is %d", "renewer_loglevel",
		  engine->renewer_loglevel);
	auks_log2("engine %s is %s", "renewer_debugfile",
		  engine->renewer_debugfile);
	auks_log2("engine %s is %d", "renewer_debuglevel",
		  engine->renewer_debuglevel);
	auks_log2("engine %s is %d", "renewer delay",
		  engine->renewer_delay);
	auks_log2("engine %s is %d", "renewer min cred lifetime",
		  engine->renewer_minlifetime);
	
	if ( engine->logfile != NULL ) {
		engine->logfd = fopen(engine->logfile,"a+");
		if ( engine->logfd != NULL ) {
			xverbose_setstream(engine->logfd);
			xerror_setstream(engine->logfd);
		}
		xverbose_setmaxlevel(loglevel);
		xerror_setmaxlevel(loglevel);
	}

	fstatus = AUKS_SUCCESS ;

	return fstatus;
}

int
auks_engine_set_logfile(auks_engine_t * engine,char* logfile)
{
	int fstatus = AUKS_ERROR ;

	if ( logfile == NULL )
		return fstatus;

	if ( engine->logfile != NULL )
		free(engine->logfile);
	engine->logfile=strdup(logfile);
	
	if ( engine->logfile == NULL )
		return fstatus;
	
	if ( engine->logfd != NULL )
		fclose(engine->logfd);

	engine->logfd = fopen(engine->logfile,"a+");
	if ( engine->logfd != NULL ) {
		xverbose_setstream(engine->logfd);
		xerror_setstream(engine->logfd);
		fstatus = AUKS_SUCCESS ;
	}

	return fstatus;
}

int
auks_engine_set_loglevel(auks_engine_t * engine,int loglevel)
{
	int fstatus = AUKS_SUCCESS ;
	
	engine->loglevel = loglevel;
	xverbose_setmaxlevel(loglevel);
	xerror_setmaxlevel(loglevel);
	
	return fstatus;	
}

int
auks_engine_init_from_config_file(auks_engine_t * engine, char *conf_file)
{
	int fstatus = AUKS_ERROR ;
	
	char* l_conf_file;
	char* e_conf_file;

	config_file_t config;
	int block_nb;
	
	char *phost;
	char *padd;
	char *pport;
	char *pprinc;

	char *shost;
	char *sadd;
	char *sport;
	char *sprinc;

	char *lfile;
	char *dfile;
	
	char *ll_str;
	char *dl_str;
	char *rnb_str;
	char *timeout_str;
	char *delay_str;
	char *nat_str;
	
	long int ll, dl, rnb, timeout, delay;

	char *renewer_lfile;
	char *renewer_dfile;
	char *renewer_ll_str;
	char *renewer_dl_str;
	char *renewer_delay_str;
	char *renewer_minlifetime_str;

	long int renewer_ll,renewer_dl,renewer_delay,renewer_minlifetime;
 
	int nat;

	int i;

	int valid_block_nb=0;

	if ( conf_file != NULL )
		l_conf_file = conf_file;
	else {
		e_conf_file = getenv("AUKS_CONF");
		if ( e_conf_file != NULL )
			l_conf_file = e_conf_file ;
		else
			l_conf_file = DEFAULT_AUKS_CONF ;
	}

	/* renewer section is not mandatory, so set default values */
	renewer_lfile = DEFAULT_AUKSDRENEWER_LOGFILE;
	renewer_ll = DEFAULT_AUKSDRENEWER_LOGLEVEL;
	renewer_dfile = DEFAULT_AUKSDRENEWER_DEBUGFILE;
	renewer_dl = DEFAULT_AUKSDRENEWER_DEBUGLEVEL;
	renewer_delay = DEFAULT_AUKSDRENEWER_DELAY ;
	renewer_minlifetime = DEFAULT_AUKSDRENEWER_MINLIFETIME ;

	/* parse configuration file */
	config = config_ParseFile(l_conf_file);
	if (!config) {
		auks_error("unable to parse configuration file %s : %s",
		      l_conf_file, extern_errormsg);
		fstatus = AUKS_ERROR_ENGINE_CONFFILE_PARSING ;
		goto exit;
	}
	
	/* get conf blocks quantity */
	block_nb = config_GetNbBlocks(config);
	if (block_nb <= 0) {
		auks_error("unable to get configuration blocks from config file"
		      " %s : %s",l_conf_file, extern_errormsg);
		fstatus = AUKS_ERROR_ENGINE_CONFFILE_INVALID ;
		goto parse_exit;
	}
	
	/* look for relevants block and add contents to engine conf */
	fstatus = AUKS_ERROR_ENGINE_CONFFILE_INCOMPLETE ;


	for (i = 0; i < block_nb; i++) {
		char *block_name;
		block_name = config_GetBlockName(config, i);
		if (strncmp("common", block_name, 6) != 0) {
			continue;
		}
		auks_log("initializing engine from 'common' block of file %s",
			 l_conf_file);

		/* primary server conf value */
		phost =
			config_GetKeyValueByName(config, i, "PrimaryHost");
		if (phost == NULL)
			phost = DEFAULT_AUKSD_PRIMARY_HOST;
		padd =
			config_GetKeyValueByName(config, i, "PrimaryAddress");
		if (padd == NULL)
			padd = DEFAULT_AUKSD_PRIMARY_ADDR;
		pport =
			config_GetKeyValueByName(config, i, "PrimaryPort");
		if (pport == NULL)
			pport = DEFAULT_AUKSD_PRIMARY_PORT;
		pprinc =
			config_GetKeyValueByName(config, i,
						 "PrimaryPrincipal");
		if (pprinc == NULL)
			pprinc = DEFAULT_AUKSD_PRIMARY_PRINC;

		/* secondary server conf value */
		shost =
			config_GetKeyValueByName(config, i, "SecondaryHost");
		if (shost == NULL)
			shost = DEFAULT_AUKSD_SECONDARY_HOST;
		sadd =
			config_GetKeyValueByName(config, i,
						 "SecondaryAddress");
		if (sadd == NULL)
			sadd = DEFAULT_AUKSD_SECONDARY_ADDR;
		sport =
			config_GetKeyValueByName(config, i, "SecondaryPort");
		if (sport == NULL)
			sport = DEFAULT_AUKSD_SECONDARY_PORT;
		sprinc =
			config_GetKeyValueByName(config, i,
						 "SecondaryPrincipal");
		if (sprinc == NULL)
			sprinc = DEFAULT_AUKSD_SECONDARY_PRINC;
		
		/* retry nb value */
		rnb_str =
		    config_GetKeyValueByName(config, i, "Retries");
		if (rnb_str == NULL)
			rnb = DEFAULT_AUKS_RETRY_NB;
		else
			rnb = strtol(rnb_str, NULL, 10);
		if (rnb == LONG_MIN || rnb == LONG_MAX)
			rnb = DEFAULT_AUKS_RETRY_NB;

		/* timeout value */
		timeout_str =
			config_GetKeyValueByName(config, i, "Timeout") ;
		if (timeout_str == NULL)
			timeout = DEFAULT_AUKS_TIMEOUT ;
		else
			timeout = strtol(timeout_str, NULL, 10);
		if (timeout == LONG_MIN || timeout == LONG_MAX)
			timeout = DEFAULT_AUKS_TIMEOUT ;

		/* delay value */
		delay_str =
			config_GetKeyValueByName(config, i, "Delay") ;
		if (delay_str == NULL)
			delay = DEFAULT_AUKS_DELAY ;
		else
			delay = strtol(delay_str, NULL, 10);
		if (delay == LONG_MIN || delay == LONG_MAX)
			delay = DEFAULT_AUKS_DELAY ;

		/* NAT traversal mode */
		nat_str =
			config_GetKeyValueByName(config, i, "NAT") ;
		if (nat_str == NULL)
			nat = DEFAULT_AUKS_NAT_TRAVERSAL ;
		else if ( strncasecmp(nat_str,"yes",4) ==0 )
			nat = 1 ;
		else
			nat = 0 ;

		valid_block_nb++;

	}
	/* EOF config block */

	for (i = 0; i < block_nb; i++) {
		char *block_name;
		block_name = config_GetBlockName(config, i);
		if (strncmp("api", block_name, 3) != 0) {
			continue;
		}
		auks_log("initializing engine from 'api' block of file %s",
			 l_conf_file);

		/* read log file value */
		lfile = config_GetKeyValueByName(config, i, "LogFile");
		if (lfile == NULL)
			lfile = DEFAULT_AUKS_LOGFILE;

		/* read log level value */
		ll_str = config_GetKeyValueByName(config, i, "LogLevel");
		if (ll_str == NULL)
			ll = DEFAULT_AUKS_LOGLEVEL;
		else
			ll = strtol(ll_str, NULL, 10);
		if (ll == LONG_MIN || ll == LONG_MAX)
			ll = DEFAULT_AUKS_LOGLEVEL;

		/* read debug file value */
		dfile = config_GetKeyValueByName(config, i, "DebugFile");
		if (dfile == NULL)
			dfile = DEFAULT_AUKS_DEBUGFILE;

		/* read debug level value */
		dl_str = config_GetKeyValueByName(config, i, "DebugLevel");
		if (dl_str == NULL)
			dl = DEFAULT_AUKS_DEBUGLEVEL;
		else
			dl = strtol(dl_str, NULL, 10);
		if (dl == LONG_MIN || dl == LONG_MAX)
			dl = DEFAULT_AUKS_DEBUGLEVEL;

		valid_block_nb++;

	}
	/* EOF config block */

	for (i = 0; i < block_nb; i++) {
		char *block_name;
		block_name = config_GetBlockName(config, i);
		if (strncmp("renewer", block_name, 3) != 0) {
			continue;
		}
		auks_log("initializing engine from 'renewer' block of file %s",
			 l_conf_file);

		/* read log file value */
		renewer_lfile = config_GetKeyValueByName(config, i, "LogFile");
		if (renewer_lfile == NULL)
			renewer_lfile = DEFAULT_AUKSDRENEWER_LOGFILE;

		/* read log level value */
		renewer_ll_str = config_GetKeyValueByName(config, i, "LogLevel");
		if (renewer_ll_str == NULL)
			renewer_ll = DEFAULT_AUKSDRENEWER_LOGLEVEL;
		else
			renewer_ll = strtol(renewer_ll_str, NULL, 10);
		if (renewer_ll == LONG_MIN || renewer_ll == LONG_MAX)
			renewer_ll = DEFAULT_AUKSDRENEWER_LOGLEVEL;

		/* read debug file value */
		renewer_dfile = config_GetKeyValueByName(config, i, "DebugFile");
		if (renewer_dfile == NULL)
			renewer_dfile = DEFAULT_AUKSDRENEWER_DEBUGFILE;

		/* read debug level value */
		renewer_dl_str = config_GetKeyValueByName(config, i, "DebugLevel");
		if (renewer_dl_str == NULL)
			renewer_dl = DEFAULT_AUKSDRENEWER_DEBUGLEVEL;
		else
			renewer_dl = strtol(renewer_dl_str, NULL, 10);
		if (renewer_dl == LONG_MIN || renewer_dl == LONG_MAX)
			renewer_dl = DEFAULT_AUKSDRENEWER_DEBUGLEVEL;

		/* delay value */
		renewer_delay_str =
			config_GetKeyValueByName(config, i, "Delay") ;
		if (renewer_delay_str == NULL)
			renewer_delay = DEFAULT_AUKSDRENEWER_DELAY ;
		else
			renewer_delay = strtol(renewer_delay_str, NULL, 10);
		if (renewer_delay == LONG_MIN || renewer_delay == LONG_MAX)
			renewer_delay = DEFAULT_AUKSDRENEWER_DELAY ;

		/* minlifetime value */
		renewer_minlifetime_str =
			config_GetKeyValueByName(config, i, "Minlifetime") ;
		if (renewer_minlifetime_str == NULL)
			renewer_minlifetime = DEFAULT_AUKSDRENEWER_MINLIFETIME ;
		else
			renewer_minlifetime = strtol(renewer_minlifetime_str, 
						     NULL, 10);
		if (renewer_minlifetime == LONG_MIN || 
		    renewer_minlifetime == LONG_MAX)
			renewer_minlifetime = DEFAULT_AUKSDRENEWER_MINLIFETIME ;

	}
	/* EOF config block */


	if ( valid_block_nb == 2 )
		fstatus = AUKS_SUCCESS;

	if ( fstatus == AUKS_SUCCESS ) {

		fstatus = auks_engine_init(engine,
					   phost,padd, pport, pprinc,
					   shost,sadd, sport, sprinc,
					   lfile,ll,dfile,dl,
					   rnb,timeout,delay,nat,
					   renewer_lfile,renewer_ll,
					   renewer_dfile,renewer_dl,
					   renewer_delay,renewer_minlifetime);
		
	}
	
parse_exit:
	/* free config file */
	config_Free(config);
	
exit:
	return fstatus;
}
