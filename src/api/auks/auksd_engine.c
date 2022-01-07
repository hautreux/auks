/***************************************************************************\
 * auksd_engine.c - AUKS daemon conf engine implementation
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

#include <errno.h>
extern int errno;

#define AUKS_LOG_HEADER "auksd_engine: "
#define AUKS_LOG_BASE_LEVEL 1

#include "auks/auks_log.h"
#include "auks/auks_error.h"
#include "auks/auks_engine.h"

#include "confparse/config_parsing.h"
extern char extern_errormsg[1024];

#define xfree(a) if(a!=NULL){free(a);a=NULL;}

#define init_strdup(a,b)			\
	{					\
		if ( b == NULL )		\
			a = NULL ;		\
		else				\
			a = strdup(b) ;		\
	}

int auksd_engine_free_contents(auksd_engine_t * engine)
{
	int fstatus = -1;

	auks_acl_free_contents(&(engine->acl));

	xfree(engine->primary_hostname);
	xfree(engine->primary_address);
	xfree(engine->primary_port);
	xfree(engine->primary_principal);
	xfree(engine->primary_keytab);

	xfree(engine->secondary_hostname);
	xfree(engine->secondary_address);
	xfree(engine->secondary_port);
	xfree(engine->secondary_principal);
	xfree(engine->secondary_keytab);

	xfree(engine->cachedir);
	xfree(engine->logfile);
	xfree(engine->debugfile);

	engine->loglevel = 0;
	engine->debuglevel = 0;

	engine->threads_nb = DEFAULT_AUKSD_THREADS_NB;
	engine->queue_size = DEFAULT_AUKSD_QUEUE_SIZE;
	engine->repo_size = DEFAULT_AUKSD_REPO_SIZE;

	engine->clean_delay = DEFAULT_AUKSD_CLEAN_DELAY;

	engine->role = UNKNOWN ;

	engine->nat_traversal = DEFAULT_AUKS_NAT_TRAVERSAL ;
	engine->replay_cache = DEFAULT_AUKS_REPLAY_CACHE ;

	fstatus = 0;

	return fstatus;
}

int
auksd_engine_init(auksd_engine_t * engine,
		  char *primary_hostname,
		  char *primary_address,
		  char *primary_port,
		  char *primary_principal,
		  char *primary_keytab,
		  char *secondary_hostname,
		  char *secondary_address,
		  char *secondary_port,
		  char *secondary_principal,
		  char *secondary_keytab,
		  char *cachedir,
		  char *acl_file,
		  char *logfile,
		  int loglevel,
		  char *debugfile,
		  int debuglevel,
		  int threads_nb,
		  int queue_size, int repo_size,
		  time_t clean_delay,
		  int nat_traversal,
		  int replay_cache)
{
	int fstatus;

	char myhostname[MAXHOSTNAMELEN] ;

	/* initialize engine value */
	fstatus = auks_acl_init_from_config_file(&(engine->acl), acl_file) ;
	if ( fstatus != 0) {
		auks_error("unable to init auksd engine ACL from file %s",
			   acl_file);
		return fstatus ;
	}
	auks_log2("engine ACL successfuly initialized using file %s",
		  acl_file);

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
	init_strdup(engine->primary_keytab,
		    primary_keytab);

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
	init_strdup(engine->secondary_keytab,
		    secondary_keytab);
	
	init_strdup(engine->cachedir,cachedir);

	init_strdup(engine->logfile,logfile);
	engine->loglevel = loglevel;

	init_strdup(engine->debugfile,debugfile);
	engine->debuglevel = debuglevel;

	engine->threads_nb = threads_nb;
	engine->queue_size = queue_size;
	engine->repo_size = repo_size;

	engine->clean_delay = clean_delay;

	engine->nat_traversal = nat_traversal ;
	engine->replay_cache = replay_cache ;

	if (engine->primary_hostname == NULL ||
	    engine->primary_address == NULL ||
	    engine->primary_port == NULL ||
	    engine->primary_principal == NULL ||
	    engine->primary_keytab == NULL ||
	    engine->secondary_hostname == NULL ||
	    engine->secondary_address == NULL ||
	    engine->secondary_port == NULL ||
	    engine->secondary_principal == NULL ||
	    engine->secondary_keytab == NULL ||
	    engine->cachedir == NULL ||
	    engine->logfile == NULL || engine->debugfile == NULL) {
		
		auks_error("unable to init auksd engine : all required conf"
			   " fields are not defined");
		auksd_engine_free_contents(engine);
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
	auks_log2("engine %s is %s",
		  "primary daemon keytab",
		  engine->primary_keytab);
	
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
	auks_log2("engine %s is %s",
		  "secondary daemon keytab",
		  engine->secondary_keytab);
	
	auks_log2("engine %s is %s", "cachedir",
		  engine->cachedir);
	auks_log2("engine %s is %s", "logfile",
		  engine->logfile);
	auks_log2("engine %s is %d", "loglevel",
		  engine->loglevel);
	auks_log2("engine %s is %s", "debugfile",
		  engine->debugfile);
	auks_log2("engine %s is %d", "debuglevel",
		  engine->debuglevel);
	
	auks_log2("engine %s is %d", "threads number",
		  engine->threads_nb);
	auks_log2("engine %s is %d",
		  "incoming requests queue size",
		  engine->queue_size);
	auks_log2("engine %s is %d",
		  "credential repository size",
		  engine->repo_size);
	auks_log2("engine %s is %u", "clean delay",
		  engine->clean_delay);
	auks_log2("engine %s is %s", "NAT traversal mode",
		  (engine->nat_traversal==0)?"disabled":"enabled");
	auks_log2("engine %s is %s", "kerberos replay cache",
		  (engine->replay_cache==0)?"disabled":"deprecated+ignored");
	
	fstatus = gethostname(myhostname,MAXHOSTNAMELEN);
	if ( fstatus != 0 ) {
		auks_log2("unable to define role : gethostname failed : %s",
			  strerror(errno));
		fstatus = AUKS_ERROR ;
		goto exit;
	}

	if ( strncmp(myhostname,engine->primary_hostname,
		     MAXHOSTNAMELEN) == 0 ) {
		auks_log("acting as a primary server");
		engine->role = PRIMARY ;		
		fstatus = AUKS_SUCCESS ;
	}
	else if ( strncmp(myhostname,engine->secondary_hostname,
			  MAXHOSTNAMELEN) == 0 ) {
		auks_log("acting as a secondary server");
		engine->role = SECONDARY ;		
		fstatus = AUKS_SUCCESS ;
	}
	else if ( strncmp("localhost",engine->primary_hostname,
			  MAXHOSTNAMELEN) == 0 || 
		  strncmp("localhost",engine->secondary_hostname,
			  MAXHOSTNAMELEN) == 0 ) {
		auks_log("acting as a local primary server");
		engine->role = PRIMARY ;
		fstatus = AUKS_SUCCESS ;
	}
	else {
		engine->role = UNKNOWN ;
		auksd_engine_free_contents(engine);
		fstatus = AUKS_ERROR_DAEMON_NOT_VALID_SERVER ;
	}

exit:
	return fstatus;
}

int
auksd_engine_init_from_config_file(auksd_engine_t * engine,
				   char *conf_file)
{
	int fstatus = AUKS_ERROR;

	char* l_conf_file;
	char* e_conf_file;

	config_file_t config;
	int block_nb;

	char *phost;
	char *padd;
	char *pport;
	char *pprinc;
	char *pktb;

	char *shost;
	char *sadd;
	char *sport;
	char *sprinc;
	char *sktb;

	char *cdir;
	char *afile;

	char *lfile;
	char *dfile;

	char *ll_str;
	char *dl_str;
	char *tnb_str;
	char *qs_str;
	char *rs_str;
	char *rd_str;
	char *nat_str;
	char *krc_str;

	long int ll, dl, tnb, qs, rs, rd;

	int nat, krc;

	int i;

	int valid_block_nb=0;

	if ( conf_file != NULL )
		l_conf_file = conf_file;
	else {
		e_conf_file = getenv("AUKSD_CONF");
		if ( e_conf_file != NULL )
			l_conf_file = e_conf_file ;
		else
			l_conf_file = DEFAULT_AUKSD_CONF ;
	}

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
		auks_error("unable to get configuration blocks from config "
			   "file %s : %s", l_conf_file, extern_errormsg);
		fstatus = AUKS_ERROR_ENGINE_CONFFILE_INVALID ;
		goto parse_exit;
	}

	/* look for relevants block and add contents to engine conf */
	fstatus = AUKS_ERROR_ENGINE_CONFFILE_INCOMPLETE ;

	for (i = 0; i < block_nb; i++) {
		char *block_name;
		block_name = config_GetBlockName(config, i);

		/* skip non config blocks */
		if (strncmp("common", block_name, 7) != 0) {
			continue;
		}
		auks_log
		    ("initializing engine from 'common' block of file %s",
		     l_conf_file);

		/* primary server conf value */
		phost =	config_GetKeyValueByName(config,i,"PrimaryHost");
		if (phost == NULL)
			phost = DEFAULT_AUKSD_PRIMARY_HOST;
		padd = config_GetKeyValueByName(config,i,"PrimaryAddress");
		if (padd == NULL)
			padd = DEFAULT_AUKSD_PRIMARY_ADDR;
		pport = config_GetKeyValueByName(config,i,"PrimaryPort");
		if (pport == NULL)
			pport = DEFAULT_AUKSD_PRIMARY_PORT;
		pprinc = config_GetKeyValueByName(config,i,"PrimaryPrincipal");
		if (pprinc == NULL)
			pprinc = DEFAULT_AUKSD_PRIMARY_PRINC;

		/* secondary server conf value */
		shost = config_GetKeyValueByName(config,i,"SecondaryHost");
		if (shost == NULL)
			shost = DEFAULT_AUKSD_SECONDARY_HOST;
		sadd = config_GetKeyValueByName(config,i,"SecondaryAddress");
		if (sadd == NULL)
			sadd = DEFAULT_AUKSD_SECONDARY_ADDR;
		sport = config_GetKeyValueByName(config,i,"SecondaryPort");
		if (sport == NULL)
			sport = DEFAULT_AUKSD_SECONDARY_PORT;
		sprinc = config_GetKeyValueByName(config,i,
						  "SecondaryPrincipal");
		if (sprinc == NULL)
			sprinc = DEFAULT_AUKSD_SECONDARY_PRINC;

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

	}			/* EOF for */

	for (i = 0; i < block_nb; i++) {
		char *block_name;
		block_name = config_GetBlockName(config, i);

		/* skip non config blocks */
		if (strncmp("auksd", block_name, 5) != 0) {
			continue;
		}
		auks_log
		    ("initializing engine from 'auksd' block of file %s",
		     l_conf_file);

		/* primary server conf value */
		pktb = config_GetKeyValueByName(config,i,"PrimaryKeytab");
		if (pktb == NULL)
			pktb = DEFAULT_AUKSD_PRIMARY_KEYTAB;

		/* secondary server conf value */
		sktb = config_GetKeyValueByName(config,i,"SecondaryKeytab");
		if (sktb == NULL)
			sktb = DEFAULT_AUKSD_SECONDARY_KEYTAB;

		/* cache dir value */
		cdir = config_GetKeyValueByName(config,i,"CacheDir");
		if (cdir == NULL)
			cdir = DEFAULT_AUKSD_CACHEDIR;

		/* acl file value */
		afile = config_GetKeyValueByName(config,i,"ACLFile");
		if (afile == NULL)
			afile = DEFAULT_AUKSD_ACLFILE;

		/* read log file value */
		lfile = config_GetKeyValueByName(config,i,"LogFile");
		if (lfile == NULL)
			lfile = DEFAULT_AUKSD_LOGFILE;

		/* read log level value */
		ll_str = config_GetKeyValueByName(config,i,"LogLevel");
		if (ll_str == NULL)
			ll = DEFAULT_AUKSD_LOGLEVEL;
		else
			ll = strtol(ll_str, NULL, 10);
		if (ll == LONG_MIN || ll == LONG_MAX)
			ll = DEFAULT_AUKSD_LOGLEVEL;

		/* read debug file value */
		dfile = config_GetKeyValueByName(config,i,"DebugFile");
		if (dfile == NULL)
			dfile = DEFAULT_AUKSD_DEBUGFILE;

		/* read debug level value */
		dl_str = config_GetKeyValueByName(config,i,"DebugLevel");
		if (dl_str == NULL)
			dl = DEFAULT_AUKSD_DEBUGLEVEL;
		else
			dl = strtol(dl_str, NULL, 10);
		if (dl == LONG_MIN || dl == LONG_MAX)
			dl = DEFAULT_AUKSD_DEBUGLEVEL;

		/* read threads nb value */
		tnb_str =
		    config_GetKeyValueByName(config,i,"Workers");
		if (tnb_str == NULL)
			tnb = DEFAULT_AUKSD_THREADS_NB;
		else
			tnb = strtol(tnb_str, NULL, 10);
		if (tnb == LONG_MIN || tnb == LONG_MAX)
			tnb = DEFAULT_AUKSD_THREADS_NB;

		/* read queue size */
		qs_str = config_GetKeyValueByName(config,i,"QueueSize");
		if (qs_str == NULL)
			qs = DEFAULT_AUKSD_QUEUE_SIZE;
		else
			qs = strtol(qs_str, NULL, 10);
		if (qs == LONG_MIN || qs == LONG_MAX)
			qs = DEFAULT_AUKSD_QUEUE_SIZE;

		/* read repository size */
		rs_str = config_GetKeyValueByName(config,i,"RepoSize");
		if (rs_str == NULL)
			rs = DEFAULT_AUKSD_REPO_SIZE;
		else
			rs = strtol(rs_str, NULL, 10);
		if (rs == LONG_MIN || rs == LONG_MAX)
			rs = DEFAULT_AUKSD_REPO_SIZE;

		/* clean delay */
		rd_str =
		    config_GetKeyValueByName(config,i,"CleanDelay");
		if (rd_str == NULL)
			rd = DEFAULT_AUKSD_CLEAN_DELAY;
		else
			rd = strtol(rd_str, NULL, 10);
		if (rd == LONG_MIN || rd == LONG_MAX)
			rd = DEFAULT_AUKSD_CLEAN_DELAY;

		/* Kerberos Replay cache mode */
		krc_str =
			config_GetKeyValueByName(config, i, "ReplayCache") ;
		if (krc_str == NULL)
			krc = DEFAULT_AUKS_REPLAY_CACHE ;
		else if ( strncasecmp(krc_str,"yes",4) ==0 )
			krc = 1 ;
		else
			krc = 0 ;

		valid_block_nb++;

	}			/* EOF for */

	if ( valid_block_nb == 2 )
		fstatus = AUKS_SUCCESS;

	if ( fstatus == AUKS_SUCCESS ) {

		/* init auksd engine */
		fstatus = auksd_engine_init(engine,
					    phost,padd, pport, pprinc, pktb,
					    shost,sadd, sport, sprinc, sktb,
					    cdir, afile, lfile, ll, dfile,
					    dl, tnb, qs, rs, rd,nat,krc);
		
		/* init ok, break */
		if (fstatus == 0) {
			auks_log("initialization succeed");
		} else
			auks_error("initialization failed");

	}

parse_exit:
	/* free config file */
	config_Free(config);
exit:
	return fstatus;
}
