/***************************************************************************\
 * slurm-spank-auks.c -  Prototype of an Auks Spank plugin for kerberos 
 * credential support
 * based on AUKS API
 *
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdint.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <signal.h>

#include <slurm/slurm.h>
#include <slurm/spank.h>

#include "auks/auks_error.h"
#include "auks/auks_api.h"

#define AUKS_HEADER "spank-auks: "

#define xerror(h,a...) slurm_error(AUKS_HEADER h,##a)
#define xinfo(h,a...) slurm_verbose(AUKS_HEADER h,##a)

#define AUKS_MODE_DISABLED  0
#define AUKS_MODE_ENABLED   1
#define AUKS_MODE_DONE      2

#define SPANK_AUKS_ENVVAR   "SLURM_SPANK_AUKS"

#ifndef BINDIR
#define BINDIR "/usr/bin"
#endif

/*
 * All spank plugins must define this macro for the SLURM plugin loader.
 */
SPANK_PLUGIN(auks, 1);

#define CREDCACHE_MAXLENGTH 128
static char auks_credcache[CREDCACHE_MAXLENGTH];

static char* auks_conf_file = NULL;

static int auks_mode = AUKS_MODE_DISABLED;

/* enable/disable acquired ticket access to next spank plugins in the stack */
static int auks_spankstack = 0;

static uid_t auks_minimum_uid = 0;

volatile pid_t renewer_pid;
volatile uint32_t exited_tasks=0;

static int _auks_opt_process (int val, const char *optarg, int remote);
struct spank_option spank_opts[] =
{
	{ "auks", "[yes|no|done]", 
	  "kerberos credential forwarding using Auks", 2, 0,
	  (spank_opt_cb_f) _auks_opt_process
	},
	SPANK_OPTIONS_TABLE_END
};
int _parse_plugstack_conf (spank_t sp, int ac, char *av[]);
int _spank_auks_get_current_mode(spank_t sp, int ac, char *av[]);


/* srun/sbatch : forward client credential to auks daemon */
int spank_auks_local_user_init (spank_t sp, int ac, char **av);

/* slurmstepd : get user credential from auks daemon */
int spank_auks_remote_init (spank_t sp, int ac, char *av[]);

/* slurmstepd : remove user localy stored credential */
int spank_auks_remote_exit (spank_t sp, int ac, char **av);


/*
 *
 * SLURM SPANK API SLURM SPANK API SLURM SPANK API SLURM SPANK API 
 *
 * SLURM SPANK API SLURM SPANK API SLURM SPANK API SLURM SPANK API 
 *
 */
int
slurm_spank_init (spank_t sp, int ac, char *av[])
{
	spank_option_register(sp,spank_opts);
	_parse_plugstack_conf(sp,ac,av);
	
	if (!spank_remote (sp))
		return 0;
	else
		return spank_auks_remote_init(sp,ac,av);
}

int
slurm_spank_init_post_opt (spank_t sp, int ac, char *av[])
{
	if ( spank_context() == S_CTX_ALLOCATOR )
		return spank_auks_local_user_init(sp,ac,av);
	else 
		return 0;
}

int
slurm_spank_local_user_init (spank_t sp, int ac, char **av)
{
	return spank_auks_local_user_init(sp,ac,av);
}

int
slurm_spank_task_exit (spank_t sp, int ac, char **av)
{
	uint32_t local_task_count;

	uid_t uid;
	gid_t gid;

	/* get local tasks count */
	if (spank_get_item (sp, S_JOB_LOCAL_TASK_COUNT,
			    &local_task_count) != ESPANK_SUCCESS) {
		xerror("failed to get local task count : %s",strerror(errno));
		return (-1);
	}

	/* get slurm job user uid */
	if (spank_get_item (sp, S_JOB_UID, &uid) != ESPANK_SUCCESS) {
		xerror("failed to get uid: %s", strerror(errno));
		return (-1);
	}
	if (spank_get_item (sp, S_JOB_GID, &gid) != ESPANK_SUCCESS) {
		xerror("failed to get gid: %s", strerror(errno));
		return (-1);
	}

	/* add this task to the count of exited tasks */
	exited_tasks += 1 ;
       
	/* signal renew process */
	if ( renewer_pid != 0 &&
	     renewer_pid != -1 ) {

		/* if all tasks exited, signal renewer process */
		if ( exited_tasks == local_task_count ) {

			xinfo("all tasks exited, killing credential renewer "
			     "(pid=%u)",renewer_pid);

			/* change to user uid/gid before the kill */
			if ( setegid(gid) ) {
				xerror("unable to switch to user gid : %s",
				      strerror(errno));
				return (-1);
			}
			if ( seteuid(uid) ) {				
				xerror("unable to switch to user uid : %s",
				      strerror(errno));
				setegid(getgid());
				return (-1);
			}
			
			/* kill the renewer process */
			kill(renewer_pid,SIGTERM);
			
			/* replace privileged uid/gid */
			seteuid(getuid());
			setegid(getgid());
			
		}
		
	}

	return 0;
}

int
slurm_spank_user_init (spank_t sp, int ac, char **av)
{
	int mode;

	/* get required auks mode */
	mode = _spank_auks_get_current_mode(sp,ac,av);
	switch(mode) {

	case AUKS_MODE_DISABLED:
		return 0;
		break;

	case AUKS_MODE_ENABLED:
	case AUKS_MODE_DONE:
		break;

	default:
		return -1;
		break;
	}

	renewer_pid = fork();
	if ( renewer_pid == -1 ) {
		xerror("unable to launch renewer process");
	}
	else if ( renewer_pid == 0 ) {
		char *argv[4];
		argv[0]= BINDIR "/auks" ;
		argv[1]="-R";argv[2]="loop";
		argv[3]=NULL;
		setenv("KRB5CCNAME",auks_credcache,1);
		execv(argv[0],argv);
		xerror("unable to exec credential renewer (%s)",argv[0]);
		exit(0);
	}
	else {
		xinfo("credential renewer launched (pid=%u)",renewer_pid);
	}

	return 0;
}

int
slurm_spank_exit (spank_t sp, int ac, char **av)
{
	if (!spank_remote (sp))
		return 0;
	else	
		return spank_auks_remote_exit(sp,ac,av);
}

/*
 *
 * AUKS SPECIFIC AUKS SPECIFIC AUKS SPECIFIC AUKS SPECIFIC AUKS SPECIFIC
 *
 * AUKS SPECIFIC AUKS SPECIFIC AUKS SPECIFIC AUKS SPECIFIC AUKS SPECIFIC
 *
 */
/* add client credential to auks */
int spank_auks_local_user_init (spank_t sp, int ac, char **av)
{
	int fstatus;
	auks_engine_t engine;
	
	int mode;
	
	/* get required auks mode */
	mode = _spank_auks_get_current_mode(sp,ac,av);
	switch(mode) {

	case AUKS_MODE_DONE:
		xinfo("cred forwarding already done");
		return 0;
		break;
		
	case AUKS_MODE_DISABLED:
	        return 0;
		break;
		
	case AUKS_MODE_ENABLED:
	        break;

	default:
		return -1;
		break;
	}

	/* load auks conf */
	fstatus = auks_api_init(&engine,auks_conf_file);
	if ( fstatus != AUKS_SUCCESS ) {
		xerror("API init failed : %s",auks_strerror(fstatus));
		return -1;
	}
	
	/* send credential to auks daemon */
	fstatus = auks_api_add_cred(&engine,NULL);
	if ( fstatus != AUKS_SUCCESS ) {
		xerror("cred forwarding failed : %s",auks_strerror(fstatus));
	}
	else {
		xinfo("cred forwarding succeed");
		fstatus = setenv("SLURM_SPANK_AUKS","done",0);
		if ( fstatus != 0 ) {
			xerror("unable to set SLURM_SPANK_AUKS to done");
		}
	}
	
	/* unload auks conf */
	auks_api_close(&engine);
			
	return fstatus;
}

/* get auks cred */
int
spank_auks_remote_init (spank_t sp, int ac, char *av[])
{
	int fstatus;
	auks_engine_t engine;
	
	static uint32_t jobid;
	uid_t uid;
	gid_t gid;
	
	mode_t omask;

	int mode;
	
	/* get required auks mode */
	mode = _spank_auks_get_current_mode(sp,ac,av);
	switch(mode) {

	case AUKS_MODE_DISABLED:
		xinfo("mode disabled");
		return 0;
		break;

	case AUKS_MODE_ENABLED:
	case AUKS_MODE_DONE:
		break;

	default:
		return -1;
		break;
	}

	/* set default auks cred cache length to 0 */
	auks_credcache[0]='\0';
	
	/* get slurm jobid */
	if (spank_get_item (sp, S_JOB_ID, &jobid) != ESPANK_SUCCESS) {
		xerror("failed to get jobid: %s",strerror(errno));
		return (-1);
	}
	
	/* get slurm job user uid & gid */
	if (spank_get_item (sp, S_JOB_UID, &uid) != ESPANK_SUCCESS) {
		xerror("failed to get uid: %s", strerror(errno));
		return (-1);
	}
	if (spank_get_item (sp, S_JOB_GID, &gid) != ESPANK_SUCCESS) {
		xerror("failed to get gid: %s", strerror(errno));
		return (-1);
	}
	
	/* build credential cache name */
	fstatus = snprintf(auks_credcache,CREDCACHE_MAXLENGTH,
			   "/tmp/krb5cc_%u_%u_XXXXXX",
			   uid,jobid);
	if ( fstatus >= CREDCACHE_MAXLENGTH ||
	     fstatus < 0 ) {
		xerror("unable to build auks credcache name");
		goto exit;
	}
	
	/* build unique credential cache */
	omask = umask(S_IRUSR | S_IWUSR);
	fstatus = mkstemp(auks_credcache);
	umask(omask);
	if ( fstatus == -1 ) {
		xerror("unable to create a unique auks credcache");
		goto exit;
	}
	else
		close(fstatus);
	
	/* initialize auks API */
	fstatus = auks_api_init(&engine,auks_conf_file);
	if ( fstatus != AUKS_SUCCESS ) {
		xerror("API init failed : %s",auks_strerror(fstatus));
		goto exit;
	}
	
	/* get user credential */
	fstatus = auks_api_get_cred(&engine,uid,auks_credcache);
	if ( fstatus != AUKS_SUCCESS ) {
		xerror("unable to get user %u cred : %s",uid,
		      auks_strerror(fstatus));
		unlink(auks_credcache);
		auks_credcache[0]='\0';
		goto unload;
	}
	xinfo("user '%u' cred stored in %s",uid,auks_credcache);
	
	/* change file owner */
	fstatus = chown(auks_credcache,uid,gid);
	if ( fstatus != 0 ) {
		xerror("unable to change cred %s owner : %s",
		      auks_credcache,strerror(errno));
		goto unload;
	}
	
	/* set cred cache name in user env */
	fstatus = spank_setenv(sp,"KRB5CCNAME",auks_credcache,1);
	if ( fstatus != 0 ) {
		xerror("unable to set KRB5CCNAME env var");
	}

	/* if required by the configuration, also put the cred cache name */
	/* in the spank plugstack environment */
	if ( auks_spankstack ) {
		setenv("KRB5CCNAME",auks_credcache,1);
	}

unload:
	/* unload auks conf */
	auks_api_close(&engine);
	
exit:    
	return (fstatus);
}

/* remove cred at end of step */
int
spank_auks_remote_exit (spank_t sp, int ac, char **av)
{
	int fstatus;

	uid_t uid;
	gid_t gid;

	/* free auks conf file if needed */
	if ( auks_conf_file != NULL )
		free(auks_conf_file);

	/* now only process in remote mode */
	if (!spank_remote (sp))
		return (0);
	
	/* only process if a cred file was defined in a previous call */
	if ( strnlen(auks_credcache,CREDCACHE_MAXLENGTH) == 0 )
		return 0;
	
	/* get slurm job user uid & gid */
	if (spank_get_item (sp, S_JOB_UID, &uid) != ESPANK_SUCCESS) {
		xerror("failed to get uid: %s", strerror(errno));
		return (-1);
	}
	if (spank_get_item (sp, S_JOB_GID, &gid) != ESPANK_SUCCESS) {
		xerror("failed to get gid: %s", strerror(errno));
		return (-1);
	}

	/* change to user gid before removing cred */
	if ( setegid(gid) ) {
		xerror("unable to switch to user gid : %s",
		      strerror(errno));
		return (-1);
	}

	/* change to user uid and gid before removing cred */
	if ( seteuid(uid) ) {
		xerror("unable to switch to user uid : %s",
		      strerror(errno));
		setegid(getgid());
		return (-1);
	}

	/* remove credential cache */
	fstatus = unlink(auks_credcache);
	if ( fstatus != 0 ) {
		xerror("unable to remove user '%u' cred cache %s : %s",
		      uid,auks_credcache,strerror(errno));
	}
	else
		xinfo("user '%u' cred cache %s removed",uid,auks_credcache);
	
	/* replace privileged uid/gid */
	seteuid(getuid());
	setegid(getgid());

	return 0;
}


/* return current auks mode */
int
_spank_auks_get_current_mode(spank_t sp, int ac, char *av[])
{
	int fstatus;
	char spank_auks_env[5];

	char* envval=NULL;
	uid_t uid;
	
	/* check if conf allow the user to do auks stuff */
	if ( auks_minimum_uid > 0 ) {
		
		/* get slurm job user uid */
		if (spank_remote (sp)) {
			if (spank_get_item (sp, S_JOB_UID, &uid) 
			    != ESPANK_SUCCESS) {
				xerror("failed to get uid: %s",
				       strerror(errno));
				return AUKS_MODE_DISABLED;
			}
		}
		else {
			uid = geteuid();
		}

		if ( uid < auks_minimum_uid ) {
			xinfo("user '%u' not allowed to do auks stuff by conf");
			return AUKS_MODE_DISABLED;
		}
	}

	if (spank_remote (sp)) {
		fstatus = spank_getenv(sp,SPANK_AUKS_ENVVAR,
				       spank_auks_env,5);
		if ( fstatus == 0 ) {
			spank_auks_env[4]='\0';
			envval=spank_auks_env;
		}
	}
	else {
		envval = getenv(SPANK_AUKS_ENVVAR);
	}
		
	/* if env variable is set, use it */
	if ( envval != NULL ) {
		/* check env var value (can be yes|no|done)*/
		if ( strncmp(envval,"yes",4) == 0 ) {
			return AUKS_MODE_ENABLED ;
		}
		else if ( strncmp(envval,"done",4) == 0 ) {
			return AUKS_MODE_DONE ;
		}
		else
			return AUKS_MODE_DISABLED ;
	}
	else {
		/* no env variable defined, return command line */
		/* or configuration file auks flag */
		return auks_mode;
	}
	
}

/* parse command line option */
static int
_auks_opt_process (int val, const char *optarg, int remote)
{
        if ( optarg == NULL )
	        return (1);

	if (strncmp ("no", optarg, 2) == 0) {
	        auks_mode = AUKS_MODE_DISABLED ;
		xdebug("disabled on user request",optarg);
	}
	else if (strncmp ("yes", optarg, 3) == 0) {
	        auks_mode = AUKS_MODE_ENABLED ;
		xdebug("enabled on user request",optarg);
	}
	else if (strncmp ("done", optarg, 4) != 0) {
		xerror ("bad parameter %s", optarg);
		return (-1);
	}
	else {
	        auks_mode = AUKS_MODE_DONE ;
		setenv("SLURM_SPANK_AUKS","done",0);
		xdebug("enabled on user request (in done mode)",optarg);
	}

	return (0);
}

/* parse plugstack conf options */
int
_parse_plugstack_conf (spank_t sp, int ac, char *av[])
{
	int i;
	char* elt;
	
	for (i = 0; i < ac; i++) {
		elt = av[i];
		if ( strncmp(elt,"conf=",5) == 0 ) {
			auks_conf_file=strdup(elt+5);	
		}
		else if (strncmp ("default=enabled", av[i], 15) == 0) {
		        auks_mode = AUKS_MODE_ENABLED;
		}
		else if (strncmp ("default=disabled", av[i], 16) == 0) {
		        auks_mode = AUKS_MODE_DISABLED;
		}
		else if (strncmp ("spankstackcred=yes", av[i], 18) == 0) {
		        auks_spankstack = 1;
		}
		else if (strncmp ("minimum_uid=", av[i], 12) == 0) {
		        auks_minimum_uid = (uid_t) strtol(av[i]+12,NULL,10);
			if ( auks_minimum_uid == LONG_MIN ||
			     auks_minimum_uid == LONG_MAX ) {
				xerror ("ignoring bad value %s for parameter ",
					"minimum_uid",av[i]+12);
			}
		}
	}
	
	return (0);
}
