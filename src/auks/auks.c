/***************************************************************************\
 * auks.c - user/admin interface to manage AUKS credentials 
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

#include <time.h>

#include "auks/auks_error.h"
#include "auks/auks_api.h"
#include "xternal/xlogger.h"

#define PING_REQUEST    1
#define ADD_REQUEST     2
#define GET_REQUEST     3
#define REMOVE_REQUEST  5
#define DUMP_REQUEST    6
#define RENEW_REQUEST   7

#define RENEW_MODE_ONCE             1
#define RENEW_MODE_UNTIL_REMOVAL    2
#define RENEW_MODE_UNTIL_EXPIRATION 3


int
main(int argc,char** argv)
{

	int fstatus = -1 ;

	int action=0;
	char* ccache=NULL;
	uid_t requested_uid;

	int debug_level=0;
	int verbose_level=0;
	char* conf_file_string;

	/* options processing variables */
	char* progname;
	char* optstring="dvhf:H:pagrDC:u:R:";
	char* short_options_desc="\nUsage : %s [-h] [-dv] [-f conffile] \
[-C ccache] [-p|a|g|r|D] [-R once|loop] [-u uid] \n\n";
	char* addon_options_desc="\
\t-h\t\tshow this message\n\
\t-d\t\tincrease debug level\n\
\t-v\t\tincrease verbose level\n\
\t-f conffile\tConfiguration file\n\
\t-p\t\tping request (default)\n\
\t-a\t\tadd request\n\
\t-g\t\tget request\n\
\t-D\t\tdump request\n\
\t-r\t\tremove request\n\
\t-R mode\t\trenew credential according to specified mode\n\
\t-C ccache\tConfiguration file\n\
\t-u uid\t\tuid of requested cred owner (get request only)\n\n";

	int  option;
  
	auks_engine_t engine;

	auks_cred_t* creds;
	int creds_nb;

	int renew_mode;

	/* set default requested uid */
	requested_uid=geteuid();

	/* get current program name */
	progname=rindex(argv[0],'/');
	if(progname==NULL)
		progname=argv[0];
	else
		progname++;

	conf_file_string=NULL;

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
		case 'C' :
			ccache=strdup(optarg);
			if(ccache==NULL){
				fprintf(stderr,"memory allocation error!");
				return 1;
			}
			break;
		case 'p' :
			action=PING_REQUEST;
			break;
		case 'a' :
			action=ADD_REQUEST;
			break;
		case 'g' :
			action=GET_REQUEST;
			break;
		case 'r' :
			action=REMOVE_REQUEST;
			break;
		case 'R' :
			action=RENEW_REQUEST;
			if(strncmp(optarg,"once",5)==0)
				renew_mode = AUKS_API_RENEW_ONCE ;
			else if(strncmp(optarg,"loop",5)==0)
				renew_mode = AUKS_API_RENEW_LOOP ;
			else {
				fprintf(stdout,short_options_desc,progname);
				fprintf(stdout,"%s\n",addon_options_desc);
				exit(1);
			}
			break;
		case 'D' :
			action=DUMP_REQUEST;
			break;
		case 'u' :
			requested_uid=(uid_t)atoi(optarg);
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

	/* load configuration */
	fstatus = auks_api_init(&engine,conf_file_string);
	if ( fstatus != AUKS_SUCCESS ) {
		fprintf(stderr,"Auks API init failed : %s\n",
			auks_strerror(fstatus));
		goto exit;
	}

	if ( verbose_level > 0 )
		auks_api_set_logfile(&engine,"/dev/stdout");
	
	switch(action){
		
	case ADD_REQUEST :
		fstatus = auks_api_add_cred(&engine,
					    ccache);
		break;
		
	case GET_REQUEST :
		fstatus = auks_api_get_cred(&engine,
					    requested_uid,
					    ccache);
		break;
		
	case DUMP_REQUEST :
		fstatus = auks_api_dump(&engine,&creds,&creds_nb);
		break;

	case REMOVE_REQUEST :
		fstatus = auks_api_remove_cred(&engine,
					       requested_uid);
		break;
		
	case RENEW_REQUEST :

		fstatus = auks_api_renew_cred(&engine,ccache,renew_mode);

		break;

	case PING_REQUEST :
	default :
		fstatus = auks_api_ping(&engine);
		break;

	}

	if ( fstatus != AUKS_SUCCESS ) {
		fprintf(stderr,"Auks API request failed : %s\n",
			auks_strerror(fstatus));
	}
	else {
		fprintf(stdout,"Auks API request succeed\n");
	}

	auks_api_close(&engine);

exit:
	if ( conf_file_string != NULL )
		free(conf_file_string);

	return fstatus;
}
