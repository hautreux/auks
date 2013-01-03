/***************************************************************************\
 * auks_acl.c - AUKS ACL implementation based on POSIX regexp
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

/* getaddrinfo / inet_ntoa */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* regular expression */
#include <regex.h>

/* configuration file processing */
#include "confparse/config_parsing.h"
extern char extern_errormsg[1024];

#define AUKS_LOG_HEADER "auks_acl: "
#define AUKS_LOG_BASE_LEVEL 4

#include "auks/auks_error.h"
#include "auks/auks_acl.h"
#include "auks/auks_log.h"

/* private functions declararions */
int
_auks_acl_rule_init(auks_acl_rule_t * p_rule, char *principal, char *host,
		   enum AUKS_ACL_ROLE role);

int
_auks_acl_rule_check_consistency(auks_acl_rule_t * p_rule);

int
_auks_acl_rule_free_contents(auks_acl_rule_t * p_rule);

int
_auks_acl_rule_check_principal(auks_acl_rule_t * p_rule,char *principal);

int
_auks_acl_rule_check_host(auks_acl_rule_t * p_rule,char *host);


/* public functions implementations */
int
auks_acl_init(auks_acl_t * p_acl, int max_rules_nb)
{
	int fstatus = AUKS_ERROR ;

	p_acl->rules_array =
	    (auks_acl_rule_t *) malloc(sizeof(auks_acl_rule_t) *
				       max_rules_nb);
	if (p_acl->rules_array) {
		p_acl->rules_nb = 0;
		p_acl->rules_nb_max = max_rules_nb;
		fstatus = AUKS_SUCCESS;
	} else {
		auks_error("unable to allocate memory for rules array");
		fstatus = AUKS_ERROR_ACL_INIT;
	}

	return fstatus;
}

int
auks_acl_free_contents(auks_acl_t * p_acl)
{
	int fstatus = AUKS_ERROR;

	int i;

	for (i = 0; i < p_acl->rules_nb; i++)
		_auks_acl_rule_free_contents(p_acl->rules_array + i);
	free(p_acl->rules_array);
	p_acl->rules_nb = 0;
	p_acl->rules_nb_max = 0;

	fstatus = AUKS_SUCCESS;

	return fstatus;
}

int
auks_acl_init_from_config_file(auks_acl_t * p_acl, char *acl_file)
{
	int fstatus = AUKS_ERROR;

	config_file_t config;
	int block_nb;

	char *principal;
	char *host;

	char *role_string;
	enum AUKS_ACL_ROLE role;

	int i;

	/* conf parsing */
	config = config_ParseFile(acl_file);
	if (!config) {
		auks_error("unable to parse configuration file %s : %s",
			   acl_file, extern_errormsg);
		fstatus = AUKS_ERROR_ACL_PARSING;
		goto exit;
	}
	auks_log("configuration file (%s) successfully parsed", acl_file);

	/* block nb */
	block_nb = config_GetNbBlocks(config);
	if (block_nb <= 0) {
		auks_error("unable to get configuration blocks nb from "
			   "config file %s : %s", acl_file, extern_errormsg);
		fstatus = AUKS_ERROR_ACL_FILE_IS_EMPTY;
		goto parse_exit;
	}
	auks_log2("configuration blocks nb (%d) successfully extracted",
		 block_nb);

	/* acl init */
	if (auks_acl_init(p_acl, block_nb) != 0) {
		auks_error("unable to init Auks ACL structure");
		fstatus = AUKS_ERROR_ACL_INIT;
		goto parse_exit;
	}
	auks_log2("Auks ACL structure successfully initialized");
	
	/* block loop */
	fstatus = 0;
	for (i = 0; i < block_nb; i++) {
		char *block_name;
		block_name = config_GetBlockName(config, i);
		
		/* keep only rule block */
		if (strncmp("rule", block_name, 7) != 0)
			continue;

		role_string = config_GetKeyValueByName(config, i, "role");
		principal =
		    config_GetKeyValueByName(config, i, "principal");
		host = config_GetKeyValueByName(config, i, "host");
		if (role_string == NULL) {
			auks_error("no role defined in rule[%d] of %s", i,
			      acl_file);
			continue;
		}
		
		if (strncmp("user", role_string, 5) == 0) {
			role = AUKS_ACL_ROLE_USER;
		} else if (strncmp("admin", role_string, 6) == 0) {
			role = AUKS_ACL_ROLE_ADMIN;
		} else if (strncmp("guest", role_string, 5) == 0) {
			role = AUKS_ACL_ROLE_GUEST;
		} else {
			auks_error("invalid role for rule[%d]", i,
			      acl_file, extern_errormsg);
			fstatus++;
			continue;
		}

		if (auks_acl_add_rule(p_acl, principal, host, role)) {
			auks_error("unable to add rule[%d] to auks_acl", i);
			fstatus++;
		} else {
			auks_log("rule[%d] '%s:%s => %s' successfully add",
				 i, principal, host, role_string);
		}

	}			/* EOF block loop */

	/* clean acl if errors occured during creation */
	if (fstatus) {
		auks_acl_free_contents(p_acl);
		fstatus = AUKS_ERROR_ACL_FILE_IS_INVALID;
	}

parse_exit:
	/* free config file */
	config_Free(config);
exit:
	return fstatus;
}

int
auks_acl_add_rule(auks_acl_t * p_acl, char *principal, char *host,
		  enum AUKS_ACL_ROLE role)
{
	int fstatus = AUKS_ERROR;

	/* principal/host validity check */
	if (principal == NULL || host == NULL) {
		fstatus = AUKS_ERROR;
		goto exit;
	}

	/* available rule slot check */
	if (p_acl->rules_nb >= p_acl->rules_nb_max) {
		auks_error("no more free rule slot available in this ACL");
		fstatus = AUKS_ERROR_ACL_IS_FULL;
		goto exit;
	}

	/* next available rule init with input values */
	if (0 != _auks_acl_rule_init(p_acl->rules_array + p_acl->rules_nb,
				    principal, host, role)) {
		auks_error("unable to init rule[%d]", p_acl->rules_nb);
		fstatus = AUKS_ERROR_ACL_RULE_IS_INVALID;
	} else {
		p_acl->rules_nb++;
		fstatus = AUKS_SUCCESS;
	}

exit:
	return fstatus;
}

int
auks_acl_get_role(auks_acl_t * p_acl, char *principal, char *host,
		  enum AUKS_ACL_ROLE *role)
{
	int fstatus;

	int i;
	auks_acl_rule_t *p_rule;
	char *role_string;

	/* default role is unknown */
	*role = AUKS_ACL_ROLE_UNKNOWN;
	fstatus = AUKS_SUCCESS;

	if (p_acl->rules_nb == 0) {
		auks_log("current ACL is empty");
		goto exit;
	}

	for (i = 0; i < p_acl->rules_nb; i++) {

		p_rule = p_acl->rules_array + i;

		if (_auks_acl_rule_check_principal(p_rule, principal)) {
			auks_log("rule[%d] principal check failed : rule is %s,"
				 " request is %s", i, p_rule->principal,
				 principal);
			continue;
		}

		if (_auks_acl_rule_check_host(p_rule, host)) {
			auks_log("rule[%d] host check failed : rule is %s, "
				 "request is %s", i, p_rule->host, host);
			continue;
		}
		
		*role = p_rule->role;

		if (*role == AUKS_ACL_ROLE_GUEST) {
			role_string = "guest";
		} else if (*role == AUKS_ACL_ROLE_USER) {
			role_string = "user";
		} else if (*role == AUKS_ACL_ROLE_ADMIN) {
			role_string = "admin";
		} else {
			role_string = "unknown";
		}

		auks_log("rule[%d] matches, associated role is %d (%s)",
			 i, p_rule->role, role_string);
		break;

	}

exit:
	return fstatus;
}


/* private functions implementations */
int
_auks_acl_rule_init(auks_acl_rule_t * p_rule, char *principal, char *host,
		   enum AUKS_ACL_ROLE role)
{
	int fstatus = AUKS_ERROR;

	if (principal != NULL && host != NULL) {
		p_rule->principal = strdup(principal);
		p_rule->host = strdup(host);
		p_rule->role = role;
		fstatus = _auks_acl_rule_check_consistency(p_rule);
	}

	return fstatus;
}

int
_auks_acl_rule_check_consistency(auks_acl_rule_t * p_rule)
{
	int fstatus = AUKS_ERROR_ACL_RULE_IS_INVALID;

	if (p_rule->principal != NULL && p_rule->host != NULL)
		fstatus = AUKS_SUCCESS;

	return fstatus;
}

int
_auks_acl_rule_free_contents(auks_acl_rule_t * p_rule)
{
	int fstatus = AUKS_SUCCESS;

	p_rule->role = AUKS_ACL_ROLE_UNKNOWN;

	if (p_rule->principal != NULL) {
		free(p_rule->principal);
		p_rule->principal = NULL;
	}

	if (p_rule->host != NULL) {
		free(p_rule->host);
		p_rule->host = NULL;
	}

	return fstatus;
}

int
_auks_acl_rule_check_principal(auks_acl_rule_t * p_rule,char *principal)
{
	int fstatus = AUKS_ERROR;

	regex_t regex;

	if (strncmp(p_rule->principal, "*", 2) == 0) {
		fstatus = AUKS_SUCCESS;
	} else {
		if (regcomp(&regex, p_rule->principal, REG_EXTENDED) == 0) {

			if (regexec(&regex, principal, 0, NULL, 0) == 0) {
				auks_log2("%s matches rule regexp '%s'",
					  principal, p_rule->principal);
				fstatus = AUKS_SUCCESS;
			} else {
				auks_log2
				    ("%s doesn't match rule regexp '%s'",
				     principal, p_rule->principal);
			}
			regfree(&regex);
		} else {
			auks_error("unable to init rule regexp '%s'",
			      p_rule->principal);
		}
	}

	return fstatus;
}

int
_auks_acl_rule_check_host(auks_acl_rule_t * p_rule,char *host)
{
	int fstatus = AUKS_ERROR;

	struct addrinfo *aitop;
	struct addrinfo hints;
	struct addrinfo *ai;
	struct sockaddr_in addr;

	/* all nodes match */
	if (strncmp(p_rule->host, "*", 2) == 0) {
		auks_log2("%s matches rule host %s", host, p_rule->host);
		fstatus = AUKS_SUCCESS;
		goto exit;
	}

	/* node names match directly */
	if (strncmp(host, p_rule->host, strlen(host) + 1) == 0) {
		auks_log2("%s matches rule host %s", host, p_rule->host);
		fstatus = AUKS_SUCCESS;
	}

	/* check matching DNS entries */
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_CANONNAME;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(p_rule->host, "", &hints, &aitop) == 0) {
		for (ai = aitop; ai; ai = ai->ai_next) {
			char * rule_host;
			memcpy(&addr, ai->ai_addr, ai->ai_addrlen);
			rule_host = inet_ntoa((struct in_addr) addr.sin_addr);
			if (strncmp(host, rule_host, strlen(host) + 1) ==
			    0) {
				fstatus = AUKS_SUCCESS;
				auks_log2("%s matches rule host %s(%s)",
					 host, p_rule->host, rule_host);
				break;
			}
		}
		freeaddrinfo(aitop);
	} else {
		auks_error("unable to get '%s' addresses info", p_rule->host);
	}

exit:
	return fstatus;
}
/**/
