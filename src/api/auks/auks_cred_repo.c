/***************************************************************************\
 * auks_cred.c - AUKS kerberos credential repository implementation
 * based on external xlibrary implementation
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

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include <string.h>
#include <errno.h>
extern int errno;

#include <time.h>

#include <pthread.h>
#include <search.h>

/* directory lookup */
#include <dirent.h>
#include <sys/types.h>
#include <fnmatch.h>

#define AUKS_LOG_HEADER "auks_repo: "
#define AUKS_LOG_BASE_LEVEL 4

#include "auks/auks_error.h"
#include "auks/auks_cred.h"
#include "auks/auks_cred_repo.h"
#include "auks/auks_krb5_cred.h"
#include "auks/auks_log.h"

#define STR_ERROR_SIZE 128
#define UID_STR_LENGTH 32

#define DUMP_ERROR(e,s,S) if(strerror_r(e,s,S)) { s[0]='-';s[1]='\0';}

/* free cred dynamic content */
void _release_cred(void *p);

int auks_cred_repo_update_index_nolock(auks_cred_repo_t * cr);

int
auks_cred_repo_auks_credfile(auks_cred_repo_t * cr,uid_t uid,
			     char* filename,size_t max_length)
{
	int fstatus;

	fstatus = snprintf(filename, max_length,
			   AUKS_CRED_CACHE_FILE_PATTERN,cr->cachedir, uid);
	if (fstatus >= max_length
	    || fstatus < 0) {
		auks_log2("unable to build '%d' auks cred cache "
			  "filename",uid);
		fstatus = AUKS_ERROR_CRED_REPO_CCACHE_BUILD ;
	}
	else
		fstatus = AUKS_SUCCESS ;

	return fstatus;
}

int
auks_cred_repo_renewer_credfile(auks_cred_repo_t * cr,int id,
				char* filename,size_t max_length)
{
	int fstatus;
	
	fstatus = snprintf(filename, max_length,
			   "%s/krb5cc_renewer_%d",cr->cachedir,id);
	if (fstatus >= max_length
	    || fstatus < 0) {
		auks_log2("unable to build renewer[%d] cred cache "
			  "filename",id);
		fstatus = AUKS_ERROR_CRED_REPO_CCACHE_BUILD ;
	}
	else
		fstatus = AUKS_SUCCESS ;
	
	return fstatus;
}

int
auks_cred_repo_init(auks_cred_repo_t * cr, char *cachedir,
		    unsigned int default_length)
{
	int fstatus = AUKS_ERROR;
	
	size_t item_size = sizeof(auks_cred_t);
	
	cr->cachedir = NULL;
	cr->read_only = 1;
	
	/* cache directory validity check */
	if (cachedir == NULL) {
		auks_log2("init : invalid cache directory");
		fstatus = AUKS_ERROR_CRED_REPO_CACHEDIR_IS_NULL;
		goto exit;
	}

	/* cache directory initialization */
	cr->cachedir = strdup(cachedir);
	if (cr->cachedir == NULL) {
		auks_log2("init : cache directory name memory "
			   "allocation failed");
		fstatus = AUKS_ERROR_CRED_REPO_CACHEDIR_INIT;
		goto exit;
	}

	/* mutex initialization */
	fstatus = pthread_mutex_init(&(cr->mutex), NULL);
	if (fstatus) {
		auks_log2("init : mutex initialization failed");
		fstatus = AUKS_ERROR_CRED_REPO_MUTEX_INIT;
		goto dir_exit;
	}

	/* condition initialization */
	fstatus = pthread_cond_init(&(cr->condition),NULL);
	if (fstatus) {
		auks_log2("init : condition initialization failed");
		fstatus = AUKS_ERROR_CRED_REPO_CONDITION_INIT;
		goto mutex_exit;
	}

	/* xlibrary initialization */
	fstatus = xlibrary_init(&(cr->library),default_length,
				item_size,_release_cred);
	if (fstatus) {
		auks_log2("init : library initialization failed "
			   "(&d items of %d bytes length)",
			   item_size,default_length);
		fstatus = AUKS_ERROR_LIBRARY_INIT;
	} else {
		/* load cache */
		auks_cred_repo_load_cache(cr);
		cr->read_only = 0;

		/* set success */
		fstatus = AUKS_SUCCESS;
	}

	/* an error occured - destroy condition */
	if (fstatus) {
		pthread_cond_destroy(&(cr->condition));
	}

mutex_exit:
	if (fstatus) {
		pthread_mutex_destroy(&(cr->mutex));
	}

dir_exit:
	if (fstatus) {
		/* an error occured - destroy cache dir */
		free(cr->cachedir);
		cr->cachedir = NULL;
	}

exit:
	return fstatus;
}

int
auks_cred_repo_free_contents(auks_cred_repo_t * cr)
{
	int fstatus;

	/* destroy the library */
	xlibrary_free_contents(&(cr->library));

	/* condition destruction */
	pthread_cond_destroy(&(cr->condition));

	/* mutex destruction */
	pthread_mutex_destroy(&(cr->mutex));

	/* free cache directory */
	if (cr->cachedir != NULL) {
		free(cr->cachedir);
		cr->cachedir = NULL;
	}
	
	fstatus = AUKS_SUCCESS;
	
	return fstatus;
}

int
auks_cred_repo_lock(auks_cred_repo_t * cr)
{
	int fstatus;
	
	fstatus = pthread_mutex_lock(&(cr->mutex));
	if (fstatus) {
		auks_log2("lock failed : %s",auks_strerror(fstatus));
		fstatus = AUKS_ERROR_CRED_REPO_MUTEX_LOCK;
	} else {
		auks_log3("locked");
		fstatus = AUKS_SUCCESS;
	}
	
	return fstatus;
}

int
auks_cred_repo_unlock(auks_cred_repo_t * cr)
{
	int fstatus;

	fstatus = pthread_mutex_unlock(&(cr->mutex));
	if (fstatus) {
		auks_log2("unlock failed : %s",auks_strerror(fstatus));
		fstatus = AUKS_ERROR_CRED_REPO_MUTEX_LOCK;
	} else {
		auks_log3("unlocked");
		fstatus = AUKS_SUCCESS;
	}
	
	return fstatus;
}

int
auks_cred_repo_add(auks_cred_repo_t * cr, auks_cred_t * cred)
{
	int fstatus;

	/* lock repo */
	fstatus = pthread_mutex_lock(&(cr->mutex));
	if (fstatus) {
		auks_log2("add : unable to lock repo");
		fstatus = AUKS_ERROR_CRED_REPO_MUTEX_LOCK;
	} else {
		/* push unlock method ( used if externaly canceled ) */
		pthread_cleanup_push((void (*)(void*))pthread_mutex_unlock,
				     (void *) (&(cr->mutex)));
		
		/* call no lock method */
		fstatus = auks_cred_repo_add_nolock(cr, cred);
		
		/* pop unlock method */
		pthread_cleanup_pop(1);
	}

	return fstatus;
}

int
auks_cred_repo_get(auks_cred_repo_t * cr, uid_t uid, auks_cred_t * cred)
{
	int fstatus;

	/* lock repo */
	fstatus = pthread_mutex_lock(&(cr->mutex));
	if (fstatus) {
		auks_log2("get : unable to get '%d' auks cred :"
			   " unable to lock repo");
		fstatus = AUKS_ERROR_CRED_REPO_MUTEX_LOCK;
	} else {
		/* push unlock method ( used if externaly canceled ) */
		pthread_cleanup_push((void (*)(void*))pthread_mutex_unlock,
				     (void *) (&(cr->mutex)));
		
		/* call no lock method */
		fstatus = auks_cred_repo_get_nolock(cr, uid, cred);
		
		/* pop unlock method */
		pthread_cleanup_pop(1);
	}
	
	return fstatus;
}

int
auks_cred_repo_remove(auks_cred_repo_t * cr, uid_t uid)
{
	int fstatus;

	/* lock repo */
	fstatus = pthread_mutex_lock(&(cr->mutex));
	if (fstatus) {
		auks_log2("remove : unable to remove '%d' auks cred :"
			   " unable to lock repo");
		fstatus = AUKS_ERROR_CRED_REPO_MUTEX_LOCK;
	} else {
		/* push unlock method ( used if externaly canceled ) */
		pthread_cleanup_push((void (*)(void*))pthread_mutex_unlock,
				     (void *) (&(cr->mutex)));
		
		/* call nolock method */
		fstatus = auks_cred_repo_remove_nolock(cr, uid);
		
		/* pop unlock method */
		pthread_cleanup_pop(1);

	}

	return fstatus;
}

int
auks_cred_repo_pack(auks_cred_repo_t * cr,auks_message_t* msg)
{
	int fstatus;

	/* lock repository */
	fstatus = auks_cred_repo_lock(cr);
	if ( fstatus != AUKS_SUCCESS )
		return fstatus;

	fstatus = auks_cred_repo_pack_nolock(cr,msg);
	
	/* unlock repository but propagate pack error 
	* if any */
	if (fstatus == AUKS_SUCCESS)
	  fstatus = auks_cred_repo_unlock(cr);
	else
	  auks_cred_repo_unlock(cr);
	
	return fstatus;
}

int
auks_cred_repo_clean(auks_cred_repo_t * cr,int* pnb)
{
	int fstatus;

	/* lock repository */
	fstatus = auks_cred_repo_lock(cr);
	if ( fstatus != AUKS_SUCCESS )
		return fstatus;

	fstatus = auks_cred_repo_clean_nolock(cr,pnb);
	
	/* unlock repository but propagate clean error 
	 * if any */
	if (fstatus == AUKS_SUCCESS)
	  fstatus = auks_cred_repo_unlock(cr);
	else
	  auks_cred_repo_unlock(cr);

	return fstatus;
}

int
auks_cred_repo_add_nolock(auks_cred_repo_t * cr, auks_cred_t * cred)
{
	int fstatus;

	uid_t uid;
	char uid_str[UID_STR_LENGTH];

	char filename[AUKS_CRED_FILE_MAX_LENGTH + 1];

	auks_cred_t credential;

	/* get cred uid */
	uid = cred->info.uid;

	/* we first try to get cred */
	fstatus = auks_cred_repo_get_nolock(cr,cred->info.uid, &credential);
	if (fstatus != 0)
		goto add_stage;

	/* replace cred only if it is a better one */
	/* or at least equivalent (required by renewer stuff) */
	if (cred->info.renew_till > credential.info.renew_till ||
	    (cred->info.endtime >= credential.info.endtime &&
	     cred->info.renew_till == credential.info.renew_till) ) {
		fstatus = auks_cred_repo_remove_nolock(cr,cred->info.uid);
		if (fstatus) {
			auks_log2("add : unable to delete '%d' old auks cred "
				   "from repo",uid);
			/* hoping that tsearch will really replace the cred */
			fstatus = AUKS_SUCCESS;
		} else {
			auks_log3("add : '%d' old auks cred deleted from repo",
				  uid);
			fstatus = AUKS_SUCCESS;
		}
	} else {
		auks_log3("add : '%d' old auks cred is a better one : "
			  "skipping this addition",uid);
		fstatus = AUKS_SUCCESS;
		goto exit;
	}

add_stage:
	/* set reference value */
	if ( snprintf(uid_str, UID_STR_LENGTH, "%u", uid) >= UID_STR_LENGTH ) {
		auks_log2("add : unable to build uid='%u' str representation",
			  uid);
		fstatus = AUKS_ERROR_LIBRARY_UID_TO_STR;
		goto exit;
	}

	/* add cred to library */
	fstatus = xlibrary_add_item(&(cr->library), uid_str,
				    cred, sizeof(auks_cred_t));
	if (fstatus) {
		auks_log2("add : unable to add '%u' cred to the library",uid);
		fstatus = AUKS_ERROR_LIBRARY_ADD;
		goto exit;
	}
	auks_log3("add : '%d' auks cred successfully added to the library",uid);

	/* if not in read-only mode, try to add it to the cache directory */
	if (cr->read_only) {
		auks_log3("add : read-only mode, '%d' auks cred cache will "
			  "not be updated");
		goto exit;
	}

	fstatus = auks_cred_repo_auks_credfile(cr,cred->info.uid,filename,
					       AUKS_CRED_FILE_MAX_LENGTH);
	if ( fstatus != AUKS_SUCCESS )
		goto exit;
	auks_log3("add : '%d' auks cred cache filename is '%s'",uid, filename);
	
	fstatus = auks_krb5_cred_store(filename, cred->data,cred->length);
	if (fstatus) {
		auks_log2("add : unable to store '%d' auks cred "
			  "in cache '%s'",uid, filename);
	} else {
		auks_log3("add : '%d' auks cred successfully stored "
			  "in cache '%s'",uid, filename);
		fstatus = AUKS_SUCCESS;
	}

exit:
	return fstatus;
}

int
auks_cred_repo_get_nolock(auks_cred_repo_t * cr,uid_t uid, auks_cred_t * cred)
{
	int fstatus;

	char uid_str[UID_STR_LENGTH];

	/* set reference value */
	if ( snprintf(uid_str, UID_STR_LENGTH, "%u", uid) >= UID_STR_LENGTH ) {
		auks_log2("add : unable to build uid='%u' str representation",
			  uid);
		fstatus = AUKS_ERROR_LIBRARY_UID_TO_STR;
		return fstatus;
	}

	/* try to get cred from library */
	fstatus = xlibrary_get_item(&(cr->library), uid_str,
				    cred, sizeof(auks_cred_t));
	if (fstatus) {
		auks_log2("get : unable to find '%u' cred in the library",
			   uid);
		fstatus = AUKS_ERROR_LIBRARY_UID_NOT_FOUND;
	} else {
		auks_log3("get : '%u' cred successfully found in the library",
			  uid);
		fstatus = AUKS_SUCCESS;
	}

	return fstatus;
}

int
auks_cred_repo_remove_nolock(auks_cred_repo_t * cr, uid_t uid)
{
	int fstatus = AUKS_ERROR;

	char str_error[STR_ERROR_SIZE];
	str_error[0] = '\0';

	char uid_str[UID_STR_LENGTH];

	char filename[AUKS_CRED_FILE_MAX_LENGTH + 1];

	/* if not in read-only mode, */
	/* try to unlink corresponding auks cred cache */
	if (cr->read_only) {
		auks_log3("remove : read-only mode, skipping");
		fstatus = AUKS_ERROR_CRED_REPO_READONLY ;
		goto exit;
	}

	/* set reference value */
	if ( snprintf(uid_str, UID_STR_LENGTH, "%u", uid) >= UID_STR_LENGTH ) {
		auks_log2("add : unable to build uid='%u' str representation",
			  uid);
		fstatus = AUKS_ERROR_LIBRARY_UID_TO_STR;
		goto exit;
	}


	/* try to remove cred from library */
	fstatus = xlibrary_remove_item(&(cr->library), uid_str);
	if (fstatus) {
		auks_log2("remove : unable to remove '%u' cred "
			   "from the library",uid);
		fstatus = AUKS_ERROR_LIBRARY_UID_NOT_FOUND;
	} else {
		auks_log3("remove : '%u' cred successfully removed "
			 "from the library",uid);
		fstatus = AUKS_SUCCESS;
	}
	
	if (fstatus != AUKS_SUCCESS)
		goto exit;

	/* build auks cred cache file name */
	fstatus = auks_cred_repo_auks_credfile(cr,uid,filename,
					       AUKS_CRED_FILE_MAX_LENGTH);
	if ( fstatus !=AUKS_SUCCESS )
		goto exit;
	auks_log3("remove : '%d' auks cred cache is '%s'",uid, filename);

	/* unlink auks cred cache */
	fstatus = unlink(filename);
	if (fstatus) {
		DUMP_ERROR(errno,str_error,STR_ERROR_SIZE);
		auks_log2("remove : unable to unlink '%d' auks cred "
			   "cache '%s' : %s",uid, filename, str_error);
		fstatus = AUKS_ERROR_CRED_REPO_UNLINK ;
	} else {
		auks_log3("remove : '%d' auks cred cache '%s' successfully "
			 "removed from cache directory",uid, filename);
		fstatus = AUKS_SUCCESS ;
	}
	
exit:
	return fstatus;
}

int
auks_cred_repo_load_cache(auks_cred_repo_t * cr)
{
	int fstatus = AUKS_ERROR;
	
	unsigned int loaded_ccache = 0;

	char str_error[STR_ERROR_SIZE];
	
	char *cachedir;

	DIR *dir;
	struct dirent entry;
	struct dirent *cookie;

	char filename[AUKS_CRED_FILE_MAX_LENGTH + 1];
	size_t filename_maxlength = AUKS_CRED_FILE_MAX_LENGTH;

	auks_cred_t cred;

	cachedir = cr->cachedir;
	
	/* cache dir validity check */
	if (cachedir == NULL) {
		auks_log2("load : no cache directory defined in this repo");
		fstatus = AUKS_ERROR_CRED_REPO_CACHEDIR_IS_NULL;
		goto exit;
	}

	/* open cache directory */
	dir = opendir(cachedir);
	if (dir == NULL) {
		DUMP_ERROR(errno, str_error, STR_ERROR_SIZE);
		auks_log2("load : unable to open cache directory %s : %s",
			   cachedir, str_error);
		fstatus = AUKS_ERROR_CRED_REPO_CACHEDIR_OPEN;
		goto exit;
	}

	while (1) {
		
		/* lookup */
		fstatus = readdir_r(dir, &entry, &cookie);
		if (fstatus != 0) {
			DUMP_ERROR(errno, str_error,
				   STR_ERROR_SIZE);
			auks_log2("load : an error occured while processing"
				   " cache directory : %s",str_error);
			break;
		} else if (fstatus == 0 && cookie == NULL) {
			/* no more entry to process */
			auks_log3("load : no more entry to process in cache "
				  "directory");
			break;
		}
			
		/* look for auks cred cache patterned file */
		if (fnmatch(AUKS_CRED_CACHE_FILE_MOTIF,entry.d_name,
			    FNM_PATHNAME | FNM_PERIOD) != 0 ) {
			auks_log3("load : '%s' is not an auks cred cache",
				  entry.d_name);
			continue;
		}
		auks_log3("load : entry %s is an auks cred cache",entry.d_name);

		/* build auks cred cache filename */
		fstatus = snprintf(filename,filename_maxlength,"%s/%s",
				   cr->cachedir,entry.d_name);
		if ( fstatus >= filename_maxlength || fstatus < 0) {
			auks_log2("load : unable to build auks cred"
				   " cache filename");
			continue;
		}

		/* init auks cred from file */
		fstatus = auks_cred_extract(&cred,filename);
		if (fstatus) {
			auks_log2("load : unable to init auks cred from"
				  " auks cache '%s'",filename);
			goto cred_loop;
		}
		auks_log3("load : auks cred successfully initialized from auks "
			  "cache '%s'",filename);
			
		/* add auks cred to repo */
		fstatus = auks_cred_repo_add(cr,&cred);
		if (fstatus) {
			auks_log2("load : unable to add cred from auks cache"
				   " '%s' to the tree : %s",
				   filename,auks_strerror(fstatus));
		} else {
			auks_log3("load : auks cred cache '%s' successfully"
				  " loaded",filename);
			loaded_ccache += 1;
		}
			
		auks_cred_free_contents(&cred);

	cred_loop:
		memset(filename,'\0',filename_maxlength);

		continue;
	}

	auks_log("%u cred(s) loaded from cachedir %s",loaded_ccache,cachedir);
	fstatus = AUKS_SUCCESS;

	closedir(dir);

exit:
	return fstatus;
}

int
auks_cred_repo_clean_nolock(auks_cred_repo_t * cr,int* pnb)
{
	int fstatus;

	auks_cred_t cred;
	int i;

	int nbc;

	time_t ctime;
	time_t delay;

	xlibrary_item_t* pitem;

	time(&ctime);
	delay=0;

	/* update index */
	fstatus = auks_cred_repo_update_index_nolock(cr);
	if ( fstatus != AUKS_SUCCESS )
		return fstatus;
	
	/* clean the expired creds */
	nbc = 0 ;
	for ( i=0 ; i < cr->library.item_nb ; i++ ) {
		
		memset(&cred,'\0',sizeof(auks_cred_t));
		
		pitem=(xlibrary_item_t*)
			((xlibrary_item_t**)cr->library.index)[i];
		fstatus = xlibrary_get_item_nolock(&(cr->library),
						   pitem->reference,
						   &cred,
						   sizeof(auks_cred_t));
		if ( fstatus != AUKS_SUCCESS ) {
			auks_log2("unable to get cred_repo[%d] "
				  ": %s",i,auks_strerror(fstatus));
			fstatus = AUKS_ERROR_CRED_REPO_GET_CRED ;
		}
		
		/* check cred times */
		if ( cred.info.endtime + delay < ctime || 
		     (cred.info.renew_till > 0 && 
		      (cred.info.renew_till + delay < ctime)) ) {
			auks_log("cred_repo[%d] content is :",i);
			auks_cred_log(&cred);
			fstatus = auks_cred_repo_remove_nolock(cr,
							       cred.info.uid);
			if ( fstatus != AUKS_SUCCESS ) {
				auks_log("unable to remove cred_repo[%d] "
					  ": %s",i,auks_strerror(fstatus));
			}
			else {
				auks_log("cred_repo[%d] removed",i);
				nbc++;
			}
		}
		
	}

	if ( fstatus == AUKS_SUCCESS )
		*pnb = nbc ;

	return fstatus;
}


int
auks_cred_repo_update_index_nolock(auks_cred_repo_t * cr)
{
	int fstatus;

	/* update repository index */
	fstatus = xlibrary_update_index(&(cr->library));
	if ( fstatus != AUKS_SUCCESS ) {
		auks_log("unable to update index : %s",
			 auks_strerror(fstatus));
		fstatus = AUKS_ERROR_CRED_REPO_UPDATE_INDEX ;
	}
	auks_log2("index updated");
	
	return fstatus;
}

int
auks_cred_repo_pack_nolock(auks_cred_repo_t * cr,auks_message_t* msg)
{
	int fstatus;
	auks_cred_t cred;
	int i;
	xlibrary_item_t *pitem;

	/* update index */
	fstatus = auks_cred_repo_update_index_nolock(cr);
	if ( fstatus != AUKS_SUCCESS )
		return fstatus;

	/* pack cred number into dump reply */
	fstatus = auks_message_pack_int(msg,cr->library.item_nb);
	if ( fstatus != AUKS_SUCCESS ) {
		auks_log("unable to pack repo cred nb (%d) : %s",
			 cr->library.item_nb,
			 auks_strerror(fstatus));
		fstatus = AUKS_ERROR_CRED_REPO_PACK ;
	}
	auks_log2("repo cred nb (%d) packed",cr->library.item_nb);

	/* pack creds */
	for ( i=0 ; i < cr->library.item_nb ; i++ ) {
		
		memset(&cred,'\0',sizeof(auks_cred_t));
		
		/* dump current id cred */
		pitem=(xlibrary_item_t*)
			((xlibrary_item_t**)cr->library.index)[i];
		fstatus = xlibrary_get_item_nolock(&(cr->library),
						   pitem->reference,
						   &cred,
						   sizeof(auks_cred_t));
		if ( fstatus != AUKS_SUCCESS ) {
			auks_log2("unable to get cred_repo[%d] "
				  ": %s",i,auks_strerror(fstatus));
			fstatus = AUKS_ERROR_CRED_REPO_GET_CRED ;
			break;
		}
		
		/* pack cred */
		fstatus = auks_cred_pack(&cred,msg);
		if ( fstatus != AUKS_SUCCESS ) {
			auks_log("unable to pack cred_repo[%d] : %s",
				 i,auks_strerror(fstatus));
			fstatus = AUKS_ERROR_CRED_REPO_PACK ;
			break;
		}
		auks_log2("cred_repo[%d] packed",i);
		
	}
	
	return fstatus;
}

/*
 * ------------------------------------------------------------------------------------
 * INTERNAL  INTERNAL   INTERNAL   INTERNAL   INTERNAL   INTERNAL   INTERNAL   INTERNAL 
 *
 * INTERNAL  INTERNAL   INTERNAL   INTERNAL   INTERNAL   INTERNAL   INTERNAL   INTERNAL 
 *
 * INTERNAL  INTERNAL   INTERNAL   INTERNAL   INTERNAL   INTERNAL   INTERNAL   INTERNAL 
 * ------------------------------------------------------------------------------------
 */

void
_release_cred(void *p)
{
	auks_cred_t *cred;
	cred = (auks_cred_t *) p;
	
	/* free auks cred content */
	auks_cred_free_contents(cred);
}
