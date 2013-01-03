/***************************************************************************\
 * auks_buffer.c - AUKS messages marshalling/unmarshalling system 
 * implementation
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

#include <stdint.h>

#define AUKS_LOG_HEADER "auks_buffer: "
#define AUKS_LOG_BASE_LEVEL 4
#define AUKS_LOG_DEBUG_LEVEL 4

#include "auks/auks_error.h"
#include "auks/auks_buffer.h"
#include "auks/auks_log.h"

#define BLOCK_SIZE ( 1* 1024 )

int
_auks_buffer_expand(auks_buffer_t * buf,size_t length)
{
	int fstatus = AUKS_ERROR ;
	int alloc = 0;

	if ( buf->length - buf->processed < length ) {
		int nb;
		nb = (int) length / BLOCK_SIZE  ;
		buf->length += BLOCK_SIZE * nb ; 
		if ( ( length % BLOCK_SIZE ) != 0 )
			buf->length += BLOCK_SIZE ;
		alloc = 1;
	}

	if ( alloc == 1 && buf->data != NULL ) {
		buf->data = (void*) realloc(buf->data,buf->length *
					    sizeof(char));
		if ( buf->data == NULL ){
			fstatus = AUKS_ERROR_BUFFER_REALLOC ;
		}
		else
			fstatus = AUKS_SUCCESS ;
	}
	else if ( buf->data == NULL ) {
		buf->data = (void*) malloc(buf->length *
					   sizeof(char));
		if ( buf->data == NULL ){
			fstatus = AUKS_ERROR_BUFFER_MALLOC ;
		}
		else
			fstatus = AUKS_SUCCESS ;
	}
	else
		fstatus = AUKS_SUCCESS ;
	
	return fstatus;
}

int
auks_buffer_init(auks_buffer_t * buf,size_t length)
{
	int fstatus;

	buf->data = NULL ;
	buf->length = BLOCK_SIZE  ;
	buf->processed = 0;

	fstatus = _auks_buffer_expand(buf,length);

	return fstatus;
}

int
auks_buffer_load(auks_buffer_t * buf,char * data,size_t length)
{
	int fstatus;

	fstatus = auks_buffer_init(buf,length);
	if ( fstatus == AUKS_SUCCESS ) {
		memcpy(buf->data,data,length);
		memset(buf->data+length,'\0',buf->length-length);
	}

	return fstatus;
}

int
auks_buffer_free_contents(auks_buffer_t * buf)
{
	int fstatus = AUKS_ERROR ;

	buf->length = 0;
	buf->processed = 0;

	if (buf->data != NULL) {
		free(buf->data);
		buf->data = NULL;
	}
	fstatus = AUKS_SUCCESS ;

	return fstatus;
}

int
auks_buffer_pack_int(auks_buffer_t * buf,int i)
{
	int fstatus;

	uint32_t ni;
	size_t size = sizeof(uint32_t);

	ni = htonl(i) ;

	fstatus = _auks_buffer_expand(buf,size);
	if ( fstatus == AUKS_SUCCESS ) {
		memcpy(buf->data+buf->processed,&ni,size);
		buf->processed+=size;
	}

	return fstatus;
}

int
auks_buffer_unpack_int(auks_buffer_t * buf,int * i)
{
	int fstatus = AUKS_ERROR ;

	uint32_t ni;
	size_t size = sizeof(uint32_t);

	if ( (buf->processed) + size <= buf->length ) {
		memcpy(&ni,buf->data+buf->processed,size);
		buf->processed+=size;
		*i = (int) ntohl(ni);
		fstatus = AUKS_SUCCESS;
	}

	return fstatus;
}

int
auks_buffer_pack_uid(auks_buffer_t * buf,uid_t u)
{
	return auks_buffer_pack_int(buf,(int)u);
}

int
auks_buffer_unpack_uid(auks_buffer_t * buf,uid_t * u)
{
	return auks_buffer_unpack_int(buf,(int*)u);
}

int
auks_buffer_pack_data(auks_buffer_t * buf,char * data,size_t length)
{
	int fstatus;

	fstatus = _auks_buffer_expand(buf,length);
	if ( fstatus == AUKS_SUCCESS ) {
		memcpy(buf->data+buf->processed,data,length);
		buf->processed+=length;
	}

	return fstatus;
}

int
auks_buffer_unpack_data(auks_buffer_t * buf,char * data,size_t length)
{
	int fstatus = AUKS_ERROR ;

	if ( (buf->processed) + length <= buf->length ) {
		memcpy(data,buf->data+buf->processed,length);
		buf->processed+=length;
		fstatus = AUKS_SUCCESS;
	}
	
	return fstatus;
}
