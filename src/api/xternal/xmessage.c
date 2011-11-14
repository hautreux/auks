/***************************************************************************\
 * xmessage.c - a simple marshalling/unmarshalling system implementation
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

/* for marshalling */
#include <rpc/types.h>
#include <rpc/xdr.h>

#include <errno.h>
extern int errno;

#include "xerror.h"

/* logging */
#include "xlogger.h"

#ifndef XMESSAGE_LOGHEADER
#define XMESSAGE_LOGHEADER "xmessage: "
#endif

#ifndef XMESSAGE_VERBOSE_BASE_LEVEL
#define XMESSAGE_VERBOSE_BASE_LEVEL 7
#endif

#ifndef XMESSAGE_DEBUG_BASE_LEVEL
#define XMESSAGE_DEBUG_BASE_LEVEL   7
#endif

#define VERBOSE(h,a...) xverboseN(XMESSAGE_VERBOSE_BASE_LEVEL,XMESSAGE_LOGHEADER h,##a)
#define VERBOSE2(h,a...) xverboseN(XMESSAGE_VERBOSE_BASE_LEVEL + 1,XMESSAGE_LOGHEADER h,##a)
#define VERBOSE3(h,a...) xverboseN(XMESSAGE_VERBOSE_BASE_LEVEL + 2,XMESSAGE_LOGHEADER h,##a)

#define DEBUG(h,a...) xdebugN(XMESSAGE_DEBUG_BASE_LEVEL,XMESSAGE_LOGHEADER h,##a)
#define DEBUG2(h,a...) xdebugN(XMESSAGE_DEBUG_BASE_LEVEL + 1,XMESSAGE_LOGHEADER h,##a)
#define DEBUG3(h,a...) xdebugN(XMESSAGE_DEBUG_BASE_LEVEL + 2,XMESSAGE_LOGHEADER h,##a)

#define ERROR VERBOSE

#define INIT_DEBUG_MARK()    DEBUG("%s : entering",function_name)
#define EXIT_DEBUG_MARK(a)   DEBUG("%s : exiting with status %d",function_name,a)

#define INIT_DEBUG2_MARK()   DEBUG2("%s : entering",function_name)
#define EXIT_DEBUG2_MARK(a)  DEBUG2("%s : exiting with status %d",function_name,a)

#define INIT_DEBUG3_MARK()   DEBUG3("%s : entering",function_name)
#define EXIT_DEBUG3_MARK(a)  DEBUG3("%s : exiting with status %d",function_name,a)

/* main header */
#include "xmessage.h"

int
xmessage_init(xmessage_t* msg,int type,char* buffer,size_t length){
  int fstatus=XERROR;
  char* function_name="xmessage_init";
  INIT_DEBUG2_MARK();

  msg->type=type;
  msg->length=0;

  if(length>0){
    msg->data=(void*)malloc(length*sizeof(char));
    if(msg->data!=NULL){
      msg->length=length;
      memcpy(msg->data,buffer,length);
      fstatus=XSUCCESS;
    }
    else{
      ERROR("unable to allocate memory for message data storage");
      fstatus=XERROR_MEMORY;
    }
  }
  else{
    msg->data=NULL;
    fstatus=XSUCCESS;
  }

  EXIT_DEBUG2_MARK(fstatus);
  return fstatus;
}

int
xmessage_free_contents(xmessage_t* msg){
  int fstatus=XSUCCESS;
  char* function_name="xmessage_free_contents";
  INIT_DEBUG2_MARK();

  msg->type=XPING_REQUEST;

  msg->length=0;

  if(msg->data!=NULL){
    free(msg->data);
    msg->data=NULL;
  }

  EXIT_DEBUG2_MARK(fstatus);
  return fstatus;
}

int
xmessage_marshall(xmessage_t* msg,char** pbuffer,size_t* psize){
  int fstatus=XERROR;
  char* function_name="xmessage_marshall";
  INIT_DEBUG_MARK();

  XDR xdr;
  char* buffer;
  size_t size;

  size=sizeof(int)+sizeof(long);
  size+=msg->length;

  buffer=(char*)malloc(size*sizeof(char));
  if(buffer!=NULL){
    
    xdrmem_create(&xdr,buffer,size,XDR_ENCODE);

    if(!xdr_int(&xdr,(int*)&(msg->type))){
      ERROR("unable to serialize message type");
    }
    else if(!xdr_u_long(&xdr,(unsigned long*)&(msg->length))){
      ERROR("unable to serialize message data length");
    }
    else if(!xdr_opaque(&xdr,(char*)msg->data,(u_int)msg->length)){
      ERROR("unable to serialize message data '%s' (%d)",msg->data,msg->length);
    }
    else{
      VERBOSE("message (type %d) successfully marshalled",msg->type);
      *pbuffer=buffer;
      *psize=size;
      fstatus=XSUCCESS;
    }
    
    xdr_destroy(&xdr);
    
  }
  else{
    ERROR("unable to allocate memory for message marshalling");
  }

  EXIT_DEBUG_MARK(fstatus);
  return fstatus;
}

int
xmessage_unmarshall(xmessage_t* msg,char* buffer,size_t size){
  int fstatus=XERROR;
  char* function_name="xmessage_unmarshall";
  INIT_DEBUG_MARK();

  XDR xdr;

  if(buffer!=NULL){
    
    xdrmem_create(&xdr,buffer,size,XDR_DECODE);

    if(!xdr_int(&xdr,(int*)&(msg->type))){
      ERROR("unable to deserialize message type");
    }
    else if(!xdr_u_long(&xdr,(unsigned long*)&(msg->length))){
      ERROR("unable to deserialize message data length");
    }
    else{

      VERBOSE("message type is %d",msg->type);
      VERBOSE("message length is %u",msg->length);

      if( msg->length > 0 ){
	msg->data=(char*)malloc(msg->length*sizeof(char));
	if(msg->data==NULL){
	  ERROR("unable to allocate memory for message unmarshalling : %s",strerror(errno));	  
	}
	else{

	  if(!xdr_opaque(&xdr,(char*)msg->data,(u_int)msg->length)){
	    ERROR("unable to deserialize message data");
	  }
	  else{
	    VERBOSE("message (type %d) successfully unmarshalled",msg->type);
	    fstatus=XSUCCESS;
	  }

	}
      }
      else{
	msg->data=NULL;
	msg->length=0;
	VERBOSE("message (type %d without data) successfully unmarshalled",msg->type);
	fstatus=XSUCCESS;
      }
      
    }
    
  }
  else
    ERROR("unable to unmarshall message, input buffer is NULL");

  EXIT_DEBUG_MARK(fstatus);
  return fstatus;
}
