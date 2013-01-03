/***************************************************************************\
 * xlogger.c - a simple logging system
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

#include <pthread.h>

#include <time.h>
#include <stdarg.h>
#include <string.h>

static pthread_mutex_t error_mutex = PTHREAD_MUTEX_INITIALIZER ;
#define ERROR_LOCK() pthread_mutex_lock(&error_mutex)
#define ERROR_UNLOCK() pthread_mutex_unlock(&error_mutex)

static pthread_mutex_t debug_mutex = PTHREAD_MUTEX_INITIALIZER ;
#define DEBUG_LOCK() pthread_mutex_lock(&debug_mutex)
#define DEBUG_UNLOCK() pthread_mutex_unlock(&debug_mutex)

static pthread_mutex_t verbose_mutex = PTHREAD_MUTEX_INITIALIZER ;
#define VERBOSE_LOCK() pthread_mutex_lock(&verbose_mutex)
#define VERBOSE_UNLOCK() pthread_mutex_unlock(&verbose_mutex)

#include "xlogger.h"

static int xverbose_max_level=0;
static int xdebug_max_level=0;
static int xerror_max_level=1;

static FILE* xerror_stream = NULL;
static FILE* xverbose_stream = NULL;
static FILE* xdebug_stream = NULL;

void xverbose_base(int level,char* format,va_list args);
void xdebug_base(int level,char* format,va_list args);

void xerror_setstream(FILE* stream){
  xerror_stream=stream;
}

void xerror_setmaxlevel(int level){
  xerror_max_level=level;
}

void xerror(char* format,...){

  char time_string[128];
  time_t current_time;

  /* vfprintf crash on stderr and multithread... */
  FILE* default_stream=stdout;
  FILE* stream;

  if(!xerror_max_level)
    return;

  if(xerror_stream==NULL)
    stream=default_stream;
  else
    stream=xerror_stream;

  va_list args;
  va_start(args,format);

  time(&current_time);
  time_string[0]='\0';
  ctime_r(&current_time,time_string);
  time_string[strlen(time_string)-1]='\0';

  ERROR_LOCK();
  fprintf(stream,"%s [ERROR] [euid=%u,pid=%u] ",time_string,
	  geteuid(),getpid());
  vfprintf(stream,format,args);
  fprintf(stream,"\n");
  fflush(stream);
  ERROR_UNLOCK();

  va_end(args);

}

void xverbose_setstream(FILE* stream){
  xverbose_stream=stream;
}

void xverbose_setmaxlevel(int level){
  xverbose_max_level=level;
}

void xverbose_base(int level,char* format,va_list args){

  time_t current_time;

  FILE* default_stream=stdout;
  FILE* stream;

  if(xverbose_stream==NULL)
    stream=default_stream;
  else
    stream=xverbose_stream;

  if(level<=xverbose_max_level){
    char time_string[128];
    time(&current_time);
    time_string[0]='\0';
    ctime_r(&current_time,time_string);
    time_string[strlen(time_string)-1]='\0';
    VERBOSE_LOCK();
    fprintf(stream,"%s [INFO%d] [euid=%u,pid=%u] ",time_string,level,
	    geteuid(),getpid());
    vfprintf(stream,format,args);
    fprintf(stream,"\n");
    fflush(stream);
    VERBOSE_UNLOCK();
  }
}

void xverbose(char* format,...){
  int level=XVERBOSE_LEVEL_1;
  va_list args;
  va_start(args,format);
  xverbose_base(level,format,args);
  va_end(args);
}

void xverbose2(char* format,...){
  int level=XVERBOSE_LEVEL_2;
  va_list args;
  va_start(args,format);
  xverbose_base(level,format,args);
  va_end(args);
}

void xverbose3(char* format,...){
  int level=XVERBOSE_LEVEL_3;
  va_list args;
  va_start(args,format);
  xverbose_base(level,format,args);
  va_end(args);
}

void xverboseN(int level,char* format,...){
  if(level>9)
    level=9;
  va_list args;
  va_start(args,format);
  xverbose_base(level,format,args);
  va_end(args);
}


void xdebug_setmaxlevel(int level){
  xdebug_max_level=level;
}

void xdebug_setstream(FILE* stream){
  xdebug_stream=stream;
}

void xdebug_base(int level,char* format,va_list args){

  time_t current_time;

  FILE* default_stream=stdout;
  FILE* stream;

  if(xdebug_stream==NULL)
    stream=default_stream;
  else
    stream=xdebug_stream;
  
  if(level<=xdebug_max_level){
    char time_string[64];
    time(&current_time);
    time_string[0]='\0';
    ctime_r(&current_time,time_string);
    time_string[strlen(time_string)-1]='\0';
    DEBUG_LOCK();
    fprintf(stream,"%s [DBUG%d] ",time_string,level);
    vfprintf(stream,format,args);
    fprintf(stream,"\n");
    fflush(stream);
    DEBUG_UNLOCK();
  }
  
}

void xdebug(char* format,...){
  int level=XDEBUG_LEVEL_1;
  va_list args;
  va_start(args,format);
  xdebug_base(level,format,args);
  va_end(args);
}

void xdebug2(char* format,...){
  int level=XDEBUG_LEVEL_2;
  va_list args;
  va_start(args,format);
  xdebug_base(level,format,args);
  va_end(args);
}

void xdebug3(char* format,...){
  int level=XDEBUG_LEVEL_3;
  va_list args;
  va_start(args,format);
  xdebug_base(level,format,args);
  va_end(args);
}

void xdebugN(int level,char* format,...){
  if(level>9)
    level=9;
  va_list args;
  va_start(args,format);
  xdebug_base(level,format,args);
  va_end(args);
}
