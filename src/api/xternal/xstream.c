/***************************************************************************\
 * xstream.c - a TCP stream management implementation
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
#include <unistd.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <fcntl.h>
#include <sys/poll.h>

#include <string.h>

#include <errno.h>
extern int errno;

#include "xlogger.h"

#include "xstream.h"

#define DUMP_ERROR(e,s,S) { char* rc=strerror_r((int)e,(char*)s,(size_t)S); \
  if(rc==0) \
    { \
      s[0]='-'; \
      s[1]='\0'; \
    } \
}

#ifndef XSTREAM_LOGHEADER
#define XSTREAM_LOGHEADER "xstream: "
#endif

#ifndef XSTREAM_VERBOSE_BASE_LEVEL
#define XSTREAM_VERBOSE_BASE_LEVEL 7
#endif

#ifndef XSTREAM_DEBUG_BASE_LEVEL
#define XSTREAM_DEBUG_BASE_LEVEL   7
#endif

#define VERBOSE(h,a...) xverboseN(XSTREAM_VERBOSE_BASE_LEVEL,XSTREAM_LOGHEADER h,##a)
#define VERBOSE2(h,a...) xverboseN(XSTREAM_VERBOSE_BASE_LEVEL + 1,XSTREAM_LOGHEADER h,##a)
#define VERBOSE3(h,a...) xverboseN(XSTREAM_VERBOSE_BASE_LEVEL + 2,XSTREAM_LOGHEADER h,##a)

#define DEBUG(h,a...) xdebugN(XSTREAM_DEBUG_BASE_LEVEL,XSTREAM_LOGHEADER h,##a)
#define DEBUG2(h,a...) xdebugN(XSTREAM_DEBUG_BASE_LEVEL + 1,XSTREAM_LOGHEADER h,##a)
#define DEBUG3(h,a...) xdebugN(XSTREAM_DEBUG_BASE_LEVEL + 2,XSTREAM_LOGHEADER h,##a)

#define ERROR VERBOSE

#define INIT_DEBUG_MARK()    DEBUG("%s : entering",function_name)
#define EXIT_DEBUG_MARK(a)   DEBUG("%s : exiting with status %d",function_name,a)

#define INIT_DEBUG2_MARK()   DEBUG2("%s : entering",function_name)
#define EXIT_DEBUG2_MARK(a)  DEBUG2("%s : exiting with status %d",function_name,a)

#define INIT_DEBUG3_MARK()   DEBUG3("%s : entering",function_name)
#define EXIT_DEBUG3_MARK(a)  DEBUG3("%s : exiting with status %d",function_name,a)

int
xstream_create(const char* hostname,
	       const char* servicename)
{
  char* function_name="xstream_create";
  INIT_DEBUG2_MARK();

  int sock;
  int authorization;

  struct addrinfo* ai;
  struct addrinfo* aitop;
  struct sockaddr_in addr;
  struct sockaddr_in addresse;

  struct addrinfo hints;

  int fstatus=XERROR;
  int status=-1;

  /* create an AF_INET socket */
  if ( ( sock = socket(AF_INET, SOCK_STREAM, 0) ) < 0 ){
    ERROR("socket creation failed : %s",strerror(errno));
    return XERROR_STREAM_SOCKET;
  }
  VERBOSE("socket creation succeed");
  
  /* set reuse flag, restart will not crash due to an already bound TCP port */
  authorization=1;
  if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &authorization, sizeof(int))){
    ERROR("socket option set up failed : %s",strerror(errno));
    close(sock);
    return XERROR_STREAM_SETSOCKOPT;
  }
  VERBOSE("socket REUSEADDR option is now set");
  
  /* 
   * Set hint flag in order to listen on any address 
   * if hostname is not specified
   */
  memset(&hints,0,sizeof(hints));
  hints.ai_flags=AI_PASSIVE;
  hints.ai_family=AF_INET;
  
  /*
   * get 'hostname' network informations
   */
  status=getaddrinfo(strnlen(hostname,1)?hostname:NULL,servicename,&hints,&aitop);
  if(status){
    ERROR("getaddrinfo (%s:%s) failed : %s",hostname,servicename,gai_strerror(status));
    close(sock);
    return XERROR_STREAM_GETADDRINFO;
  }
  else{
    VERBOSE("getaddrinfo (%s:%s) succeed",hostname,servicename);

    /*
     * For all returned addresses, try to bind socket on it
     * exits when it succeeds or fail after all tries
     */
    for(ai=aitop; ai; ai=ai->ai_next){
      memcpy(&addr,ai->ai_addr,ai->ai_addrlen);
      
      if(addr.sin_family==AF_INET){
	memset(& addresse, 0, sizeof(struct sockaddr_in));
	addresse.sin_family = AF_INET;
	addresse.sin_port = addr.sin_port;
	addresse.sin_addr.s_addr = addr.sin_addr.s_addr;
	
	if(bind(sock, (struct sockaddr*) &addresse, sizeof(struct sockaddr_in))<0){
	  ERROR("bind(%s:%d) failed : %s",inet_ntoa(addr.sin_addr),ntohs(addr.sin_port),strerror(errno));
	  fstatus=XERROR_STREAM_BIND;
	  continue;
	}
	else{
	  VERBOSE("bind(%s:%d) succeed",inet_ntoa(addr.sin_addr),ntohs(addr.sin_port));
	  fstatus=XSUCCESS;
	  break;
	} /* bind */

      } /* AF_INET check */

    } /* for(ai=...) */

    /* free addrinfo structures */
    freeaddrinfo(aitop);
    
  } /* getaddrinfo */
  

  /*
   * Return the socket file descriptor if success, -1 otherwise
   */
  if(fstatus==XSUCCESS)
    fstatus=sock;
  else{
    close(sock);  
  }
  
  EXIT_DEBUG2_MARK(fstatus);

  return fstatus;
}


int
xstream_connect(const char* hostname,
		const char* servicename,
		time_t timeout)
{
  char* function_name="xstream_connect";
  INIT_DEBUG2_MARK();

  int sock;
  int sock_flags;

  struct addrinfo* ai;
  struct addrinfo* aitop;
  struct sockaddr_in addr;
  struct sockaddr_in addresse;
  
  socklen_t optlen;
  struct addrinfo hints;

  struct pollfd ufds;
  int sockopt;

  int fstatus=XERROR;
  int status;

  /* set hint flag that indicate to get TCP/IP information only */
  memset(&hints,0,sizeof(hints));
  hints.ai_family=AF_INET;
  hints.ai_socktype=SOCK_STREAM;

  /*
   * get 'hostname' network informations
   */
  status=getaddrinfo(hostname,servicename,&hints,&aitop);
  if(status){
    ERROR("getaddrinfo (%s:%s) failed : %s",hostname,servicename,gai_strerror(status));
    close(sock);
    return XERROR_STREAM_GETADDRINFO;
  }
  else{

    /*
     * for all returned addresses try to connect the socket to
     */
    for(ai=aitop; ai; ai=ai->ai_next){
      memset(&addresse, 0, sizeof(struct sockaddr_in));
      memcpy(&addr,ai->ai_addr,ai->ai_addrlen);

	addresse.sin_family = AF_INET;
	addresse.sin_port = addr.sin_port;
	addresse.sin_addr.s_addr = addr.sin_addr.s_addr;

	/* create an AF_INET socket */
	if (( sock = socket(AF_INET, SOCK_STREAM, 0) ) < 0 ){
	  ERROR("socket creation failed : %s",strerror(errno));
	  fstatus=XERROR_STREAM_SOCKET;
	  continue;
	}
	VERBOSE("socket creation succeed");
	
	/* if timeout is not zero, set non blocking mode */
	if(timeout!=0){
	  sock_flags=fcntl(sock,F_GETFL);
	  if(fcntl(sock,F_SETFL, sock_flags | O_NONBLOCK)){
	    ERROR("unable to set socket non-blocking flag : %s",strerror(errno));
	    close(sock);
	    fstatus=XERROR_STREAM_SETSOCKOPT;
	    continue;
	  }
	  VERBOSE("socket non-blocking flag is now set");
	}

	int rc;
	rc=connect(sock, (struct sockaddr*) &addresse, sizeof(struct sockaddr_in));
	/* connection failed */
	if(rc<0 && errno != EINPROGRESS && errno != EALREADY){
	  ERROR("connect (%s:%d) failed : %s (%d)",inet_ntoa(addresse.sin_addr),
		ntohs(addresse.sin_port),strerror(errno),errno);
	  fstatus=XERROR_STREAM_CONNECT;
	  close(sock);
	  continue;
	}
	/* connection in progress */
	else if(rc<0){
	  ufds.fd=sock;
	  ufds.events= POLLIN | POLLOUT ;
	  ufds.revents=0;
	  /* poll socket */
	  do{
	    rc=poll(&ufds,1,timeout);
	  }
	  while(rc==-1 && (errno==EINTR || errno==EALREADY));

	  if(rc==-1){
	    ERROR("poll (%s:%d) failed : %s",inet_ntoa(addresse.sin_addr),ntohs(addresse.sin_port),
		  strerror(errno));
	  }
	  else if(rc==0){
	    ERROR("poll (%s:%d) times out",inet_ntoa(addresse.sin_addr),ntohs(addresse.sin_port));
	  }
	  else{
	    /* we have to verify that this is not an error that trigger poll success */
	    optlen=sizeof(sockopt);
	    rc=getsockopt(sock,SOL_SOCKET,SO_ERROR,&sockopt,&optlen);
	    if(rc<0){
	      ERROR("unable to get socket SO_ERROR value despite of %s:%d polling success : %s",
		    inet_ntoa(addresse.sin_addr),ntohs(addresse.sin_port),strerror(errno));
	    }
	    else{
	      if(sockopt){
		ERROR("connect (%s:%d) failed while polling : %s",inet_ntoa(addresse.sin_addr),
		      ntohs(addresse.sin_port),strerror(sockopt));
	      }
	      else{
		VERBOSE("connect (%s:%d) succeed while polling",inet_ntoa(addresse.sin_addr),
			ntohs(addresse.sin_port));
		fstatus=XSUCCESS;
		break;
	      }
	    }
	  }
	  close(sock);
	  fstatus=XERROR_STREAM_POLL_ERROR;
	}
	/* connection succeed immediately */
	else{
	  VERBOSE("connect (%s:%d) immediately succeed",inet_ntoa(addresse.sin_addr),
		  ntohs(addresse.sin_port));
	  fstatus=XSUCCESS;
	  break;
	}
	
    } /* for (ai=...) */

    /* free addrinfo structures */
    freeaddrinfo(aitop);

  }
  
  /* reverse socket flags */
  if(timeout!=0){
    fcntl(sock,F_SETFL,sock_flags);
  }

  /*
   * Return the socket file descriptor if success, -1 otherwise
   */
  if(fstatus==XSUCCESS)
    fstatus=sock;
  else{
    close(sock);    
    fstatus=-1;
  }

  EXIT_DEBUG2_MARK(fstatus);

  return fstatus;
}


int
xstream_accept(int socket){
  char* function_name="xstream_accept";
  INIT_DEBUG2_MARK();

  int incoming_stream;
  struct sockaddr_in remote_addr;
  socklen_t addrlen;

  int fstatus=XERROR;
  
  addrlen=sizeof(remote_addr);

  incoming_stream=accept(socket,(struct sockaddr *)&remote_addr,&addrlen);
  if(incoming_stream<0 && errno==EINTR){
    ERROR("error while accepting incoming request : interrupted");
    fstatus=XERROR_EINTR;
  }
  else if(incoming_stream<0){
    ERROR("error while accepting incoming request : %s",strerror(errno));
  }
  else{
    fstatus=incoming_stream;
  }
  
  EXIT_DEBUG2_MARK(fstatus);

  return fstatus;
}

int
xstream_close(int socket){
  int fstatus=-1;

  close(socket);

  return fstatus;
}

int
xstream_listen(int socket,int backlog){
  int fstatus;
  char* function_name="xstream_listen";
  INIT_DEBUG2_MARK();

  fstatus=listen(socket,backlog);
  if(fstatus!=0){
    ERROR("error while specifying stream listening queue length : %s",strerror(errno));
  }
  
  EXIT_DEBUG2_MARK(fstatus);

  return fstatus;
}


int xstream_send(int socket,char* buffer,size_t length){

  return xstream_send_timeout(socket,buffer,length,0);

}

int xstream_send_timeout(int socket,char* buffer,size_t length,int timeout){
  int fstatus=XERROR;
  int rc;
  size_t written_bytes;

  char test;

  int sock_flags;
  int nonblock=0;
  struct pollfd ufds;

  struct timeval start_time;
  struct timeval current_time;
  int timeleft;

  /* set non block mode if required */
  if(timeout!=0){
    sock_flags=fcntl(socket,F_GETFL);
    if(fcntl(socket,F_SETFL, sock_flags | O_NONBLOCK)){
      ERROR("unable to set socket non-blocking flag : %s",strerror(errno));
      return XERROR_STREAM_SETSOCKOPT;
    }
    else{
      VERBOSE("socket non-blocking flag is now set");
      nonblock=1;

      ufds.fd=socket;
      ufds.events=POLLOUT;
    }
  }
  
  /* get start time */
  gettimeofday(&start_time,NULL);

  /* send data */
  written_bytes=0;
  while(written_bytes<length){

    /* attempt polling if non block mode is activated */
    if(nonblock){
      VERBOSE3("looking for POLLOUT events on socket %d",socket);

      gettimeofday(&current_time,NULL);
      timeleft=timeout
	-(current_time.tv_sec-start_time.tv_sec)*1000
	-(current_time.tv_sec-start_time.tv_sec)/1000;
      
      if(timeleft<=0){
	ERROR("send at %d/%d bytes transmitted : timeout",
	      written_bytes,length);
	fstatus=XERROR_STREAM_TIMEOUT;
	break;
      }

      if((rc=poll(&ufds,1,timeleft))<=0){
	if(rc<0 && (errno==EINTR || errno==EAGAIN)){
	  continue;
	}
	else if(rc==0){
	  continue;
	}
	else if(rc<0){
	  ERROR("send at %d/%d bytes transmitted : poll error : %s",
		written_bytes,length,strerror(errno));
	  fstatus=XERROR_STREAM_POLL_ERROR;
	  break;
	}
	else{
	  
	  /* we just check that the socket is still here */
	  /* read from a closed nonblocking socket should return 0 */
	  do{
	    rc=read(socket,&test,1);
	  }
	  while(rc<0 && errno==EINTR);
	  if(rc==0){
	    ERROR("send at %d/%d bytes transmitted : socket is gone",
		  written_bytes,length);
	    fstatus=XERROR_STREAM_SOCKET_CLOSED;
	    break;
	  }
	  
	}
      }
      
      /* send data */
      rc=write(socket,buffer+written_bytes,length-written_bytes);
      VERBOSE3("write return code is %d (errno=%d)",rc,errno);

    }
    else {

      /* send data */
      do{
	rc=write(socket,buffer+written_bytes,length-written_bytes);
	VERBOSE3("write return code is %d (errno=%d)",rc,errno);
      }
      while(rc<0 && (errno==EINTR || errno==EAGAIN));

    }

    /* process write return code */
    if(rc>0)
      written_bytes+=rc;
    else if(rc) {
      fstatus=rc;
      break;
    }
    else
      break;
    
  }
  
  /* reverse socket flags */
  if(timeout!=0){
    fcntl(socket,F_SETFL,sock_flags);
  }

  if(written_bytes==length){
    fstatus=XSUCCESS;
  }
    
  return fstatus;
}


int xstream_receive(int socket,char* buffer,size_t length){

  return xstream_receive_timeout(socket,buffer,length,0);

}

int xstream_receive_timeout(int socket,char* buffer,size_t length,int timeout){
  int fstatus=-1;
  int rc;
  size_t read_bytes;
  
  int sock_flags;
  int nonblock=0;
  struct pollfd ufds;

  struct timeval start_time;
  struct timeval current_time;
  int timeleft;

  /* set non block mode if required */
  if(timeout!=0){
    sock_flags=fcntl(socket,F_GETFL);
    if(fcntl(socket,F_SETFL, sock_flags | O_NONBLOCK)){
      ERROR("unable to set socket non-blocking flag : %s",strerror(errno));
      return XERROR_STREAM_SETSOCKOPT;
    }
    else{
      VERBOSE("socket non-blocking flag is now set");
      nonblock=1;

      ufds.fd=socket;
      ufds.events=POLLIN;
    }
  }
  
  /* get start time */
  gettimeofday(&start_time,NULL);

  /* send data */
  read_bytes=0;
  while(read_bytes<length){
    
    /* attempt polling if non block mode is activated */
    if(nonblock){
      VERBOSE3("looking for POLLIN events on socket %d",socket);
      
      gettimeofday(&current_time,NULL);
      timeleft=timeout
	-(current_time.tv_sec-start_time.tv_sec)*1000
	-(current_time.tv_sec-start_time.tv_sec)/1000;
      
      if(timeleft<=0){
	ERROR("receive at %d of %d bytes : timeout",
	      read_bytes,length);
	fstatus=XERROR_STREAM_TIMEOUT;
	break;
      }

      if((rc=poll(&ufds,1,timeleft))<=0){
	if(rc<0 && (errno==EINTR || errno==EAGAIN)){
	  continue;
	}
	else if(rc==0){
	  continue;
	}
	else if(rc<0){
	  ERROR("receive at %d of %d bytes : poll error : %s",
		read_bytes,length,strerror(errno));
	  fstatus=XERROR_STREAM_POLL_ERROR;
	  break;
	}
      }
      
      /* read data from socket */
      rc=read(socket,buffer+read_bytes,length-read_bytes);
      VERBOSE3("read return code is %d (errno=%d)",rc,errno);

    }
    else {

      /* read data from socket */
      do{
	rc=read(socket,buffer+read_bytes,length-read_bytes);
	VERBOSE3("read return code is %d (errno=%d)",rc,errno);
      }
      while(rc<0 && (errno==EINTR || errno==EAGAIN));

    }
    /*_*/ /* attempt polling if required */

    /* process read return code */
    if(rc>0)
      read_bytes+=rc;
    else if (rc==0) {
      ERROR("receive at %d of %d bytes : 0 bytes received during read op",
	    read_bytes,length);
      fstatus=XERROR_STREAM_SOCKET_CLOSED;
      break;
    }
    else {
      ERROR("receive at %d of %d bytes : bad return code on read op : %d",
	    read_bytes,length,rc);
      fstatus=rc;
      break;
    }
    
  }

  if(read_bytes==length){
    fstatus=XSUCCESS;
  }
    
  return fstatus;
}

int xstream_send_msg_timeout(int socket,char* buffer,size_t length,int timeout){

  int fstatus;
  uint32_t nlength;
  
  /* send message length */
  nlength=htonl(length);
  fstatus=xstream_send_timeout(socket,(char*)&nlength,sizeof(uint32_t),timeout);
  if(fstatus!=XSUCCESS){
    ERROR("unable to send message length (%d)",length);
  }
  else{
    VERBOSE("message length (%d) successfully send",length);

    /* send message data */
    fstatus=xstream_send(socket,buffer,length);
    if(fstatus==XSUCCESS){
      VERBOSE("message successfully send");
    }
    else{
      ERROR("unable to send message");
    }
    
  }

  return fstatus;
}


int xstream_receive_msg_timeout(int socket,char** buffer,size_t* length,int timeout){

  int fstatus;
  uint32_t nlength;
  
  char* mbuf;
  
  /* receive message length */
  fstatus=xstream_receive_timeout(socket,(char*)&nlength,sizeof(uint32_t),timeout);
  if(fstatus){
    ERROR("unable to receive message length");
  }
  else{
    size_t mlen;
    mlen=ntohl(nlength);
    VERBOSE("message length (%d) successfully received",mlen);

    /* allocate memory for message */
    mbuf=(char*)malloc(mlen*sizeof(char));
    if(mbuf==NULL){
      fstatus=XERROR_MEMORY;
    }
    else{

      /* receive message data */
      fstatus=xstream_receive(socket,mbuf,mlen);
      if(fstatus){
	ERROR("unable to receive message");
	free(mbuf);
      }
      else{
	*buffer=mbuf;
	*length=mlen;
	VERBOSE("message successfully received");
	fstatus=XSUCCESS;
      }

    }
    
  }

  return fstatus;
}


int xstream_send_msg(int socket,char* buffer,size_t length){

  return xstream_send_msg_timeout(socket,buffer,length,0);

}


int xstream_receive_msg(int socket,char** buffer,size_t* length){

  return xstream_receive_msg_timeout(socket,buffer,length,0);

}

