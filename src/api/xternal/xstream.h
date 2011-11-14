/***************************************************************************\
 * xstream.h - xstream functions and structures definitions
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
#ifndef __XSTREAM_H
#define __XSTREAM_H

#include "xerror.h"

/*! \addtogroup XTERNAL
 *  @{
 */

/*! \addtogroup XSTREAM
 *  @{
 */

#include <sys/socket.h>

/*!
 * \brief Create stream socket and connect it to given host and service
 *
 * \param hostname host to connect to
 * \param servicename service to connect to (name or port)
 * \param timeout connection timeout (0 if no timeout)
 *
 * \retval >0 socket fd
 * \retval XERROR generic error
 * \retval XERROR_STREAM_SOCKET_FAILED unable to create socket
 * \retval XERROR_STREAM_SETSOCKOPT_FAILED unable to set socket options
 * \retval XERROR_STREAM_GETADDRINFO_FAILED unable to get hostname addr info
 * \retval XERROR_STREAM_CONNECT_FAILED unable to connect hostname
 * \retval XERROR_STREAM_POLL_ERROR unable to connect hostname due to poll error
 *
*/
int
xstream_connect(const char* hostname,const char* servicename,
		time_t timeout);

/*!
 * \brief Create stream socket and bind it using given host and service
 *
 * \param hostname host to use during bind
 * \param servicename service  to use during bind
 *
 * \retval >0 socket fd
 * \retval XERROR generic error
 * \retval XERROR_STREAM_SOCKET_FAILED unable to create socket
 * \retval XERROR_STREAM_SETSOCKOPT_FAILED unable to set socket options
 * \retval XERROR_STREAM_GETADDRINFO_FAILED unable to get hostname addr info
 * \retval XERROR_STREAM_BIND_FAILED unable to bind socket on any addr
 *
 */
int
xstream_create(const char* hostname,const char* servicename);


/*!
 * \brief Specify queue limit for incoming connections on a a socket
 *
 * \param socket previously created stream socket (@xstream_create)
 * \param backlog queue limit (see man listen for more details)
 *
 * \retval  0 operation successfully done
 * \retval XERROR generic error
 *
*/
int
xstream_listen(int socket, int backlog);


/*!
 * \brief Accept incoming connection from previously created stream socket
 *
 * \param socket previously created stream socket (@xstream_create)
 *
 * \retval >0 incoming request socket fd
 * \retval XERROR generic error
 * \retval XERROR_EINTR interrupted
 *
*/
int
xstream_accept(int socket);


/*!
 * \brief Close previously created or connected stream socket
 *
 * \param socket the socket to close
 *
 * \retval XSUCCESS success
 * \retval XERROR generic error
 *
*/
int
xstream_close(int socket);

/*!
 * \brief Send data into a socket with timeout
 *
 * \param socket the socket FD to use
 * \param buffer pointer on the data to send
 * \param length amount of data to send from buffer
 * \param timeout timeout in milliseconds for the operation
 *
 * \retval XSUCCESS success
 * \retval XERROR generic error
 * \retval XERROR_STREAM_SETSOCKOPT_FAILED unable to switch socket to non blocking mode
 * \retval XERROR_STREAM_TIMEOUT timeout during the operation
 * \retval XERROR_STREAM_POLL_ERROR error while polling
 * \retval XERROR_STREAM_SOCKET_CLOSED socket is closed
 *
*/
int xstream_send_timeout(int socket,char* buffer,size_t length,int timeout);

/*!
 * \brief Send data into a socket without timeout
 *
 * \param socket the socket FD to use
 * \param buffer pointer on the data to send
 * \param length amount of data to send from buffer
 *
 * \retval XSUCCESS success
 * \retval XERROR generic error
 *
*/
int xstream_send(int socket,char* buffer,size_t length);

/*!
 * \brief Receive data from a socket with timeout
 *
 * \param socket the socket FD to use
 * \param buffer pointer on the data to receive
 * \param length amount of data to receive from buffer
 * \param timeout timeout in milliseconds for the operation
 *
 * \retval XSUCCESS success
 * \retval XERROR generic error
 * \retval XERROR_STREAM_SETSOCKOPT_FAILED unable to switch socket to non blocking mode
 * \retval XERROR_STREAM_TIMEOUT timeout during the operation
 * \retval XERROR_STREAM_POLL_ERROR error while polling
 * \retval XERROR_STREAM_SOCKET_CLOSED socket is closed
 *
*/
int xstream_receive_timeout(int socket,char* buffer,size_t length,int timeout);

/*!
 * \brief Receive data from a socket without timeout
 *
 * \param socket the socket FD to use
 * \param buffer pointer on the data to receive
 * \param length amount of data to receive from buffer
 *
 * \retval XSUCCESS success
 * \retval XERROR generic error
 *
*/
int xstream_receive(int socket,char* buffer,size_t length);


/*!
 * \brief Send message into a socket with timeout
 *
 * \param socket the socket FD to use
 * \param buffer pointer on the data to send
 * \param length amount of data to send from buffer
 * \param timeout timeout in milliseconds for the operation
 *
 * \retval XSUCCESS success
 * \retval XERROR generic error
 * \retval XERROR_STREAM_SETSOCKOPT_FAILED unable to switch socket to non blocking mode
 * \retval XERROR_STREAM_TIMEOUT timeout during the operation
 * \retval XERROR_STREAM_POLL_ERROR error while polling
 * \retval XERROR_STREAM_SOCKET_CLOSED socket is closed
 *
*/
int xstream_send_msg_timeout(int socket,char* buffer,size_t length,int timeout);

/*!
 * \brief Send message into a socket without timeout
 *
 * \param socket the socket FD to use
 * \param buffer pointer on the data to send
 * \param length amount of data to send from buffer
 *
 * \retval XSUCCESS success
 * \retval XERROR generic error
 *
*/
int xstream_send_msg(int socket,char* buffer,size_t length);

/*!
 * \brief Receive a message from a socket with timeout
 *
 * \param socket the socket FD to use
 * \param pbuffer pointer on a buffer to allocate and fill with message data (must be free externally)
 * \param plength pointer on the amount of data corresponding to the message
 * \param timeout timeout in milliseconds for the operation
 *
 * \retval XSUCCESS success
 * \retval XERROR generic error
 * \retval XERROR_MEMORY unable to allocate memory for message data storage
 * \retval XERROR_STREAM_SETSOCKOPT_FAILED unable to switch socket to non blocking mode
 * \retval XERROR_STREAM_TIMEOUT timeout during the operation
 * \retval XERROR_STREAM_POLL_ERROR error while polling
 * \retval XERROR_STREAM_SOCKET_CLOSED socket is closed
 *
*/
int xstream_receive_msg_timeout(int socket,char** pbuffer,size_t* plength,int timeout);

/*!
 * \brief Receive data from a socket without timeout
 *
 * \param socket the socket FD to use
 * \param pbuffer pointer on a buffer to allocate and fill with message data (must be free externally)
 * \param plength pointer on the amount of data corresponding to the message
 *
 * \retval XSUCCESS success
 * \retval XERROR generic error
 * \retval XERROR_MEMORY unable to allocate memory for message data storage
 *
*/
int xstream_receive_msg(int socket,char** buffer,size_t* length);



/*!
 * @}
*/

/*!
 * @}
*/

#endif
