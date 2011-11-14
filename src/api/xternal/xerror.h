/***************************************************************************\
 * xerror.h - xternal implementations error codes
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
#ifndef __XERROR_H_
#define __XERROR_H_


#define XSUCCESS                                 0
#define XERROR                                  -1

#define XERROR_EINTR                            -2
#define XERROR_MEMORY                           -3

/* pthread related error code */
#define XERROR_MUTEX_INIT                      -91
#define XERROR_MUTEX_LOCK                      -92
#define XERROR_CONDITION_INIT                  -93

/* xfreelist related error codes */
#define XERROR_FREELIST_INIT                  -101
#define XERROR_FREELIST_IS_EMPTY              -102
#define XERROR_FREELIST_ITEM_NOT_FOUND        -103
#define XERROR_FREELIST_ITEM_ALREADY_FREE     -104

/* xlibrary related error codes */
#define XERROR_LIBRARY_ITEM_NOT_FOUND         -201
#define XERROR_LIBRARY_OBJECT_NOT_FOUND       -202
#define XERROR_LIBRARY_ADD                    -203

/* xstream related error code */
#define XERROR_STREAM_SOCKET                  -301
#define XERROR_STREAM_SETSOCKOPT              -302
#define XERROR_STREAM_GETADDRINFO             -303
#define XERROR_STREAM_BIND                    -304
#define XERROR_STREAM_CONNECT                 -305
#define XERROR_STREAM_POLL_ERROR              -306
#define XERROR_STREAM_TIMEOUT                 -307
#define XERROR_STREAM_SOCKET_CLOSED           -308

/* xqueue related error code */
#define XERROR_QUEUE_FREELIST_IS_NULL         -401
#define XERROR_QUEUE_FREELIST_EXTRACT_ITEM    -402
#define XERROR_QUEUE_IS_EMPTY                 -403

#endif
