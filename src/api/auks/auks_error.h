/***************************************************************************\
 * auks_error.h - AUKS error functions and variables definitions
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
#ifndef __AUKS_ERROR_H_
#define __AUKS_ERROR_H_

/*! \addtogroup AUKS_ERROR
 *  @{
 */

const char * auks_strerror(int error) ;

/*
 * GLOBAL
 */
#define AUKS_SUCCESS                                    0
#define AUKS_ERROR                                     -1

/*
 * INTERNAL 
 */

/* -- LIBRARY */
#define AUKS_ERROR_LIBRARY_INIT                   -100001
#define AUKS_ERROR_LIBRARY_UID_NOT_FOUND          -100002
#define AUKS_ERROR_LIBRARY_ADD                    -100003
#define AUKS_ERROR_LIBRARY_UID_TO_STR             -100004

/* -- BUFFER */
#define AUKS_ERROR_BUFFER_MALLOC                  -100101
#define AUKS_ERROR_BUFFER_REALLOC                 -100102

/* -- ACL */
#define AUKS_ERROR_ACL_INIT                       -100201
#define AUKS_ERROR_ACL_PARSING                    -100202
#define AUKS_ERROR_ACL_IS_FULL                    -100203
#define AUKS_ERROR_ACL_FILE_IS_EMPTY              -100205
#define AUKS_ERROR_ACL_FILE_IS_INVALID            -100206
#define AUKS_ERROR_ACL_RULE_IS_INVALID            -100207

/* -- KERBEROS */

/* -- AUKS CRED */
#define AUKS_ERROR_CRED_INIT_BUFFER_TOO_LARGE     -100301
#define AUKS_ERROR_CRED_INIT_BUFFER_IS_NULL       -100302
#define AUKS_ERROR_CRED_INIT_KRB_CTX_INIT         -100303
#define AUKS_ERROR_CRED_INIT_KRB_AUTH_CTX_INIT    -100304
#define AUKS_ERROR_CRED_INIT_KRB_RD_BUFFER        -100305
#define AUKS_ERROR_CRED_INIT_KRB_RD_PRINC         -100306
#define AUKS_ERROR_CRED_INIT_KRB_PRINC_TOO_LONG   -100307
#define AUKS_ERROR_CRED_INIT_KRB_PRINC_TO_UNAME   -100308
#define AUKS_ERROR_CRED_INIT_GETPWNAM             -100309
#define AUKS_ERROR_CRED_NOT_RENEWABLE             -100310
#define AUKS_ERROR_CRED_LIFETIME_TOO_SHORT        -100311
#define AUKS_ERROR_CRED_EXPIRED                   -100312
#define AUKS_ERROR_CRED_STILL_VALID               -100313



/* -- AUKS CRED REPO*/
#define AUKS_ERROR_CRED_REPO_MUTEX_INIT           -100401
#define AUKS_ERROR_CRED_REPO_MUTEX_LOCK           -100402
#define AUKS_ERROR_CRED_REPO_MUTEX_UNLOCK         -100403
#define AUKS_ERROR_CRED_REPO_CONDITION_INIT       -100404
#define AUKS_ERROR_CRED_REPO_CACHEDIR_IS_NULL     -100405
#define AUKS_ERROR_CRED_REPO_CACHEDIR_INIT        -100406
#define AUKS_ERROR_CRED_REPO_CACHEDIR_OPEN        -100407
#define AUKS_ERROR_CRED_REPO_CCACHE_BUILD         -100408
#define AUKS_ERROR_CRED_REPO_UNLINK               -100409
#define AUKS_ERROR_CRED_REPO_READONLY             -100410
#define AUKS_ERROR_CRED_REPO_UPDATE_INDEX         -100411
#define AUKS_ERROR_CRED_REPO_PACK                 -100412
#define AUKS_ERROR_CRED_REPO_UNPACK               -100413
#define AUKS_ERROR_CRED_REPO_GET_CRED             -100414

/* -- AUKS MESSAGE */
#define AUKS_ERROR_MESSAGE_MALLOC                 -100501
#define AUKS_ERROR_MESSAGE_NULL_BUFFER            -100502
#define AUKS_ERROR_MESSAGE_TYPE_MARSH             -100503
#define AUKS_ERROR_MESSAGE_TYPE_UNMARSH           -100504
#define AUKS_ERROR_MESSAGE_SIZE_MARSH             -100505
#define AUKS_ERROR_MESSAGE_SIZE_UNMARSH           -100506
#define AUKS_ERROR_MESSAGE_DATA_MARSH             -100507
#define AUKS_ERROR_MESSAGE_DATA_UNMARSH           -100508

/* -- AUKS KRB5 CRED */
#define AUKS_ERROR_KRB5_CRED_MALLOC               -100601
#define AUKS_ERROR_KRB5_CRED_INIT_CTX             -100602
#define AUKS_ERROR_KRB5_CRED_OPEN_CC              -100603
#define AUKS_ERROR_KRB5_CRED_READ_CC              -100604
#define AUKS_ERROR_KRB5_CRED_INIT_CC              -100605
#define AUKS_ERROR_KRB5_CRED_NO_TGT_FOUND         -100606
#define AUKS_ERROR_KRB5_CRED_INIT_AUTH_CTX        -100607
#define AUKS_ERROR_KRB5_CRED_MK_CRED              -100608
#define AUKS_ERROR_KRB5_CRED_RD_CRED              -100609
#define AUKS_ERROR_KRB5_CRED_STORE_CRED           -100610
#define AUKS_ERROR_KRB5_CRED_GET_PRINC            -100611
#define AUKS_ERROR_KRB5_CRED_CP_PRINC             -100612
#define AUKS_ERROR_KRB5_CRED_GET_FWD_CRED         -100613
#define AUKS_ERROR_KRB5_CRED_TGT_HAS_EXPIRED      -100614
#define AUKS_ERROR_KRB5_CRED_TGT_RENEW            -100615
#define AUKS_ERROR_KRB5_CRED_TGT_NOT_RENEWABLE    -100616
#define AUKS_ERROR_KRB5_CRED_NO_HOST_SPECIFIED    -100617
#define AUKS_ERROR_KRB5_CRED_GET_FWD              -100618

/* -- AUKS KRB5 STREAM */
#define AUKS_ERROR_KRB5_STREAM_GETSOCKNAME        -100701
#define AUKS_ERROR_KRB5_STREAM_GETPEERNAME        -100702
#define AUKS_ERROR_KRB5_STREAM_INIT_CTX           -100703
#define AUKS_ERROR_KRB5_STREAM_INIT_AUTH_CTX      -100704
#define AUKS_ERROR_KRB5_STREAM_INIT_CC            -100705
#define AUKS_ERROR_KRB5_STREAM_INIT_KT            -100706
#define AUKS_ERROR_KRB5_STREAM_CTX_SETADDR        -100707
#define AUKS_ERROR_KRB5_STREAM_CTX_SETFLAGS       -100708
#define AUKS_ERROR_KRB5_STREAM_CTX_GETPRINC       -100709
#define AUKS_ERROR_KRB5_STREAM_CTX_SETPRINC       -100710
#define AUKS_ERROR_KRB5_STREAM_CTX_SENDAUTH       -100711
#define AUKS_ERROR_KRB5_STREAM_CTX_RECVAUTH       -100712
#define AUKS_ERROR_KRB5_STREAM_CTX_AUTH_TOKEN     -100713
#define AUKS_ERROR_KRB5_STREAM_CP_PRINC           -100714
#define AUKS_ERROR_KRB5_STREAM_PRINC_TOO_LONG     -100715
#define AUKS_ERROR_KRB5_STREAM_CTX_MKPRIV         -100716
#define AUKS_ERROR_KRB5_STREAM_CTX_RDPRIV         -100717
#define AUKS_ERROR_KRB5_STREAM_CTX_WRITE          -100718
#define AUKS_ERROR_KRB5_STREAM_CTX_READ           -100719
#define AUKS_ERROR_KRB5_STREAM_DATA_TOO_LARGE     -100720
#define AUKS_ERROR_KRB5_STREAM_MALLOC             -100721
#define AUKS_ERROR_KRB5_STREAM_NOT_AUTHENTICATED  -100722

/**/


/* -- AUKS ENGINE */
#define AUKS_ERROR_ENGINE_CONFFILE_PARSING        -100801
#define AUKS_ERROR_ENGINE_CONFFILE_INVALID        -100802
#define AUKS_ERROR_ENGINE_CONFFILE_INCOMPLETE     -100803



/*
 * API API API API API API API API API API
 */
#define AUKS_ERROR_API_REQUEST_INIT               -200101
#define AUKS_ERROR_API_REQUEST_PROCESSING         -200102
#define AUKS_ERROR_API_REQUEST_PACK_UID           -200103
#define AUKS_ERROR_API_REQUEST_PACK_CRED          -200104
#define AUKS_ERROR_API_REPLY_PROCESSING           -200105

#define AUKS_ERROR_API_CONNECTION_FAILED          -200201
#define AUKS_ERROR_API_EMPTY_REQUEST              -200202

#define AUKS_ERROR_API_INVALID_REPLY              -200301
#define AUKS_ERROR_API_CORRUPTED_REPLY            -200302

/**/

/**/
/* AUKSD */
#define AUKS_ERROR_DAEMON_INVALID_CONF            -300001
#define AUKS_ERROR_DAEMON_NOT_VALID_SERVER        -300002
#define AUKS_ERROR_DAEMON_STREAM_CREATION         -300003
#define AUKS_ERROR_DAEMON_THREAD_CONFIG           -300004
#define AUKS_ERROR_DAEMON_THREAD_DATA             -300005

#define AUKS_ERROR_DAEMON_REQUEST_UNPACK_UID      -300101
#define AUKS_ERROR_DAEMON_REQUEST_UNPACK_CRED     -300102
#define AUKS_ERROR_DAEMON_REQUEST_DONE            -300103

#define AUKS_ERROR_DAEMON_UNKNOWN_REQUEST         -300201
#define AUKS_ERROR_DAEMON_CORRUPTED_REQUEST       -300202
#define AUKS_ERROR_DAEMON_PROCESSING_REQUEST      -300203
#define AUKS_ERROR_DAEMON_PRINCIPALS_MISMATCH     -300204
#define AUKS_ERROR_DAEMON_NOT_AUTHORIZED          -300205
#define AUKS_ERROR_DAEMON_ADDRESSFUL_CRED         -300206

#define AUKS_ERROR_DAEMON_REPLY_INIT              -300301
#define AUKS_ERROR_DAEMON_REPLY_TRANSMISSION      -300302

#define AUKS_ERROR_DAEMON_RENEW_IN_PROGRESS       -300401



/*!
 * @}
*/
#endif
