/***************************************************************************\
 * auks_engine.h - AUKS engines functions and structures definitions
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
#ifndef __AUKS_ENGINE_H_
#define __AUKS_ENGINE_H_

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#ifndef SYSCONFDIR
#define SYSCONFDIR "/etc"
#endif

#ifndef LOCALSTATEDIR
#define LOCALSTATEDIR "/var"
#endif

#define DEFAULT_AUKS_RETRY_NB           3
#define DEFAULT_AUKS_TIMEOUT           10
#define DEFAULT_AUKS_DELAY             10

#define DEFAULT_AUKS_NAT_TRAVERSAL      0
#define DEFAULT_AUKS_REPLAY_CACHE       1

#define DEFAULT_AUKS_LOGFILE            "/tmp/auksapi.log"
#define DEFAULT_AUKS_LOGLEVEL           0
#define DEFAULT_AUKS_DEBUGFILE          "/tmp/auksapi.log"
#define DEFAULT_AUKS_DEBUGLEVEL         0

#ifndef DEFAULT_AUKS_CONF
#define DEFAULT_AUKS_CONF               SYSCONFDIR "/auks.conf"
#endif

#ifndef DEFAULT_AUKSD_CONF
#define DEFAULT_AUKSD_CONF              SYSCONFDIR "/auks.conf"
#endif

#ifndef DEFAULT_AUKSD_ACLFILE
#define DEFAULT_AUKSD_ACLFILE           SYSCONFDIR "/auks.acl"
#endif

#ifndef DEFAULT_AUKSD_CACHEDIR
#define DEFAULT_AUKSD_CACHEDIR          LOCALSTATEDIR "/cache/auks"
#endif

#define DEFAULT_AUKSD_LOGFILE           "/var/log/auksd.log"
#define DEFAULT_AUKSD_LOGLEVEL          1
#define DEFAULT_AUKSD_DEBUGFILE         "/var/log/auksd.log"
#define DEFAULT_AUKSD_DEBUGLEVEL        0

#define DEFAULT_AUKSD_THREADS_NB       10
#define DEFAULT_AUKSD_QUEUE_SIZE       50
#define DEFAULT_AUKSD_REPO_SIZE       500

#define DEFAULT_AUKSD_CLEAN_DELAY     300

#define DEFAULT_AUKSD_PRIMARY_HOST      "localhost"
#define DEFAULT_AUKSD_PRIMARY_ADDR      NULL
#define DEFAULT_AUKSD_PRIMARY_PORT      "12345"
#define DEFAULT_AUKSD_PRIMARY_PRINC     ""
#define DEFAULT_AUKSD_PRIMARY_KEYTAB    "/etc/auks/auks.keytab"

#define DEFAULT_AUKSD_SECONDARY_HOST    "localhost"
#define DEFAULT_AUKSD_SECONDARY_ADDR    NULL
#define DEFAULT_AUKSD_SECONDARY_PORT    "12345"
#define DEFAULT_AUKSD_SECONDARY_PRINC   ""
#define DEFAULT_AUKSD_SECONDARY_KEYTAB  "/etc/auks/auks.keytab"

#define DEFAULT_AUKSDRENEWER_LOGFILE    "/var/log/auksdrenewer.log"
#define DEFAULT_AUKSDRENEWER_LOGLEVEL   1
#define DEFAULT_AUKSDRENEWER_DEBUGFILE  "/var/log/auksdrenewer.log"
#define DEFAULT_AUKSDRENEWER_DEBUGLEVEL 0
#define DEFAULT_AUKSDRENEWER_DELAY      60
#define DEFAULT_AUKSDRENEWER_MINLIFETIME 300


/*! \addtogroup AUKS_ENGINE
 *  @{
 */

typedef struct auks_engine {

	char *primary_hostname;
	char *primary_address;
	char *primary_port;
	char *primary_principal;

	char *secondary_hostname;
	char *secondary_address;
	char *secondary_port;
	char *secondary_principal;

	char *logfile;
	int loglevel;
	char *debugfile;
	int debuglevel;

	int retries;
	time_t timeout;
	time_t delay;

	int nat_traversal;

	/* for renewer */
	char* renewer_logfile;
	int renewer_loglevel;
	char *renewer_debugfile;
	int renewer_debuglevel;

	time_t renewer_delay;
	time_t renewer_minlifetime;

	char* ccache;

	FILE* logfd;
	FILE* debugfd;

} auks_engine_t;

/*!
 * \brief Initialize auks engine structure
 * \internal
 *
 * \param engine pointer on the structure to initialize
 *
 * \param primary_hostname name of the primary Auks server
 * \param primary_address address of the primary Auks server
 * \param primary_port port of the primary Auks server
 * \param primary_principal kerberos V principal of the primary Auks server
 * \param primary_keytab file that contain the kerberos keytab of the primary 
 *        Auks server
 *
 * \param secondary_hostname name of the secondary Auks server
 * \param secondary_address address of the secondary Auks server
 * \param secondary_port port of the secondary Auks server
 * \param secondary_principal kerberos V principal of the secondary Auks server
 * \param secondary_keytab file that contain the kerberos keytab of 
 *        the secondary Auks server
 *
 * \param logfile file that wil be used to store verbosity
 * \param loglevel verbosity level
 *
 * \param debugfile file that wil be used to store debug data
 * \param debuglevel debug level
 *
 * \param retries number of allowed retries per host
 * \param timeout network actions timeout
 * \param delay time to wait between retries
 * \param nat_traversal NAT traversal mode flag (0=disabled 1=enabled)
 *
 * \param renewer_logfile file that wil be used to store renewer verbosity
 * \param renewer_loglevel renewer verbosity level
 *
 * \param renewer_debugfile file that wil be used to store renewer debug data
 * \param renewer_debuglevel renewer debug level
 *
 * \param renewer_delay time to wait between 2 renewer loops
 * \param renewer_minlifetime min lifetime for a cred to be renewed by the
 *        renewer
 *
 * \retval AUKS_SUCCESS on success
 * \retval AUKS_ERROR on failure
 *  
 */
int
auks_engine_init(auks_engine_t * engine,
		 char *primary_hostname,
		 char *primary_address,
		 char *primary_port,
		 char *primary_principal,
		 char *secondary_hostname,
		 char *secondary_address,
		 char *secondary_port,
		 char *secondary_principal,
		 char *logfile,int loglevel,
		 char *debugfile,int debuglevel,
		 int retries,time_t timeout,
		 time_t delay,int nat_traversal,
		 char* renewer_logfile,int renewer_loglevel,
		 char* renewer_debugfile,int renewer_debuglevel,
		 time_t renewer_delay,
		 time_t renewer_minlifetime);

/*!
 * \brief Initialize auks engine structure from a configuration file
 * \internal
 *
 * \param engine pointer on the structure to initialize
 *
 * \param conf_file configuration file to use
 *
 * \retval AUKS_SUCCESS on success
 * \retval AUKS_ERROR on failure
 *  
 */
int
auks_engine_init_from_config_file(auks_engine_t * engine, char *conf_file);

/*!
 * \brief Set the logfile to use
 *
 * \param engine pointer on the engine structure to use
 * \param logfile log destination file
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 */
int
auks_engine_set_logfile(auks_engine_t* engine,char * logfile);

/*!
 * \brief Set the log level to use
 *
 * \param engine pointer on the engine structure to use
 * \param loglevel level
 *
 * \retval AUKS_SUCCESS
 * \retval AUKS_ERROR
 */
int
auks_engine_set_loglevel(auks_engine_t* engine,int loglevel);

/*!
 * \brief Free auks engine structure contents
 * \internal
 *
 * \param engine pointer on the structure to initialize
 *
 * \retval AUKS_SUCCESS on success
 * \retval AUKS_ERROR on failure
 *  
 */
int auks_engine_free_contents(auks_engine_t * engine);

/*!
 * @}
*/


/*! \addtogroup AUKSD_ENGINE
 *  @{
 */

#include "auks/auks_acl.h"

enum AUKS_SERVER_TYPE {
	PRIMARY = 0,
	SECONDARY,
	UNKNOWN
};

typedef struct auksd_engine {

	char *primary_hostname;
	char *primary_address;
	char *primary_port;
	char *primary_principal;
	char *primary_keytab;

	char *secondary_hostname;
	char *secondary_address;
	char *secondary_port;
	char *secondary_principal;
	char *secondary_keytab;

	char *cachedir;
	auks_acl_t acl;

	int threads_nb;		//!< number of worker thread (default is 10)
	int queue_size;		//!< request queue length
	int repo_size;		//!< repository size (max stored cred nb)

	int clean_delay;

	char *logfile;
	int loglevel;
	char *debugfile;
	int debuglevel;

	int nat_traversal;
	int replay_cache;
	
	enum AUKS_SERVER_TYPE role;

} auksd_engine_t;

/*!
 * \brief Initialize auksd engine structure
 * \internal
 *
 * \param engine pointer on the structure to initialize
 *
 * \param primary_hostname name of the primary Auks server
 * \param primary_address address of the primary Auks server
 * \param primary_port port of the primary Auks server
 * \param primary_principal kerberos V principal of the primary Auks server
 * \param primary_keytab file that contain the kerberos keytab of the primary 
 *        Auks server
 *
 * \param secondary_hostname name of the secondary Auks server
 * \param secondary_address address of the secondary Auks server
 * \param secondary_port port of the secondary Auks server
 * \param secondary_principal kerberos V principal of the secondary Auks server
 * \param secondary_keytab file that contain the kerberos keytab of the 
 *        secondary Auks server
 *
 * \param cachedir directory that contains cached credetials
 * \param acl_file file that contains ACL rules of the server
 *
 * \param logfile file that wil be used to store verbosity
 * \param loglevel verbosity level
 *
 * \param debugfile file that wil be used to store debug data
 * \param debuglevel debug level
 *
 * \param worker_nb number of worker to launch for request processing
 * \param queue_size default size of request queue
 * \param repo_size default size of the repository
 * \param clean_delay delay beetween each clean stages
 * \param nat_traversal NAT traversal mode flag (0=disabled 1=enabled)
 * \param replay cache replay cache usage flag (0=disabled 1=enabled)
 *
 * \retval  0 on success
 * \retval -1 on failure
 *  
 */
int
auksd_engine_init(auksd_engine_t * engine,
		  char *primary_hostname,
		  char *primary_address,
		  char *primary_port,
		  char *primary_principal,
		  char *primary_keytab,
		  char *secondary_hostname,
		  char *secondary_address,
		  char *secondary_port,
		  char *secondary_principal,
		  char *secondary_keytab,
		  char *cachedir,
		  char *acl_file,
		  char *logfile,
		  int loglevel,
		  char *debugfile,
		  int debuglevel,
		  int worker_nb,
		  int queue_size, int repo_size,
		  time_t clean_delay,
		  int nat_traversal,
		  int replay_cache);

/*!
 * \brief Initialize auksd engine structure from a configuration file
 * \internal
 *
 * \param engine pointer on the structure to initialize
 *
 * \param conf_file configuration file to use
 *
 * \retval  0 on success
 * \retval -1 on failure
 *  
 */
int
auksd_engine_init_from_config_file(auksd_engine_t * engine,
				   char *conf_file);


/*!
 * \brief Free auksd engine structure contents
 * \internal
 *
 * \param engine pointer on the structure to initialize
 *
 * \retval  0 on success
 * \retval -1 on failure
 *  
 */
int auksd_engine_free_contents(auksd_engine_t * engine);

/*!
 * @}
*/

#endif
