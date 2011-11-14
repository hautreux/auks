#ifndef __AUKS_LOG_H_
#define __AUKS_LOG_H_

/*! \addtogroup AUKS_LOG
 *  @{
 */

#include "xternal/xlogger.h"

#ifndef AUKS_LOG_HEADER
#define AUKS_LOG_HEADER ""
#endif

#ifndef AUKS_LOG_BASE_LEVEL
#define AUKS_LOG_BASE_LEVEL 1
#endif

#ifndef AUKS_DEBUG_HEADER
#define AUKS_DEBUG_HEADER ""
#endif

#ifndef AUKS_DEBUG_BASE_LEVEL
#define AUKS_DEBUG_BASE_LEVEL 1
#endif


#define auks_log(h,a...) xverboseN(AUKS_LOG_BASE_LEVEL,		\
				  AUKS_LOG_HEADER h,##a)
#define auks_log2(h,a...) xverboseN(AUKS_LOG_BASE_LEVEL + 1,	\
				   AUKS_LOG_HEADER h,##a)
#define auks_log3(h,a...) xverboseN(AUKS_LOG_BASE_LEVEL + 2,	\
				   AUKS_LOG_HEADER h,##a)

#define auks_debug(h,a...) xdebugN(AUKS_DEBUG_BASE_LEVEL,	\
			      AUKS_LOG_HEADER h,##a)
#define auks_debug2(h,a...) xdebugN(AUKS_DEBUG_BASE_LEVEL + 1,	\
			       AUKS_LOG_HEADER h,##a)
#define auks_debug3(h,a...) xdebugN(AUKS_DEBUG_BASE_LEVEL + 2,	\
			       AUKS_LOG_HEADER h,##a)

#define auks_error auks_log

#define INIT_DEBUG_MARK()    DEBUG("%s : entering",function_name)
#define EXIT_DEBUG_MARK(a)   DEBUG("%s : exiting with status %d",	\
				   function_name,a)

#define INIT_DEBUG2_MARK()   DEBUG2("%s : entering",function_name)
#define EXIT_DEBUG2_MARK(a)  DEBUG2("%s : exiting with status %d",	\
				    function_name,a)

#define INIT_DEBUG3_MARK()   DEBUG3("%s : entering",function_name)
#define EXIT_DEBUG3_MARK(a)  DEBUG3("%s : exiting with status %d",	\
				    function_name,a)

/*!
 * @}
*/


#endif
