/*
 * logging.h - Centralised logging. Originated from the Linux-NTFS project.
 *
 * Copyright (c) 2005      Richard Russon
 * Copyright (c) 2007-2008 Szabolcs Szakacsits
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the NTFS-3G
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _LOGGING_H_
#define _LOGGING_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#include "types.h"


/* Logging levels - Determine what gets logged */
#define NTFS_LOG_LEVEL_DEBUG	(1 <<  0) /* x = 42 */
#define NTFS_LOG_LEVEL_TRACE	(1 <<  1) /* Entering function x() */
#define NTFS_LOG_LEVEL_QUIET	(1 <<  2) /* Quietable output */
#define NTFS_LOG_LEVEL_INFO	(1 <<  3) /* Volume needs defragmenting */
#define NTFS_LOG_LEVEL_VERBOSE	(1 <<  4) /* Forced to continue */
#define NTFS_LOG_LEVEL_PROGRESS	(1 <<  5) /* 54% complete */
#define NTFS_LOG_LEVEL_WARNING	(1 <<  6) /* You should backup before starting */
#define NTFS_LOG_LEVEL_ERROR	(1 <<  7) /* Operation failed, no damage done */
#define NTFS_LOG_LEVEL_PERROR	(1 <<  8) /* Message : standard error description */
#define NTFS_LOG_LEVEL_CRITICAL	(1 <<  9) /* Operation failed,damage may have occurred */
#define NTFS_LOG_LEVEL_ENTER	(1 << 10) /* Enter a function */
#define NTFS_LOG_LEVEL_LEAVE	(1 << 11) /* Leave a function  */

/* Logging style flags - Manage the style of the output */
#define NTFS_LOG_FLAG_PREFIX	(1 << 0) /* Prefix messages with "ERROR: ", etc */
#define NTFS_LOG_FLAG_FILENAME	(1 << 1) /* Show the file origin of the message */
#define NTFS_LOG_FLAG_LINE	(1 << 2) /* Show the line number of the message */
#define NTFS_LOG_FLAG_FUNCTION	(1 << 3) /* Show the function name containing the message */
#define NTFS_LOG_FLAG_ONLYNAME	(1 << 4) /* Only display the filename, not the pathname */

#define DEBUG

/* By default debug and trace messages are compiled into the program,
 * but not displayed.
 */
#ifdef DEBUG
#define ntfs_log_debug(FORMAT, ...) do { printk(FORMAT, ##__VA_ARGS__);} while (0)
#define ntfs_log_trace(FORMAT, ...) do { printk(FORMAT, ##__VA_ARGS__);} while (0)
#define ntfs_log_enter(FORMAT, ...) do { printk(FORMAT, ##__VA_ARGS__);} while (0)
#define ntfs_log_leave(FORMAT, ...) do { printk(FORMAT, ##__VA_ARGS__);} while (0)
#define ntfs_log_critical(FORMAT, ...) do { printk(FORMAT, ##__VA_ARGS__);} while (0)
#define ntfs_log_error(FORMAT, ...) do { printk(FORMAT, ##__VA_ARGS__);} while (0)
#define ntfs_log_info(FORMAT, ...) do { printk(FORMAT, ##__VA_ARGS__);} while (0)
#define ntfs_log_perror(FORMAT, ...) do { printk(FORMAT, ##__VA_ARGS__);} while (0)
#define ntfs_log_progress(FORMAT, ...) do { printk(FORMAT, ##__VA_ARGS__);} while (0)
#define ntfs_log_quiet(FORMAT, ...) do { printk(FORMAT, ##__VA_ARGS__);} while (0)
#define ntfs_log_verbose(FORMAT, ...) do { printk(FORMAT, ##__VA_ARGS__);} while (0)
#define ntfs_log_warning(FORMAT, ...) do { printk(FORMAT, ##__VA_ARGS__);} while (0)
#else
#define ntfs_log_debug(FORMAT, ARGS...)do {} while (0)
#define ntfs_log_trace(FORMAT, ARGS...)do {} while (0)
#define ntfs_log_enter(FORMAT, ARGS...)do {} while (0)
#define ntfs_log_leave(FORMAT, ARGS...)do {} while (0)
#define ntfs_log_leave(FORMAT, ARGS...) do {} while (0)
#define ntfs_log_critical(FORMAT, ARGS...) do {} while (0)
#define ntfs_log_error(FORMAT, ARGS...) do {} while (0)
#define ntfs_log_info(FORMAT, ARGS...) do {} while (0)
#define ntfs_log_perror(FORMAT, ARGS...) do {} while (0)
#define ntfs_log_progress(FORMAT, ARGS...) do {} while (0)
#define ntfs_log_quiet(FORMAT, ARGS...) do {} while (0)
#define ntfs_log_verbose(FORMAT, ARGS...) do {} while (0)
#define ntfs_log_warning(FORMAT, ARGS...) do {} while (0)
#endif /* DEBUG */

#endif /* _LOGGING_H_ */
