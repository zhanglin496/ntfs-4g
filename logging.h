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

#ifndef _NTFS_LOGGING_H_
#define _NTFS_LOGGING_H_

#include "types.h"

extern int ntfs_log_level(void);

enum log_level {
	LOG_ERROR,
	LOG_PERROR,
	LOG_WARNING,
	LOG_DEBUG,
	LOG_TRACE,
	LOG_ENTER,
	LOG_LEAVE,
	LOG_CRITICAL,
	LOG_INFO,
	LOG_QUIET,
	LOG_PROGRESS,
	LOG_VERBOSE,
};

#define DEBUG

#define ntfs_fmt(fmt)  "[%s %d]"": " fmt, __func__, __LINE__

/* By default debug and trace messages are compiled into the program,
 * but not displayed.
 */
#ifdef DEBUG
#define ntfs_log_debug(FORMAT, ...) \
	do { \
		if (ntfs_log_level() >= LOG_DEBUG) \
			printk(ntfs_fmt(FORMAT), ##__VA_ARGS__); \
	} while (0)
#define ntfs_log_trace(FORMAT, ...) \
	do { \
		if (ntfs_log_level() >= LOG_TRACE) \
			printk(ntfs_fmt(FORMAT), ##__VA_ARGS__); \
	} while (0)
#define ntfs_log_enter(FORMAT, ...) \
	do { \
		if (ntfs_log_level() >= LOG_ENTER) \
			printk(ntfs_fmt(FORMAT), ##__VA_ARGS__); \
	} while (0)
#define ntfs_log_leave(FORMAT, ...) \
	do { \
		if (ntfs_log_level() >= LOG_LEAVE) \
			printk(ntfs_fmt(FORMAT), ##__VA_ARGS__); \
	} while (0)
#define ntfs_log_critical(FORMAT, ...) \
	do { \
		if (ntfs_log_level() >= LOG_CRITICAL) \
			printk(ntfs_fmt(FORMAT), ##__VA_ARGS__); \
	} while (0)
#define ntfs_log_error(FORMAT, ...) \
	do { \
		if (ntfs_log_level() >= LOG_ERROR) \
			printk(ntfs_fmt(FORMAT), ##__VA_ARGS__); \
	} while (0)
#define ntfs_log_info(FORMAT, ...) \
	do { \
		if (ntfs_log_level() >= LOG_INFO) \
			printk(ntfs_fmt(FORMAT), ##__VA_ARGS__); \
	} while (0)
#define ntfs_log_perror(FORMAT, ...) \
	do { \
		if (ntfs_log_level() >= LOG_PERROR) \
			printk(ntfs_fmt(FORMAT), ##__VA_ARGS__); \
	} while (0)
#define ntfs_log_progress(FORMAT, ...) \
	do { \
		if (ntfs_log_level() >= LOG_PROGRESS) \
			printk(ntfs_fmt(FORMAT), ##__VA_ARGS__); \
	} while (0)
#define ntfs_log_quiet(FORMAT, ...) \
	do { \
		if (ntfs_log_level() >= LOG_QUIET) \
			printk(ntfs_fmt(FORMAT), ##__VA_ARGS__); \
	} while (0)
#define ntfs_log_verbose(FORMAT, ...) \
	do { \
		if (ntfs_log_level() >= LOG_VERBOSE) \
			printk(ntfs_fmt(FORMAT), ##__VA_ARGS__); \
	} while (0)
#define ntfs_log_warning(FORMAT, ...) \
	do { \
		if (ntfs_log_level() >= LOG_WARNING) \
			printk(ntfs_fmt(FORMAT), ##__VA_ARGS__); \
	} while (0)
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
