/**
 * acls.c - General function to process NTFS ACLs
 *
 *	This module is part of ntfs-3g library, but may also be
 *	integrated in tools running over Linux or Windows
 *
 * Copyright (c) 2007-2016 Jean-Pierre Andre
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


#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#include <linux/stat.h>

#include "types.h"
#include "layout.h"
#include "security.h"
#include "acls.h"
#include "misc.h"

static int errno;


/*
 *	A few useful constants
 */

/*
 *		null SID (S-1-0-0)
 */

static const char nullsidbytes[] = {
		1,		/* revision */
		1,		/* auth count */
		0, 0, 0, 0, 0, 0,	/* base */
		0, 0, 0, 0 	/* 1st level */
	};

static const SID *nullsid = (const SID*)nullsidbytes;

/*
 *		SID for world  (S-1-1-0)
 */

static const char worldsidbytes[] = {
		1,		/* revision */
		1,		/* auth count */
		0, 0, 0, 0, 0, 1,	/* base */
		0, 0, 0, 0	/* 1st level */
} ;

const SID *worldsid = (const SID*)worldsidbytes;

/*
 *		SID for authenticated user (S-1-5-11)
 */

static const char authsidbytes[] = {
		1,		/* revision */
		1,		/* auth count */
		0, 0, 0, 0, 0, 5,	/* base */
		11, 0, 0, 0	/* 1st level */ 
};
	        
static const SID *authsid = (const SID*)authsidbytes;

/*
 *		SID for administrator
 */

static const char adminsidbytes[] = {
		1,		/* revision */
		2,		/* auth count */
		0, 0, 0, 0, 0, 5,	/* base */
		32, 0, 0, 0,	/* 1st level */
		32, 2, 0, 0	/* 2nd level */
};

const SID *adminsid = (const SID*)adminsidbytes;

/*
 *		SID for system
 */

static const char systemsidbytes[] = {
		1,		/* revision */
		1,		/* auth count */
		0, 0, 0, 0, 0, 5,	/* base */
		18, 0, 0, 0 	/* 1st level */
	};

static const SID *systemsid = (const SID*)systemsidbytes;

/*
 *		SID for generic creator-owner
 *		S-1-3-0
 */

static const char ownersidbytes[] = {
		1,		/* revision */
		1,		/* auth count */
		0, 0, 0, 0, 0, 3,	/* base */
		0, 0, 0, 0	/* 1st level */
} ;

static const SID *ownersid = (const SID*)ownersidbytes;

/*
 *		SID for generic creator-group
 *		S-1-3-1
 */

static const char groupsidbytes[] = {
		1,		/* revision */
		1,		/* auth count */
		0, 0, 0, 0, 0, 3,	/* base */
		1, 0, 0, 0	/* 1st level */
} ;

static const SID *groupsid = (const SID*)groupsidbytes;

/*
 *		Determine the size of a SID
 */

int ntfs_sid_size(const SID * sid)
{
	return (sid->sub_authority_count * 4 + 8);
}

/*
 *		Test whether two SID are equal
 */

BOOL ntfs_same_sid(const SID *first, const SID *second)
{
	int size;

	size = ntfs_sid_size(first);
	return ((ntfs_sid_size(second) == size)
		&& !memcmp(first, second, size));
}

/*
 *		Test whether a SID means "world user"
 *	Local users group recognized as world
 *	Also interactive users so that /Users/Public is world accessible,
 *	but only if Posix ACLs are not enabled (if Posix ACLs are enabled,
 *	access to /Users/Public should be done by defining interactive users
 *	as a mapped group.)
 */

static int is_world_sid(const SID * usid)
{
	return (
	     /* check whether S-1-1-0 : world */
	       ((usid->sub_authority_count == 1)
	    && (usid->identifier_authority.high_part ==  const_cpu_to_be16(0))
	    && (usid->identifier_authority.low_part ==  const_cpu_to_be32(1))
	    && (usid->sub_authority[0] == const_cpu_to_le32(0)))

	     /* check whether S-1-5-32-545 : local user */
	  ||   ((usid->sub_authority_count == 2)
	    && (usid->identifier_authority.high_part ==  const_cpu_to_be16(0))
	    && (usid->identifier_authority.low_part ==  const_cpu_to_be32(5))
	    && (usid->sub_authority[0] == const_cpu_to_le32(32))
	    && (usid->sub_authority[1] == const_cpu_to_le32(545)))

	     /* check whether S-1-5-11 : authenticated user */
	  ||   ((usid->sub_authority_count == 1)
	    && (usid->identifier_authority.high_part ==  const_cpu_to_be16(0))
	    && (usid->identifier_authority.low_part ==  const_cpu_to_be32(5))
	    && (usid->sub_authority[0] == const_cpu_to_le32(11)))

#if !POSIXACLS
	     /* check whether S-1-5-4 : interactive user */
	  ||   ((usid->sub_authority_count == 1)
	    && (usid->identifier_authority.high_part ==  const_cpu_to_be16(0))
	    && (usid->identifier_authority.low_part ==  const_cpu_to_be32(5))
	    && (usid->sub_authority[0] == const_cpu_to_le32(4)))
#endif /* !POSIXACLS */
		);
}

/*
 *		Test whether a SID means "some user (or group)"
 *	Currently we only check for S-1-5-21... but we should
 *	probably test for other configurations
 */

BOOL ntfs_is_user_sid(const SID *usid)
{
	return ((usid->sub_authority_count == 5)
	    && (usid->identifier_authority.high_part ==  const_cpu_to_be16(0))
	    && (usid->identifier_authority.low_part ==  const_cpu_to_be32(5))
	    && (usid->sub_authority[0] ==  const_cpu_to_le32(21)));
}

/*
 *		Test whether a SID means "some special group"
 *	Currently we only check for a few S-1-5-n but we should
 *	probably test for other configurations.
 *
 *	This is useful for granting access to /Users/Public for
 *	specific users when the Posix ACLs are enabled.
 */

static BOOL ntfs_known_group_sid(const SID *usid)
{
			/* count == 1 excludes S-1-5-5-X-Y (logon) */
	return ((usid->sub_authority_count == 1)
	    && (usid->identifier_authority.high_part ==  const_cpu_to_be16(0))
	    && (usid->identifier_authority.low_part ==  const_cpu_to_be32(5))
	    && (le32_to_cpu(usid->sub_authority[0]) >=  1)
	    && (le32_to_cpu(usid->sub_authority[0]) <=  6));
}

/*
 *		Determine the size of a security attribute
 *	whatever the order of fields
 */

unsigned int ntfs_attr_size(const char *attr)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const ACL *pdacl;
	const ACL *psacl;
	const SID *psid;
	unsigned int offdacl;
	unsigned int offsacl;
	unsigned int offowner;
	unsigned int offgroup;
	unsigned int endsid;
	unsigned int endacl;
	unsigned int attrsz;

	phead = (const SECURITY_DESCRIPTOR_RELATIVE*)attr;
		/*
		 * First check group, which is the last field in all descriptors
		 * we build, and in most descriptors built by Windows
		 */
	attrsz = sizeof(SECURITY_DESCRIPTOR_RELATIVE);
	offgroup = le32_to_cpu(phead->group);
	if (offgroup >= attrsz) {
			/* find end of GSID */
		psid = (const SID*)&attr[offgroup];
		endsid = offgroup + ntfs_sid_size(psid);
		if (endsid > attrsz) attrsz = endsid;
	}
	offowner = le32_to_cpu(phead->owner);
	if (offowner >= attrsz) {
			/* find end of USID */
		psid = (const SID*)&attr[offowner];
		endsid = offowner + ntfs_sid_size(psid);
		attrsz = endsid;
	}
	offsacl = le32_to_cpu(phead->sacl);
	if (offsacl >= attrsz) {
			/* find end of SACL */
		psacl = (const ACL*)&attr[offsacl];
		endacl = offsacl + le16_to_cpu(psacl->size);
		if (endacl > attrsz)
			attrsz = endacl;
	}


		/* find end of DACL */
	offdacl = le32_to_cpu(phead->dacl);
	if (offdacl >= attrsz) {
		pdacl = (const ACL*)&attr[offdacl];
		endacl = offdacl + le16_to_cpu(pdacl->size);
		if (endacl > attrsz)
			attrsz = endacl;
	}
	return (attrsz);
}

/**
 * ntfs_valid_sid - determine if a SID is valid
 * @sid:	SID for which to determine if it is valid
 *
 * Determine if the SID pointed to by @sid is valid.
 *
 * Return TRUE if it is valid and FALSE otherwise.
 */
BOOL ntfs_valid_sid(const SID *sid)
{
	return sid && sid->revision == SID_REVISION &&
		sid->sub_authority_count <= SID_MAX_SUB_AUTHORITIES;
}

/*
 *		Check whether a SID is acceptable for an implicit
 *	mapping pattern.
 *	It should have been already checked it is a valid user SID.
 *
 *	The last authority reference has to be >= 1000 (Windows usage)
 *	and <= 0x7fffffff, so that 30 bits from a uid and 30 more bits
 *      from a gid an be inserted with no overflow.
 */

BOOL ntfs_valid_pattern(const SID *sid)
{
	int cnt;
	u32 auth;
	le32 leauth;

	cnt = sid->sub_authority_count;
	leauth = sid->sub_authority[cnt-1];
	auth = le32_to_cpu(leauth);
	return ((auth >= 1000) && (auth <= 0x7fffffff));
}

static int buildacls(char *secattr, int offs, mode_t mode, int isdir,
	       const SID * usid, const SID * gsid)
{
	ACL *pacl;
	ACCESS_ALLOWED_ACE *pgace;
	ACCESS_ALLOWED_ACE *pdace;
	BOOL adminowns;
	BOOL groupowns;
	ACE_FLAGS gflags;
	int pos;
	int acecnt;
	int usidsz;
	int gsidsz;
	int wsidsz;
	int asidsz;
	int ssidsz;
	int nsidsz;
	le32 grants;
	le32 denials;

	usidsz = ntfs_sid_size(usid);
	gsidsz = ntfs_sid_size(gsid);
	wsidsz = ntfs_sid_size(worldsid);
	asidsz = ntfs_sid_size(adminsid);
	ssidsz = ntfs_sid_size(systemsid);
	adminowns = ntfs_same_sid(usid, adminsid)
	         || ntfs_same_sid(gsid, adminsid);
	groupowns = !adminowns && ntfs_same_sid(usid, gsid);

	/* ACL header */
	pacl = (ACL*)&secattr[offs];
	pacl->revision = ACL_REVISION;
	pacl->alignment1 = 0;
	pacl->size = cpu_to_le16(sizeof(ACL) + usidsz + 8);
	pacl->ace_count = const_cpu_to_le16(1);
	pacl->alignment2 = const_cpu_to_le16(0);
	pos = sizeof(ACL);
	acecnt = 0;

	/* compute a grant ACE for owner */
	/* this ACE will be inserted after denial for owner */

	grants = OWNER_RIGHTS;
	if (isdir) {
		gflags = DIR_INHERITANCE;
		if (mode & S_IXUSR)
			grants |= DIR_EXEC;
		if (mode & S_IWUSR)
			grants |= DIR_WRITE;
		if (mode & S_IRUSR)
			grants |= DIR_READ;
	} else {
		gflags = FILE_INHERITANCE;
		if (mode & S_IXUSR)
			grants |= FILE_EXEC;
		if (mode & S_IWUSR)
			grants |= FILE_WRITE;
		if (mode & S_IRUSR)
			grants |= FILE_READ;
	}

	/* a possible ACE to deny owner what he/she would */
	/* induely get from administrator, group or world */
        /* unless owner is administrator or group */

	denials = const_cpu_to_le32(0);
	pdace = (ACCESS_DENIED_ACE*) &secattr[offs + pos];
	if (!adminowns) {
		if (!groupowns) {
			if (isdir) {
				pdace->flags = DIR_INHERITANCE;
				if (mode & (S_IXGRP | S_IXOTH))
					denials |= DIR_EXEC;
				if (mode & (S_IWGRP | S_IWOTH))
					denials |= DIR_WRITE;
				if (mode & (S_IRGRP | S_IROTH))
					denials |= DIR_READ;
			} else {
				pdace->flags = FILE_INHERITANCE;
				if (mode & (S_IXGRP | S_IXOTH))
					denials |= FILE_EXEC;
				if (mode & (S_IWGRP | S_IWOTH))
					denials |= FILE_WRITE;
				if (mode & (S_IRGRP | S_IROTH))
					denials |= FILE_READ;
			}
		} else {
			if (isdir) {
				pdace->flags = DIR_INHERITANCE;
				if ((mode & S_IXOTH) && !(mode & S_IXGRP))
					denials |= DIR_EXEC;
				if ((mode & S_IWOTH) && !(mode & S_IWGRP))
					denials |= DIR_WRITE;
				if ((mode & S_IROTH) && !(mode & S_IRGRP))
					denials |= DIR_READ;
			} else {
				pdace->flags = FILE_INHERITANCE;
				if ((mode & S_IXOTH) && !(mode & S_IXGRP))
					denials |= FILE_EXEC;
				if ((mode & S_IWOTH) && !(mode & S_IWGRP))
					denials |= FILE_WRITE;
				if ((mode & S_IROTH) && !(mode & S_IRGRP))
					denials |= FILE_READ;
			}
		}
		denials &= ~grants;
		if (denials) {
			pdace->type = ACCESS_DENIED_ACE_TYPE;
			pdace->size = cpu_to_le16(usidsz + 8);
			pdace->mask = denials;
			memcpy((char*)&pdace->sid, usid, usidsz);
			pos += usidsz + 8;
			acecnt++;
		}
	}
		/*
		 * for directories, a world execution denial
		 * inherited to plain files
		 */

	if (isdir) {
		pdace = (ACCESS_DENIED_ACE*) &secattr[offs + pos];
			pdace->type = ACCESS_DENIED_ACE_TYPE;
			pdace->flags = INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE;
			pdace->size = cpu_to_le16(wsidsz + 8);
			pdace->mask = FILE_EXEC;
			memcpy((char*)&pdace->sid, worldsid, wsidsz);
			pos += wsidsz + 8;
			acecnt++;
	}


		/* now insert grants to owner */
	pgace = (ACCESS_ALLOWED_ACE*) &secattr[offs + pos];
	pgace->type = ACCESS_ALLOWED_ACE_TYPE;
	pgace->size = cpu_to_le16(usidsz + 8);
	pgace->flags = gflags;
	pgace->mask = grants;
	memcpy((char*)&pgace->sid, usid, usidsz);
	pos += usidsz + 8;
	acecnt++;

	/* a grant ACE for group */
	/* unless group has the same rights as world */
	/* but present if group is owner or owner is administrator */
	/* this ACE will be inserted after denials for group */

	if (adminowns
	    || (((mode >> 3) ^ mode) & 7)) {
		grants = WORLD_RIGHTS;
		if (isdir) {
			gflags = DIR_INHERITANCE;
			if (mode & S_IXGRP)
				grants |= DIR_EXEC;
			if (mode & S_IWGRP)
				grants |= DIR_WRITE;
			if (mode & S_IRGRP)
				grants |= DIR_READ;
		} else {
			gflags = FILE_INHERITANCE;
			if (mode & S_IXGRP)
				grants |= FILE_EXEC;
			if (mode & S_IWGRP)
				grants |= FILE_WRITE;
			if (mode & S_IRGRP)
				grants |= FILE_READ;
		}

		/* a possible ACE to deny group what it would get from world */
		/* or administrator, unless owner is administrator or group */

		denials = const_cpu_to_le32(0);
		pdace = (ACCESS_ALLOWED_ACE*)&secattr[offs + pos];
		if (!adminowns && !groupowns) {
			if (isdir) {
				pdace->flags = DIR_INHERITANCE;
				if (mode & S_IXOTH)
					denials |= DIR_EXEC;
				if (mode & S_IWOTH)
					denials |= DIR_WRITE;
				if (mode & S_IROTH)
					denials |= DIR_READ;
			} else {
				pdace->flags = FILE_INHERITANCE;
				if (mode & S_IXOTH)
					denials |= FILE_EXEC;
				if (mode & S_IWOTH)
					denials |= FILE_WRITE;
				if (mode & S_IROTH)
					denials |= FILE_READ;
			}
			denials &= ~(grants | OWNER_RIGHTS);
			if (denials) {
				pdace->type = ACCESS_DENIED_ACE_TYPE;
				pdace->size = cpu_to_le16(gsidsz + 8);
				pdace->mask = denials;
				memcpy((char*)&pdace->sid, gsid, gsidsz);
				pos += gsidsz + 8;
				acecnt++;
			}
		}

		if (adminowns
		   || groupowns
		   || ((mode >> 3) & ~mode & 7)) {
				/* now insert grants to group */
				/* if more rights than other */
			pgace = (ACCESS_ALLOWED_ACE*)&secattr[offs + pos];
			pgace->type = ACCESS_ALLOWED_ACE_TYPE;
			pgace->flags = gflags;
			pgace->size = cpu_to_le16(gsidsz + 8);
			pgace->mask = grants;
			memcpy((char*)&pgace->sid, gsid, gsidsz);
			pos += gsidsz + 8;
			acecnt++;
		}
	}

	/* an ACE for world users */

	pgace = (ACCESS_ALLOWED_ACE*)&secattr[offs + pos];
	pgace->type = ACCESS_ALLOWED_ACE_TYPE;
	grants = WORLD_RIGHTS;
	if (isdir) {
		pgace->flags = DIR_INHERITANCE;
		if (mode & S_IXOTH)
			grants |= DIR_EXEC;
		if (mode & S_IWOTH)
			grants |= DIR_WRITE;
		if (mode & S_IROTH)
			grants |= DIR_READ;
	} else {
		pgace->flags = FILE_INHERITANCE;
		if (mode & S_IXOTH)
			grants |= FILE_EXEC;
		if (mode & S_IWOTH)
			grants |= FILE_WRITE;
		if (mode & S_IROTH)
			grants |= FILE_READ;
	}
	pgace->size = cpu_to_le16(wsidsz + 8);
	pgace->mask = grants;
	memcpy((char*)&pgace->sid, worldsid, wsidsz);
	pos += wsidsz + 8;
	acecnt++;

	/* an ACE for administrators */
	/* always full access */

	pgace = (ACCESS_ALLOWED_ACE*)&secattr[offs + pos];
	pgace->type = ACCESS_ALLOWED_ACE_TYPE;
	if (isdir)
		pgace->flags = DIR_INHERITANCE;
	else
		pgace->flags = FILE_INHERITANCE;
	pgace->size = cpu_to_le16(asidsz + 8);
	grants = OWNER_RIGHTS | FILE_READ | FILE_WRITE | FILE_EXEC;
	pgace->mask = grants;
	memcpy((char*)&pgace->sid, adminsid, asidsz);
	pos += asidsz + 8;
	acecnt++;

	/* an ACE for system (needed ?) */
	/* always full access */

	pgace = (ACCESS_ALLOWED_ACE*)&secattr[offs + pos];
	pgace->type = ACCESS_ALLOWED_ACE_TYPE;
	if (isdir)
		pgace->flags = DIR_INHERITANCE;
	else
		pgace->flags = FILE_INHERITANCE;
	pgace->size = cpu_to_le16(ssidsz + 8);
	grants = OWNER_RIGHTS | FILE_READ | FILE_WRITE | FILE_EXEC;
	pgace->mask = grants;
	memcpy((char*)&pgace->sid, systemsid, ssidsz);
	pos += ssidsz + 8;
	acecnt++;

	/* a null ACE to hold special flags */
	/* using the same representation as cygwin */

	if (mode & (S_ISVTX | S_ISGID | S_ISUID)) {
		nsidsz = ntfs_sid_size(nullsid);
		pgace = (ACCESS_ALLOWED_ACE*)&secattr[offs + pos];
		pgace->type = ACCESS_ALLOWED_ACE_TYPE;
		pgace->flags = NO_PROPAGATE_INHERIT_ACE;
		pgace->size = cpu_to_le16(nsidsz + 8);
		grants = const_cpu_to_le32(0);
		if (mode & S_ISUID)
			grants |= FILE_APPEND_DATA;
		if (mode & S_ISGID)
			grants |= FILE_WRITE_DATA;
		if (mode & S_ISVTX)
			grants |= FILE_READ_DATA;
		pgace->mask = grants;
		memcpy((char*)&pgace->sid, nullsid, nsidsz);
		pos += nsidsz + 8;
		acecnt++;
	}

	/* fix ACL header */
	pacl->size = cpu_to_le16(pos);
	pacl->ace_count = cpu_to_le16(acecnt);
	return (pos);
}

char *ntfs_build_descr(mode_t mode,
			int isdir, const SID * usid, const SID * gsid)
{
	int newattrsz;
	SECURITY_DESCRIPTOR_RELATIVE *pnhead;
	char *newattr;
	int aclsz;
	int usidsz;
	int gsidsz;
	int wsidsz;
	int asidsz;
	int ssidsz;

	usidsz = ntfs_sid_size(usid);
	gsidsz = ntfs_sid_size(gsid);
	wsidsz = ntfs_sid_size(worldsid);
	asidsz = ntfs_sid_size(adminsid);
	ssidsz = ntfs_sid_size(systemsid);

	/* allocate enough space for the new security attribute */
	newattrsz = sizeof(SECURITY_DESCRIPTOR_RELATIVE)	/* header */
	    + usidsz + gsidsz	/* usid and gsid */
	    + sizeof(ACL)	/* acl header */
	    + 2*(8 + usidsz)	/* two possible ACE for user */
	    + 2*(8 + gsidsz)	/* two possible ACE for group */
	    + 8 + wsidsz	/* one ACE for world */
	    + 8 + asidsz 	/* one ACE for admin */
	    + 8 + ssidsz;	/* one ACE for system */
	if (isdir)			/* a world denial for directories */
		newattrsz += 8 + wsidsz;
	if (mode & 07000)	/* a NULL ACE for special modes */
		newattrsz += 8 + ntfs_sid_size(nullsid);
	newattr = (char*)ntfs_malloc(newattrsz);
	if (newattr) {
		/* build the main header part */
		pnhead = (SECURITY_DESCRIPTOR_RELATIVE*) newattr;
		pnhead->revision = SECURITY_DESCRIPTOR_REVISION;
		pnhead->alignment = 0;
			/*
			 * The flag SE_DACL_PROTECTED prevents the ACL
			 * to be changed in an inheritance after creation
			 */
		pnhead->control = SE_DACL_PRESENT | SE_DACL_PROTECTED
				    | SE_SELF_RELATIVE;
			/*
			 * Windows prefers ACL first, do the same to
			 * get the same hash value and avoid duplication
			 */
		/* build permissions */
		aclsz = buildacls(newattr,
			  sizeof(SECURITY_DESCRIPTOR_RELATIVE),
			  mode, isdir, usid, gsid);
		if (((int)sizeof(SECURITY_DESCRIPTOR_RELATIVE)
				+ aclsz + usidsz + gsidsz) <= newattrsz) {
			/* append usid and gsid */
			memcpy(&newattr[sizeof(SECURITY_DESCRIPTOR_RELATIVE)
				 + aclsz], usid, usidsz);
			memcpy(&newattr[sizeof(SECURITY_DESCRIPTOR_RELATIVE)
				+ aclsz + usidsz], gsid, gsidsz);
			/* positions of ACL, USID and GSID into header */
			pnhead->owner =
			    cpu_to_le32(sizeof(SECURITY_DESCRIPTOR_RELATIVE)
				 + aclsz);
			pnhead->group =
			    cpu_to_le32(sizeof(SECURITY_DESCRIPTOR_RELATIVE)
				 + aclsz + usidsz);
			pnhead->sacl = const_cpu_to_le32(0);
			pnhead->dacl =
			    const_cpu_to_le32(sizeof(SECURITY_DESCRIPTOR_RELATIVE));
		} else {
			/* hope error was detected before overflowing */
			free(newattr);
			newattr = (char*)NULL;
			ntfs_log_error("Security descriptor is longer than expected\n");
			errno = EIO;
		}
	} else
		errno = ENOMEM;
	return (newattr);
}

void ntfs_free_mapping(struct MAPPING *mapping[])
{
	struct MAPPING *user;
	struct MAPPING *group;

		/* free user mappings */
	while (mapping[MAPUSERS]) {
		user = mapping[MAPUSERS];
		/* do not free SIDs used for group mappings */
		group = mapping[MAPGROUPS];
		while (group && (group->sid != user->sid))
			group = group->next;
		if (!group)
			free(user->sid);
			/* free group list if any */
		if (user->grcnt)
			free(user->groups);
			/* unchain item and free */
		mapping[MAPUSERS] = user->next;
		free(user);
	}
		/* free group mappings */
	while (mapping[MAPGROUPS]) {
		group = mapping[MAPGROUPS];
		free(group->sid);
			/* unchain item and free */
		mapping[MAPGROUPS] = group->next;
		free(group);
	}
}

BOOL ntfs_valid_descr(const char *securattr, unsigned int attrsz)
{
	return true;
}
