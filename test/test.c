/*
 * This file is released under the GPL.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <grp.h>

#include "../ugidctl.h"

void check(int rc, int error, const char *msg)
{
	if (rc == -1 ? (error == errno ? 0 : 1)
	             : (error == 0 ? 0 : 1))
	{
		printf("test: %s: FAIL\n", msg);
		exit(1);
	}
	else
	{
		printf("test: %s: OK\n", msg);
	}
}

int main(void)
{
	int fd;
	struct ugidctl_key_rq *key;
	struct ugidctl_add_rq *add_uids;
	struct ugidctl_add_rq *add_gids;
	struct ugidctl_setid_rq *setid;
	struct ugidctl_setgroups_rq *setgids;
	gid_t gids[3];
	gid_t gid;
	uid_t uid;

	// open device
	check((fd = open("/dev/ugidctl", O_RDONLY)), 0, "device open ok");

	// get access key
	key = alloca(sizeof(*key));
	check(ioctl(fd, UGIDCTLIO_GETKEY, key), 0, "ugidctl_getkey ok");
	check(ioctl(fd, UGIDCTLIO_GETKEY, NULL), EFAULT, "ugidctl_getkey fault");

	// allow setuid to 65533, 65534, 65535
	add_uids = alloca(sizeof(*add_uids) + 3 * sizeof(uid_t));
	add_uids->count = 3;
	add_uids->uid_list[0] = 65533;
	add_uids->uid_list[1] = 65534;
	add_uids->uid_list[2] = 65535;
	check(ioctl(fd, UGIDCTLIO_ADDUIDLIST, add_uids), 0, "ugidctl_adduidlist(65533, 65534, 65535) ok");

	// allow setgid/setgroups to 65533, 65534, 65535
	add_gids = alloca(sizeof(*add_gids) + 3 * sizeof(gid_t));
	add_gids->count = 3;
	add_gids->gid_list[0] = 65533;
	add_gids->gid_list[1] = 65534;
	add_gids->gid_list[2] = 65535;
	check(ioctl(fd, UGIDCTLIO_ADDGIDLIST, add_gids), 0, "ugidctl_addgidlist(65533, 65534, 65535) ok");

	// setuidlist/setgidlist fault
	check(ioctl(fd, UGIDCTLIO_ADDUIDLIST, NULL), EFAULT, "ugidctl_adduidlist fault");
	check(ioctl(fd, UGIDCTLIO_ADDGIDLIST, NULL), EFAULT, "ugidctl_addgidlist fault");

	// become user 65535
	uid = 65535;
	gid = 65535;
	check(setgroups(1, &gid), 0, "sys_setgroups(1, 65535) ok");
	check(setgid(gid), 0, "sys_setgid(65535) ok");
	check(setuid(uid), 0, "sys_setuid(65535) ok");

	// try to become user 65534
	uid = 65534;
	gid = 65534;
	check(setgroups(1, &gid), EPERM, "sys_setgroups(65534) perm");
	check(setgid(gid), EPERM, "sys_setgid(65534) perm");
	check(setuid(uid), EPERM, "sys_setuid(65534) perm");

	// get access key: EPERM
	check(ioctl(fd, UGIDCTLIO_GETKEY, key), EPERM, "ugidctl_getkey perm");

	// setuidlist/setgidlist: EPERM
	check(ioctl(fd, UGIDCTLIO_ADDUIDLIST, add_uids), EPERM, "ugidctl_adduidlist perm");
	check(ioctl(fd, UGIDCTLIO_ADDGIDLIST, add_gids), EPERM, "ugidctl_addgidlist perm");

	// init setuid/setgid/setgroups request structs
	setid = alloca(sizeof(*setid));
	memcpy(setid->key, key->key, sizeof(key->key));
	setgids = alloca(sizeof(*setgids) + 3 * sizeof(gid_t));
	memcpy(setgids->key, key->key, sizeof(key->key));

	// become user 65533
	setid->uid = 65533;
	check(ioctl(fd, UGIDCTLIO_SETUID, setid), 0, "ugidctl_setuid(65533) ok");
	setid->gid = 65533;
	check(ioctl(fd, UGIDCTLIO_SETGID, setid), 0, "ugidctl_setgid(65533) ok");
	setgids->count = 1;
	setgids->list[0] = 65533;
	check(ioctl(fd, UGIDCTLIO_SETGROUPS, setgids), 0, "ugidctl_setgroups([65533]) ok");

	check((getuid() == 65533) ? 0 : -1, 0, "sys_getuid() == 65533");
	check((getgid() == 65533) ? 0 : -1, 0, "sys_getgid() == 65533");
	check((getgroups(1, &gid) == 1) && (gid == 65533) ? 0 : -1, 0, "sys_getgroups() == [65533]");

	// become user 65534
	setid->uid = 65534;
	check(ioctl(fd, UGIDCTLIO_SETUID, setid), 0, "ugidctl_setuid(65534) ok");
	setid->gid = 65534;
	check(ioctl(fd, UGIDCTLIO_SETGID, setid), 0, "ugidctl_setgid(65534) ok");
	setgids->count = 1;
	setgids->list[0] = 65534;
	check(ioctl(fd, UGIDCTLIO_SETGROUPS, setgids), 0, "ugidctl_setgroups([65534]) ok");

	check((getuid() == 65534) ? 0 : -1, 0, "sys_getuid() == 65534");
	check((getgid() == 65534) ? 0 : -1, 0, "sys_getgid() == 65534");
	check((getgroups(1, &gid) == 1) && (gid == 65534) ? 0 : -1, 0, "sys_getgroups() == [65534]");

	// become user 65535
	setid->uid = 65535;
	check(ioctl(fd, UGIDCTLIO_SETUID, setid), 0, "ugidctl_setuid(65535) ok");
	setid->gid = 65535;
	check(ioctl(fd, UGIDCTLIO_SETGID, setid), 0, "ugidctl_setgid(65535) ok");
	setgids->count = 3;
	setgids->list[0] = 65535;
	setgids->list[1] = 65534;
	setgids->list[2] = 65533;
	check(ioctl(fd, UGIDCTLIO_SETGROUPS, setgids), 0, "ugidctl_setgroups([65535, 65534, 65533]) ok");

	check((getuid() == 65535) ? 0 : -1, 0, "sys_getuid() == 65535");
	check((getgid() == 65535) ? 0 : -1, 0, "sys_getgid() == 65535");
	check((getgroups(3, gids) == 3) ? 0 : -1, 0, "sys_getgroups() == 3");
	check(gids[0] == 65535 || gids[1] == 65535 || gids[2] == 65535 ? 0 : -1, 0, "sys_getgroups() contains 65535");
	check(gids[0] == 65534 || gids[1] == 65534 || gids[2] == 65534 ? 0 : -1, 0, "sys_getgroups() contains 65534");
	check(gids[0] == 65533 || gids[1] == 65533 || gids[2] == 65533 ? 0 : -1, 0, "sys_getgroups() contains 65533");

	// become user 100
	setid->uid = 100;
	check(ioctl(fd, UGIDCTLIO_SETUID, setid), EPERM, "ugidctl_setuid(100) perm");
	setid->gid = 100;
	check(ioctl(fd, UGIDCTLIO_SETGID, setid), EPERM, "ugidctl_setgid(100) perm");
	setgids->count = 1;
	setgids->list[0] = 100;
	check(ioctl(fd, UGIDCTLIO_SETGROUPS, setgids), EPERM, "ugidctl_setgroups([100]) perm");
	setgids->count = 2;
	setgids->list[0] = 65535;
	setgids->list[1] = 100;
	check(ioctl(fd, UGIDCTLIO_SETGROUPS, setgids), EPERM, "ugidctl_setgroups([65535, 100]) perm");

	// taint key
	key->key[15]++;
	memcpy(setid->key, key->key, sizeof(key->key));
	memcpy(setgids->key, key->key, sizeof(key->key));

	// try to become 65535
	setid->uid = 65535;
	check(ioctl(fd, UGIDCTLIO_SETUID, setid), EPERM, "ugidctl_setuid(65535) bad key perm");
	setid->gid = 65535;
	check(ioctl(fd, UGIDCTLIO_SETGID, setid), EPERM, "ugidctl_setgid(65533) bad key perm");
	setgids->count = 1;
	setgids->list[0] = 65535;
	check(ioctl(fd, UGIDCTLIO_SETGROUPS, setgids), EPERM, "ugidctl_setgroups([65535]) bad key perm");

	printf("All tests passed\n");
	return 0;
}
