#include <utils.h>

#define VERSION "1.0.0b"
#define DEBUG_SOCKET
#define DEBUG_ADDR IP(192, 168, 1, 155);
#define DEBUG_PORT 5655

#define BACKUP_DB "BackupDB"
#define SYSTEM "/system"
#define SYSTEM_DATA "/system_data"
#define PRIV "/priv"
#define USERDATA "/user"
#define SAVEDATA "/savedata"
#define PROSPERO "/savedata_prospero"

#define SYSTEM_LOGGER2 "/system_logger2"

char *welcom(SceUserServiceLoginUserIdList userIdList)
{
	memset_s(&userIdList, sizeof(SceUserServiceLoginUserIdList), 0, sizeof(SceUserServiceLoginUserIdList));
	char *retval = f_malloc(sizeof(char) * 16);
	if (getUserIDList(&userIdList) == 0)
	{
		for (int i = 0; i < SCE_USER_SERVICE_MAX_LOGIN_USERS; i++)
		{
			if (userIdList.userId[i] != -1 && userIdList.userId[i] != 0)
			{
				f_strcpy(retval, getUserName(userIdList.userId[i]));
			}
		}
	}
	return retval;
}

int sock;

int payload_main(struct payload_args *args)
{
	dlsym_t *dlsym = args->dlsym;

	int libKernel = 0x2001;

	dlsym(libKernel, "sceKernelSleep", &f_sceKernelSleep);
	dlsym(libKernel, "sceKernelLoadStartModule", &f_sceKernelLoadStartModule);
	dlsym(libKernel, "sceKernelDebugOutText", &f_sceKernelDebugOutText);
	dlsym(libKernel, "sceKernelSendNotificationRequest", &f_sceKernelSendNotificationRequest);
	dlsym(libKernel, "sceKernelUsleep", &f_sceKernelUsleep);
	dlsym(libKernel, "scePthreadMutexLock", &f_scePthreadMutexLock);
	dlsym(libKernel, "scePthreadMutexUnlock", &f_scePthreadMutexUnlock);
	dlsym(libKernel, "scePthreadExit", &f_scePthreadExit);
	dlsym(libKernel, "scePthreadMutexInit", &f_scePthreadMutexInit);
	dlsym(libKernel, "scePthreadCreate", &f_scePthreadCreate);
	dlsym(libKernel, "scePthreadMutexDestroy", &f_scePthreadMutexDestroy);
	dlsym(libKernel, "scePthreadJoin", &f_scePthreadJoin);
	dlsym(libKernel, "socket", &f_socket);
	dlsym(libKernel, "bind", &f_bind);
	dlsym(libKernel, "listen", &f_listen);
	dlsym(libKernel, "accept", &f_accept);
	dlsym(libKernel, "open", &f_open);
	dlsym(libKernel, "read", &f_read);
	dlsym(libKernel, "write", &f_write);
	dlsym(libKernel, "close", &f_close);
	dlsym(libKernel, "stat", &f_stat);
	dlsym(libKernel, "fstat", &f_fstat);
	dlsym(libKernel, "rename", &f_rename);
	dlsym(libKernel, "rmdir", &f_rmdir);
	dlsym(libKernel, "mkdir", &f_mkdir);
	dlsym(libKernel, "getdents", &f_getdents);
	dlsym(libKernel, "unlink", &f_unlink);
	dlsym(libKernel, "readlink", &f_readlink);
	dlsym(libKernel, "lseek", &f_lseek);
	dlsym(libKernel, "puts", &f_puts);
	dlsym(libKernel, "mmap", &f_mmap);
	dlsym(libKernel, "munmap", &f_munmap);

	dlsym(libKernel, "sceKernelReboot", &f_sceKernelReboot);

	int libNet = f_sceKernelLoadStartModule("libSceNet.sprx", 0, 0, 0, 0, 0);
	dlsym(libNet, "sceNetSocket", &f_sceNetSocket);
	dlsym(libNet, "sceNetConnect", &f_sceNetConnect);
	dlsym(libNet, "sceNetHtons", &f_sceNetHtons);
	dlsym(libNet, "sceNetAccept", &f_sceNetAccept);
	dlsym(libNet, "sceNetSend", &f_sceNetSend);
	dlsym(libNet, "sceNetInetNtop", &f_sceNetInetNtop);
	dlsym(libNet, "sceNetSocketAbort", &f_sceNetSocketAbort);
	dlsym(libNet, "sceNetBind", &f_sceNetBind);
	dlsym(libNet, "sceNetListen", &f_sceNetListen);
	dlsym(libNet, "sceNetSocketClose", &f_sceNetSocketClose);
	dlsym(libNet, "sceNetHtonl", &f_sceNetHtonl);
	dlsym(libNet, "sceNetInetPton", &f_sceNetInetPton);
	dlsym(libNet, "sceNetGetsockname", &f_sceNetGetsockname);
	dlsym(libNet, "sceNetRecv", &f_sceNetRecv);
	dlsym(libNet, "sceNetErrnoLoc", &f_sceNetErrnoLoc);
	dlsym(libNet, "sceNetSetsockopt", &f_sceNetSetsockopt);

	int libC = f_sceKernelLoadStartModule("libSceLibcInternal.sprx", 0, 0, 0, 0, 0);
	dlsym(libC, "vsprintf", &f_vsprintf);
	dlsym(libC, "memset", &f_memset);
	dlsym(libC, "sprintf", &f_sprintf);
	dlsym(libC, "snprintf", &f_snprintf);
	dlsym(libC, "snprintf_s", &f_snprintf_s);
	dlsym(libC, "strcat", &f_strcat);
	dlsym(libC, "free", &f_free);
	dlsym(libC, "memcpy", &f_memcpy);
	dlsym(libC, "strcpy", &f_strcpy);
	dlsym(libC, "strncpy", &f_strncpy);
	dlsym(libC, "sscanf", &f_sscanf);
	dlsym(libC, "scanf", &f_scanf);
	dlsym(libC, "scanf", &f_scanf);
	dlsym(libC, "malloc", &f_malloc);
	dlsym(libC, "calloc", &f_calloc);
	dlsym(libC, "strlen", &f_strlen);
	dlsym(libC, "strcmp", &f_strcmp);
	dlsym(libC, "strchr", &f_strchr);
	dlsym(libC, "strrchr", &f_strrchr);
	dlsym(libC, "gmtime_s", &f_gmtime_s);
	dlsym(libC, "time", &f_time);
	dlsym(libC, "localtime", &f_localtime);
	dlsym(libC, "closedir", &f_closedir);
	dlsym(libC, "opendir", &f_opendir);
	dlsym(libC, "readdir", &f_readdir);
	dlsym(libC, "fclose", &f_fclose);
	dlsym(libC, "fopen", &f_fopen);
	dlsym(libC, "strstr", &f_strstr);
	dlsym(libC, "fseek", &f_fseek);
	dlsym(libC, "ftell", &f_ftell);
	dlsym(libC, "fread", &f_fread);
	dlsym(libC, "usleep", &f_usleep);
	dlsym(libC, "fputs", &f_fputs);
	dlsym(libC, "fgetc", &f_fgetc);
	dlsym(libC, "feof", &f_feof);
	dlsym(libC, "fprintf", &f_fprintf);
	dlsym(libC, "realloc", &f_realloc);
	dlsym(libC, "seekdir", &f_seekdir);

	int libNetCtl = f_sceKernelLoadStartModule("libSceNetCtl.sprx", 0, 0, 0, 0, 0);
	dlsym(libNetCtl, "sceNetCtlInit", &f_sceNetCtlInit);
	dlsym(libNetCtl, "sceNetCtlTerm", &f_sceNetCtlTerm);
	dlsym(libNetCtl, "sceNetCtlGetInfo", &f_sceNetCtlGetInfo);

	int libSysModule = f_sceKernelLoadStartModule("libSceSysmodule.sprx", 0, 0, 0, 0, 0);
	dlsym(libSysModule, "sceSysmoduleLoadModuleInternal", &f_sceSysmoduleLoadModuleInternal);
	dlsym(libSysModule, "sceSysmoduleUnloadModuleInternal", &f_sceSysmoduleUnloadModuleInternal);

	int sysModule = f_sceSysmoduleLoadModuleInternal(SCE_SYSMODULE_INTERNAL_USER_SERVICE);
	SceUserServiceLoginUserIdList userIdList;
	// memset_s(&userIdList, sizeof(SceUserServiceLoginUserIdList), 0, sizeof(SceUserServiceLoginUserIdList));

	int libUserService = f_sceKernelLoadStartModule("libSceUserService.sprx", 0, 0, 0, 0, 0);
	dlsym(libUserService, "sceUserServiceInitialize", &f_sceUserServiceInitialize);
	dlsym(libUserService, "sceUserServiceGetInitialUser", &f_sceUserServiceGetInitialUser);
	dlsym(libUserService, "sceUserServiceGetLoginUserIdList", &f_sceUserServiceGetLoginUserIdList);
	dlsym(libUserService, "sceUserServiceGetUserName", &f_sceUserServiceGetUserName);
	dlsym(libUserService, "sceUserServiceTerminate", &f_sceUserServiceTerminate);

	struct sockaddr_in server;
	server.sin_len = sizeof(server);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = DEBUG_ADDR;
	server.sin_port = f_sceNetHtons(DEBUG_PORT);
	f_memset(server.sin_zero, 0, sizeof(server.sin_zero));
	sock = f_sceNetSocket("debug", AF_INET, SOCK_STREAM, 0);
	f_sceNetConnect(sock, (struct sockaddr *)&server, sizeof(server));

	char src_path[256], dst_path[256], tmp_path[256];
	char usb_mount_path[64];
	char *usb_mnt_path = getusbpath();
	char userName[16];

	int i = 0;
	if (sysModule == 0)
	{
		char *get_userName = welcom(userIdList);
		if (get_userName != NULL)
		{
			f_strcpy(userName, get_userName);
			printf_notification("Welcome %s to\nBackup-DB-PS5 V%s\n\nBy ★@Logic-68★", userName, VERSION);
			f_sceKernelSleep(7);
		}
		f_free(get_userName);
	}

	if (usb_mnt_path == NULL)
	{
		do
		{
			if(i == 0)
			printf_notification("Warning:Please insert your USB key\nOtherwise your backup will take place on the internal disk");
			f_sceKernelSleep(7);
			if(i == 1)
			printf_notification("Last warning:Please insert your USB key\nOtherwise your backup will take place on the internal disk");
			f_sceKernelSleep(7);
			usb_mnt_path = getusbpath();
			i++;
		} while (i < 2);
	}
	f_sprintf(usb_mount_path, "%s", usb_mnt_path);
	f_free(usb_mnt_path);

	if (usb_mnt_path != NULL)
	{
		printf_notification("Backup of USB");
		f_sceKernelSleep(7);

		f_sprintf(tmp_path, "%s/%s/%s", usb_mount_path, userName, BACKUP_DB);
		f_strcpy(usb_mount_path, tmp_path);

		if (dir_exists(usb_mount_path))
		{
			if (!erase_folder(usb_mount_path))
			{
				printf_notification("Backup already present on USB.\nErasure...");
				f_sceKernelSleep(7);
			}
		}
		f_mkdir(usb_mount_path, 0777);
		// system_data/
		f_sprintf(src_path, "%s/%s/%s", SYSTEM_DATA, PRIV, "mms");
		f_sprintf(dst_path, "%s/%s", usb_mount_path, SYSTEM_DATA);
		f_mkdir(dst_path, 0777);
		f_sprintf(tmp_path, "%s/%s", dst_path, PRIV);
		f_mkdir(tmp_path, 0777);
		f_sprintf(dst_path, "%s/%s", tmp_path, "mms");
		if (dir_exists(src_path))
		{
			copy_dir(src_path, dst_path);
		}
		f_sprintf(src_path, "%s/%s/%s", SYSTEM_DATA, PRIV, SYSTEM_LOGGER2);
		f_sprintf(dst_path, "%s/%s", usb_mount_path, SYSTEM_LOGGER2);
		f_mkdir(dst_path, 0777);
		if (dir_exists(src_path))
		{
			copy_dir(src_path, dst_path);
		}
		f_sprintf(src_path, "%s/%s", SYSTEM_DATA, SAVEDATA);
		f_sprintf(dst_path, "%s/%s/%s", usb_mount_path, SYSTEM_DATA, SAVEDATA);
		if (dir_exists(src_path))
		{
			copy_dir(src_path, dst_path);
		}
		f_sprintf(src_path, "%s/%s", SYSTEM_DATA, PROSPERO);
		f_sprintf(dst_path, "%s/%s/%s", usb_mount_path, SYSTEM_DATA, PROSPERO);
		if (dir_exists(src_path))
		{
			copy_dir(src_path, dst_path);
		}
		// user
		f_sprintf(src_path, "%s/%s/%s", SYSTEM_DATA, PRIV, "home");
		f_sprintf(dst_path, "%s/%s", tmp_path, "home");
		if (dir_exists(src_path))
		{
			copy_dir(src_path, dst_path);
		}
		f_sprintf(src_path, "%s/%s/%s", SYSTEM_DATA, PRIV, "license");
		f_sprintf(dst_path, "%s/%s", tmp_path, "license");
		if (dir_exists(src_path))
		{
			copy_dir(src_path, dst_path);
		}
		f_sprintf(src_path, "%s/%s", USERDATA, "home");
		f_sprintf(tmp_path, "%s/%s", usb_mount_path, "user");
		f_mkdir(tmp_path, 0777);
		f_sprintf(dst_path, "%s/%s", tmp_path, "home");
		if (dir_exists(src_path))
		{
			copy_dir(src_path, dst_path);
		}
		f_sprintf(src_path, "%s/%s", USERDATA, "trophy2");
		f_sprintf(dst_path, "%s/%s", tmp_path, "trophy2");
		if (dir_exists(src_path))
		{
			copy_dir(src_path, dst_path);
		}
		f_sprintf(src_path, "%s/%s", USERDATA, "license");
		f_sprintf(dst_path, "%s/%s", tmp_path, "license");
		if (dir_exists(src_path))
		{
			copy_dir(src_path, dst_path);
		}
		// webkit
		f_sprintf(dst_path, "%s/%s", tmp_path, SYSTEM);
		f_mkdir(dst_path, 0777);
		f_sprintf(tmp_path, "%s/%s", dst_path, "webkit");
		f_mkdir(tmp_path, 0777);
		f_sprintf(src_path, "%s/%s/%s", USERDATA, SYSTEM, "webkit");
		f_sprintf(dst_path, "%s", tmp_path);
		if (dir_exists(src_path))
		{
			copy_dir(src_path, dst_path);
		}
	}
	else
	{
		printf_notification("Backup of internal");
		f_sceKernelSleep(7);

		char file[256];
		char delete[256];
		char make[256];

		f_sprintf(file, "%s/%s/%s/%s", SYSTEM_DATA, PRIV, "mms", "app");
		f_sprintf(delete, "%s%s", file, ".bak");
		f_unlink(src_path);
		f_sprintf(make, "%s%s", file, ".db");
		copy_file(make, f_strcat(file, ".bak"));

		f_sprintf(file, "%s/%s/%s/%s", SYSTEM_DATA, PRIV, "mms", "addcont");
		f_sprintf(delete, "%s%s", file, ".bak");
		f_unlink(src_path);
		f_sprintf(make, "%s%s", file, ".db");
		copy_file(make, f_strcat(file, ".bak"));

		f_sprintf(file, "%s/%s/%s/%s", SYSTEM_DATA, PRIV, "mms", "av_content_bg");
		f_sprintf(delete, "%s%s", file, ".bak");
		f_unlink(src_path);
		f_sprintf(make, "%s%s", file, ".db");
		copy_file(make, f_strcat(file, ".bak"));

		f_sprintf(src_path, "%s/%s/%s", USERDATA, SYSTEM, "_webkit");
		if (dir_exists(src_path))
		{
			erase_folder(src_path);
		}
		f_sprintf(src_path, "%s/%s/%s", USERDATA, SYSTEM, "webkit");
		f_sprintf(dst_path, "%s/%s/%s", USERDATA, SYSTEM, "_webkit");

		if (dir_exists(src_path))
		{
			copy_dir(src_path, dst_path);
		}
	}
	f_sceSysmoduleUnloadModuleInternal(SCE_SYSMODULE_INTERNAL_USER_SERVICE);
	printf_notification("Thank you for using Backup-DB-PS5\n\nGoodbye!");
	return 0;
}