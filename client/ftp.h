//
//  ftp.h
//
//  Created by RunningDay on 17/2/17.
//  Copyright © 2017年 Tonmind. All rights reserved.
//

#ifndef __ftp_h_runningDay__
#define __ftp_h_runningDay__

#include <stdio.h>

typedef struct ftp {
    int socket;
} ftp_t;

enum FTP_GET_TYPE {
    FTP_GET_TYPE_DOWNLOADING = 0,
    FTP_GET_TYPE_BEGAN = 1,
    FTP_GET_TYPE_ENDED = 2,
    FTP_GET_TYPE_FAILED = 3,
    FTP_GET_TYPE_CANCELLED = 4,
};
typedef void (*ftp_get_callback_t)(void *object, int type, int64_t current, int64_t total, const char *path, float speed);

enum FTP_PUT_TYPE {
    FTP_PUT_TYPE_PUTTING = 0,
    FTP_PUT_TYPE_BEGAN = 1,
    FTP_PUT_TYPE_ENDED = 2,
    FTP_PUT_TYPE_FAILED = 3,
    FTP_PUT_TYPE_CANCELLED = 4,
};
typedef void (*ftp_put_callback_t)(void *object, int type, int64_t current, int64_t total, const char *path, float speed);

/**
 连接服务器
 */
ftp_t *ftp_connect(const char *host, int port, const char *user, const char *pwd);

/**
 断开服务器
 */
int ftp_disconnect(ftp_t *ftp);

/**
 放弃之前的ftp命令, 如果命令已经完成, 则返回226, 没有完成, 返回426, 在返回226, 关闭控制连接, 但是不关闭数据连接
 */
int ftp_abor(ftp_t *ftp);

/**
 设置ftp传输类型
 'A', Assci, 文本传输模式
 'I', Binary, 二进制(文件)模式
 */
int ftp_type(ftp_t *ftp, char mode);

/**
 列出当前路径, buf长度要足够
 */
int ftp_pwd(ftp_t *ftp, char *buf);

/**
 切换到path目录下
 */
int ftp_cwd(ftp_t *ftp, const char *path);

/**
 ftp返回上级目录
 */
int ftp_cdup(ftp_t *ftp);

/**
 创建目录
 */
int ftp_mkdir(ftp_t *ftp, const char *path);

/**
 列出ftp path目录下的文件信息
 */
int ftp_list(ftp_t *ftp, const char *path, uint8_t **data, int *len);

/**
 下载文件
 从ftp服务器上的src完整路径, 下载到本地路径dst
 */
int ftp_get(ftp_t *ftp, const char *src, const char *dst, void *obj, ftp_get_callback_t callback, int *stop);

/**
 上传文件
 从本地完整路径src, 上传到服务器完整路径dst
 */
int ftp_put(ftp_t *ftp, const char *src, const char *dst, void *obj, ftp_get_callback_t callback, int *stop);

/**
 重命名文件/文件夹
 将src重命名为dst
 */
int ftp_rename(ftp_t *ftp, const char *src, const char *dst);

/**
 删除文件
 */
int ftp_delete(ftp_t *ftp, const char *path);

/**
 删除文件夹
 */
int ftp_rmd(ftp_t *ftp, const char *dir);

#endif /* __ftp_h_runningDay__ */
