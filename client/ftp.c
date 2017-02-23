//
//  ftp.c
//
//  Created by RunningDay on 17/2/17.
//  Copyright © 2017年 Tonmind. All rights reserved.
//
/*
 
 响应代码	解释说明
 110	新文件指示器上的重启标记
 120	服务器准备就绪的时间（分钟数）
 125	打开数据连接，开始传输
 150	打开连接
 200	成功
 202	命令没有执行
 211	系统状态回复
 212	目录状态回复
 213	文件状态回复
 214	帮助信息回复
 215	系统类型回复
 220	服务就绪
 221	退出网络
 225	打开数据连接
 226	结束数据连接
 227	进入被动模式（IP 地址、ID 端口）
 230	登录因特网
 250	文件行为完成
 257	路径名建立
 331	要求密码
 332	要求帐号
 350	文件行为暂停
 421	服务关闭
 425	无法打开数据连接
 426	结束连接
 450	文件不可用
 451	遇到本地错误
 452	磁盘空间不足
 500	无效命令
 501	错误参数
 502	命令没有执行
 503	错误指令序列
 504	无效命令参数
 530	未登录网络
 532	存储文件需要帐号
 550	文件不可用
 551	不知道的页类型
 552	超过存储分配
 553	文件名不允许 
 */

#include "ftp.h"
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>

#include <sys/time.h>

#define FTP_BUF_SIZE    1024

#ifdef DEBUG
#define FTP_LOG printf
#else
#define FTP_LOG printf
#endif

static ssize_t ftp_send(int s, const void *buf, ssize_t len, int flags, int times) {
    ssize_t ret = -1;
    for (int i = 0; i < times; ++i) {
        ret = send(s, buf, len, flags);
        if (ret == -1) {
            int error = errno;
            if (error == EINTR || error == EWOULDBLOCK || error == EAGAIN) {
                continue;
            }
        } else if (ret == 0) {
            break;
        } else {
            return ret;
        }
    }
    return ret;
}

static ssize_t ftp_recv(int s, void *buf, size_t len, int flags, int times) {
    ssize_t ret = -1;
    for (int i = 0; i < times; ++i) {
        ret = recv(s, buf, len, flags);
        if (ret == -1) {
            int error = errno;
            if (error == EINTR || error == EWOULDBLOCK || error == EAGAIN) {
                continue;
            }
        } else if (ret == 0) {
            break;
        } else {
            return ret;
        }
    }
    return ret;
}

static int64_t ftp_current_ms() {
    struct timeval now;
    if (gettimeofday(&now, NULL) < 0) {
        return 0;
    }
    return (int64_t)(now.tv_sec) * 1000 + now.tv_usec / 1000;
}

static int64_t ftp_file_size(const char *path) {
    return 0;
}

static int64_t ftp_local_file_size(const char *path) {
    FILE*fp;
    fp=fopen(path, "rb");
    if (fp == NULL) {
        fclose(fp);
        return 0;
    }
    fseek(fp,0,SEEK_SET);
    fseek(fp,0,SEEK_END);
    long longBytes=ftell(fp);// longBytes就是文件的长度
    fclose(fp);
    return longBytes;
}

static int socket_connect(int socket, struct sockaddr *addr, struct timeval *timeout) {
    unsigned long ul = 1;
    
    ioctl(socket, FIONBIO, &ul);
    
    int ret = connect(socket, addr, sizeof(*addr));
    if (ret != -1) {
        return -1;
    }
    
    fd_set read, write;
    FD_ZERO(&read);
    FD_SET(socket, &read);
    
    write = read;
    
    ret = select(socket + 1, &read, &write, NULL, timeout);
    if (ret < 0) {
        return -1;
    }
    
    ul = 0;
    ioctl(socket, FIONBIO, &ul);
    
    return socket;
}

static int ftp_socket_connect(const char *host, int port) {
    if (host == NULL || port < 0) {
        return -1;
    }
    
    struct sockaddr_in address;
    int s, opvalue;
    socklen_t slen;
    
    opvalue = 8;
    slen = sizeof(opvalue);
    memset(&address, 0, sizeof(address));
    
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0 ||
        setsockopt(s, IPPROTO_IP, IP_TOS, &opvalue, slen) < 0)
        return -1;
    
    //设置接收和发送超时
    struct timeval timeo = {5, 0};
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &timeo, sizeof(timeo));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeo, sizeof(timeo));
    
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)port);
    
    struct hostent* server = gethostbyname(host);
    if (!server) {
        return -1;
    }
    
    memcpy(&address.sin_addr.s_addr, server->h_addr, server->h_length);
    
    if (socket_connect(s, (struct sockaddr*)&address, &timeo) == -1) {
        printf("socket connect failed");
        close(s);
        return -1;
    }
    
    return s;
}

static void ftp_check(ftp_t *ftp, ssize_t ret) {
    if (ret > 0) {
        return;
    }
    
    if (ret < 0) {
        int error = errno;
        if (error == EINTR || error == EWOULDBLOCK || error == EAGAIN) {
            return;
        }
        close(ftp->socket);
        ftp->socket = -1;
        FTP_LOG("socket recv_ret = -1, error!!!\n");
        return;
    }
    
    if (ret == 0) {
        close(ftp->socket);
        ftp->socket = -1;
        FTP_LOG("socket recv_ret = 0, error!!!\n");
    }
}

static int ftp_cmd_ret(ftp_t *ftp, const char *cmd, void *buf, ssize_t *len) {
    if (ftp == NULL || ftp->socket < 0) {
        return -1;
    }
    
    if (ftp_send(ftp->socket, cmd, strlen(cmd), 0, 2) == -1) {
        return -1;
    }
    
    char response[FTP_BUF_SIZE];
    ssize_t ret = ftp_recv(ftp->socket, response, FTP_BUF_SIZE, 0, 2);
    if (ret <= 0) {
        ftp_check(ftp, ret);
        return -1;
    }
    response[ret] = 0;
    FTP_LOG("%s\n", response);
    if (len) {
        *len = ret;
    }
    
    if (buf) {
        sprintf(buf, "%s", response);
    }
    
    return 0;
}

static int ftp_cmd(ftp_t *ftp, const char *cmd) {
    if (ftp == NULL || ftp->socket < 0) {
        return -1;
    }
    
    char buf[FTP_BUF_SIZE];
    ssize_t len = 0;
    int ret = ftp_cmd_ret(ftp, cmd, buf, &len);
    if (ret == 0) {
        sscanf(buf, "%d", &ret);
    }
    
    return ret;
}

static int ftp_pasv(ftp_t *ftp) {
    if (ftp == NULL || ftp->socket < 0) {
        return -1;
    }
    
    char response[FTP_BUF_SIZE];
    ssize_t len;
    
    int addr[6];
    
    char buf[FTP_BUF_SIZE];
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "PASV\r\n");
    int ret = ftp_cmd_ret(ftp, buf, response, &len);
    if (ret == 0) {
        sscanf(response, "%*[^(](%d,%d,%d,%d,%d,%d)",&addr[0],&addr[1],&addr[2],&addr[3],&addr[4],&addr[5]);
    }
    
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
    return ftp_socket_connect(buf, (addr[4] << 8) + addr[5]);
}

int ftp_login(ftp_t *ftp, const char *user, const char *pwd) {
    
    char buf[128];
    
    snprintf(buf, sizeof(buf), "USER %s\r\n", user);
    int ret = ftp_cmd(ftp, buf);
    if (ret == 230) {
        return 0;
    } else if (ret == 331) {
        snprintf(buf, sizeof(buf), "PASS %s\r\n", pwd);
        if (ftp_cmd(ftp, buf) != 230) {
            return -1;
        }
        return 0;
    } else {
        return -1;
    }
}


/**
 连接服务器
 */
ftp_t *ftp_connect(const char *host, int port, const char *user, const char *pwd) {
    char buf[FTP_BUF_SIZE];
    
    int socket = ftp_socket_connect(host, port);
    if (socket == -1) {
        return NULL;
    }
    
    ssize_t len = ftp_recv(socket, buf, FTP_BUF_SIZE, 0, 2);
    if (len <= 0) {
        close(socket);
        return NULL;
    }
    buf[len] = 0;
    
    int ret = 0;
    sscanf(buf, "%d", &ret);
    if (ret != 220) {
        close(socket);
        return NULL;
    }
    
    ftp_t *ftp = (ftp_t *) malloc(sizeof(ftp_t));
    ftp->socket = socket;
    
    if (ftp_login(ftp, user, pwd) == -1) {
        free(ftp);
        return NULL;
    }
    return ftp;
}

int ftp_disconnect(ftp_t *ftp) {
    if (ftp == NULL || ftp->socket < 0) {
        return -1;
    }
    
    int ret = ftp_cmd(ftp, "QUIT\r\n");
    close(ftp->socket);
    ftp->socket = -1;
    
    return ret;
}

int ftp_abor(ftp_t *ftp) {
    if (ftp == NULL || ftp->socket < 0) {
        return -1;
    }
    
    return ftp_cmd(ftp, "ABOR");
}

int ftp_type(ftp_t *ftp, char type) {
    char buf[128];
    snprintf(buf, sizeof(buf), "TYPE %c\r\n", type);
    
    return ftp_cmd(ftp, buf);
}

int ftp_pwd(ftp_t *ftp, char *buf) {
    
    char response[FTP_BUF_SIZE];
    ssize_t len = 0;
    int ret = ftp_cmd_ret(ftp, "PWD \r\n", response, &len);
    if (ret != 0) {
        return -1;
    }
    
    sscanf(response, "%d %s", &ret, buf);
    if (ret != 257) {
        return -1;
    }
    
    return 0;
}

int ftp_cwd(ftp_t *ftp, const char *path) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "CWD %s\r\n", path);
    
    int ret = ftp_cmd(ftp, cmd);
    if (ret != 250) {
        return -1;
    }
    return 0;
}

int ftp_cdup(ftp_t *ftp) {
    int ret = ftp_cmd(ftp, "CDUP\r\n");
    if (ret != 250) {
        return -1;
    }
    return 0;
}

int ftp_mkdir(ftp_t *ftp, const char *path) {
    char cmd[FTP_BUF_SIZE];
    snprintf(cmd, sizeof(cmd), "MKD %s\r\n", path);
    int ret = ftp_cmd(ftp, cmd);
    if (ret != 257) {
        return -1;
    }
    return 0;
}

int ftp_list(ftp_t *ftp, const char *path, uint8_t **data, int *len) {
    
    int pasv_socket = ftp_pasv(ftp);
    if (pasv_socket < 0) {
        return -1;
    }
    
    char buf[FTP_BUF_SIZE];
    snprintf(buf, sizeof(buf), "LIST %s\r\n", path);
    int ret = ftp_cmd(ftp, buf);
    if (ret >= 300 || ret <= 0) {
        return -1;
    }
    
    ssize_t recv_len, total_len, buf_len;
    recv_len = total_len = 0;
    buf_len = FTP_BUF_SIZE;
    void *recv_buf = malloc(buf_len);
    
    while ( (recv_len = ftp_recv(pasv_socket, buf, FTP_BUF_SIZE, 0, 2)) > 0) {
        if (total_len + recv_len > buf_len) {
            buf_len <<= 1;
            void *realloc_buf = malloc(buf_len);
            memcpy(realloc_buf, recv_buf, total_len);
            free(recv_buf);
            recv_buf = realloc_buf;
        }
        memcpy(recv_buf + total_len, buf, recv_len);
        total_len += recv_len;
    }
    close(pasv_socket);
    
    buf[0] = 0;
    recv_len = ftp_recv(ftp->socket, buf, FTP_BUF_SIZE, 0, 2);
    if (recv_len <= 0) {
        ftp_check(ftp, recv_len);
        return -1;
    }
    buf[recv_len] = 0;
    sscanf(buf, "%d", &ret);
    if (ret != 226) {
        free(recv_buf);
        return -1;
    }
    
    if (buf_len > total_len) {
        *(((char *)recv_buf) + total_len) = 0;
    }
    
    *data = recv_buf;
    *len = (int)total_len;
    
    return 0;
}

int ftp_get(ftp_t *ftp, const char *src, const char *dst, void *obj, ftp_get_callback_t callback, int *stop) {
    
    FILE *file = NULL;
    int pasv_socket = -1;
    int success = FTP_GET_TYPE_FAILED;
    
    int64_t current = 0, total = 0;
    float speed = 0;
    
    char buf[FTP_BUF_SIZE];
    
    int ret = -1;
    do {
        int64_t dst_size = ftp_local_file_size(dst);
        file = fopen(dst, "ab+");
        if (file == NULL) {
            break;
        }
        
        ftp_type(ftp, 'I');
        pasv_socket = ftp_pasv(ftp);
        if (pasv_socket < 0) {
            break;
        }
        
        if (dst_size > 0) {
            memset(buf, 0, sizeof(buf));
            snprintf(buf, sizeof(buf), "REST %lld\r\n", dst_size);
            ret = ftp_cmd(ftp, buf);
            if (ret >= 300 || ret == 0) {
            } else {
                fseek(file, 0, SEEK_SET);
                dst_size = 0;
            }
        }

        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "RETR %s\r\n", src);
        ret = ftp_cmd(ftp, buf);
        if (ret >= 300 || ret == 0) {
            break;
        }
        
        current = dst_size;
        total = 0;
        if (callback) {
            callback(obj, FTP_GET_TYPE_BEGAN, current, total, src, speed);
        }
        
        int64_t began_time, ended_time;
        int64_t began_size, ended_size;
        
        began_time = ftp_current_ms();
        began_size = current;
        
        memset(buf, 0, sizeof(buf));
        int run = 1;
        int times = 0;
        while (run) {
            if (stop && *stop) {
                success = FTP_GET_TYPE_CANCELLED;
                break;
            }
            
            ssize_t len = ftp_recv(pasv_socket, buf, FTP_BUF_SIZE, 0, 2);
            if (len == -1) {
                int error = errno;
                FTP_LOG("socket error = %d\n", error);
                if (error == EINTR || error == EWOULDBLOCK || error == EAGAIN) {
                    ++times;
                    if (times >= 1) {
                        break;
                    }
                    continue;
                } else {
                    break;
                }
            }
            
            times = 0;
            
            if (len == 0) {
                FTP_LOG("socket recv == 0\n");
                break;
            }
            
            ssize_t write_len = fwrite(buf, len, 1, file);
            if (write_len == 0) {
                run = 0;
                break;
            }
            
            current += len;
            ended_time = ftp_current_ms();
            if (ended_time - began_time > 1000) {
                ended_size = current;
                
                speed = 1.0 * (ended_size - began_size) / (ended_time - began_time);
                
                began_time = ended_time;
                began_size = ended_size;
                if (callback) {
                    callback(obj, FTP_GET_TYPE_DOWNLOADING, current, total, src, speed);
                }
            }
        }
        
        //要先关闭数据端口, 命令端口才会将226 Transfer complete命令发过来
        close(pasv_socket);
        pasv_socket = -1;
        
        memset(buf, 0, sizeof(buf));
        ssize_t len = ftp_recv(ftp->socket, buf, FTP_BUF_SIZE, 0, 2);
        FTP_LOG("ftp get %s\n", buf);
        if (len <= 0) {
            ftp_check(ftp, len);
        }
        buf[len] = 0;
        sscanf(buf, "%d", &ret);
        
        if (ret == 221) {
            close(ftp->socket);
            ftp->socket = -1;
            break;
        }
        success = FTP_GET_TYPE_ENDED;
    } while (0);
    
    if (file) {
        fflush(file);
        fclose(file);
    }
    
    if (pasv_socket > 0) {
        close(pasv_socket);
    }
    
    if (callback) {
        callback(obj, success, current, total, src, speed);
    }
    
    return ret;
}

int ftp_put(ftp_t *ftp, const char *src, const char *dst, void *obj, ftp_get_callback_t callback, int *stop) {
    
    FILE *file = NULL;
    int pasv_socket = -1;
    char buf[FTP_BUF_SIZE];
    
    int64_t current = 0, total = 0;
    float speed = 0;
    
    int ret = -1;
    int success = FTP_PUT_TYPE_FAILED;
    
    ftp_type(ftp, 'I');
    
    do {
        file = fopen(src, "rb+");
        if (file == NULL) {
            break;
        }
        
        pasv_socket = ftp_pasv(ftp);
        if (pasv_socket < 0) {
            break;
        }
        
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "STOR %s\r\n", dst);
        ret = ftp_cmd(ftp, buf);
        if (ret >= 300 || ret == 0) {
            ret = -1;
            break;
        }
        
        if (callback) {
            callback(obj, FTP_PUT_TYPE_BEGAN, current, total, dst, speed);
        }
        
        int64_t began_time, ended_time;
        int64_t began_size, ended_size;
        
        began_time = ftp_current_ms();
        began_size = current;
        
        memset(buf, 0, sizeof(buf));
        int run = 1;
        while (run) {
            if (stop && *stop) {
                success = FTP_PUT_TYPE_CANCELLED;
                break;
            }
            
            ssize_t len = fread(buf, 1, FTP_BUF_SIZE, file);
            if (len <= 0) {
                break;
            }
            
            ssize_t send_len = ftp_send(pasv_socket, buf, len, 0, 2);
            if (send_len == -1) {
                
            }
            
            if (send_len == 0 || send_len != len) {
                run = 0;
                break;
            }
            
            current += send_len;
            ended_time = ftp_current_ms();
            if (ended_time - began_time > 1000) {
                ended_size = current;
                
                speed = 1.0 * (ended_size - began_size) / (ended_time - began_time);
                
                began_time = ended_time;
                began_size = ended_size;
                if (callback) {
                    callback(obj, FTP_PUT_TYPE_PUTTING, current, total, dst, speed);
                }
            }
            
        }
        
        //要先关闭数据端口, 命令端口才会将226 Transfer complete命令发过来
        close(pasv_socket);
        pasv_socket = -1;
        
        memset(buf, 0, sizeof(buf));
        ssize_t len = ftp_recv(ftp->socket, buf, FTP_BUF_SIZE, 0, 1);
        FTP_LOG("put recv %s\n", buf);
        if (len <= 0) {
            ftp_check(ftp, len);
        }
        buf[len] = 0;
        
        sscanf(buf, "%d", &ret);
        
        success = FTP_PUT_TYPE_ENDED;
    } while (0);
    
    if (file) {
        fclose(file);
    }
    
    if (pasv_socket > 0) {
        close(pasv_socket);
    }
    
    if (callback) {
        callback(obj, success, current, total, dst, speed);
    }
    
    return ret;
}

int ftp_rename(ftp_t *ftp, const char *src, const char *dst) {
    char cmd[FTP_BUF_SIZE];
    snprintf(cmd, sizeof(cmd), "RNFR %s\r\n", src);
    int ret = ftp_cmd(ftp, cmd);
    if (ret != 350) {
        return -1;
    }
    
    snprintf(cmd, sizeof(cmd), "RNTO %s\r\n", dst);
    ret = ftp_cmd(ftp, cmd);
    if (ret != 250) {
        return -1;
    }
    
    return 0;
}

int ftp_delete(ftp_t *ftp, const char *path) {
    char buf[FTP_BUF_SIZE];
    snprintf(buf, sizeof(buf), "DELE %s\r\n", path);
    int ret = ftp_cmd(ftp, buf);
    if (ret != 250) {
        return -1;
    }
    return 0;
}

int ftp_rmd(ftp_t *ftp, const char *dir) {
    char buf[FTP_BUF_SIZE];
    snprintf(buf, sizeof(buf), "RMD %s\r\n", dir);
    int ret = ftp_cmd(ftp, buf);
    if (ret != 250) {
        return -1;
    }
    return 0;
}
