/*
 * socket_ipc.h
 *
 *  Created on: Aug 8, 2018
 *      Author: chenbo
 *  Reference:
 *  [1] https://users.cs.cf.ac.uk/Dave.Marshall/C/node28.html
 *  [2] https://unix.stackexchange.com/a/16487
 */

#ifndef LIB_INCLUDE_EXTERNAL_SOCKET_IPC_H_
#define LIB_INCLUDE_EXTERNAL_SOCKET_IPC_H_

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>

// @ret: error with negative return, success on 0 return
static int create_skt_server(void);
static int create_skt_client(void);
static int close_skt(void);

static int send_message(const char *buf, const int len);
 // @ret: success with number of bytes received
//       error with negative return
static int receive_message(char *buf, const int len);

static const char *IPC_SKT_ADDR = "/tmp/crete_ipc_skt";
static int s_server = -1;
static int s_client = -1;

__attribute__((unused))
static int create_skt_server(void)
{
    int len, fromlen;
    struct sockaddr_un saun, fsaun;

    if(s_server != -1 || s_client != -1) {
        fprintf(stderr, "[CRETE ERROR] server: s_server = %d, s_client = %d\n", s_server, s_client);
        return -1;
    }

    /*
     * Get a socket to work with.  This socket will
     * be in the UNIX domain, and will be a
     * stream socket.
     */
    if ((s_server = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        perror("server: socket");
        return -1;
    }

    /*
     * Create the address we will be binding to.
     */
    saun.sun_family = AF_UNIX;
    strcpy(saun.sun_path, IPC_SKT_ADDR);

    /*
     * Try to bind the address to the socket.  We
     * unlink the name first so that the bind won't
     * fail.
     *
     * The third argument indicates the "length" of
     * the structure, not just the length of the
     * socket name.
     */
    unlink(IPC_SKT_ADDR);
    len = sizeof(saun.sun_family) + strlen(saun.sun_path);

    if (bind(s_server, (const struct sockaddr *)&saun, len) < 0) {
        perror("server: bind");
        return -1;
    }

    /*
     * Listen on the socket.
     */
    if (listen(s_server, 5) < 0) {
        perror("server: listen");
        return -1;
    }

    /*
     * Accept connections.  When we accept one, ns
     * will be connected to the client.  fsaun will
     * contain the address of the client.
     */
    if ((s_client = accept(s_server, (struct sockaddr *)&fsaun, (socklen_t *__restrict)&fromlen)) < 0) {
        perror("server: accept");
        return -1;
    }

    return 0;
}

__attribute__((unused))
static int create_skt_client(void)
{
    int len;
    struct sockaddr_un saun;

    if(s_client != -1) {
        fprintf(stderr, "[CRETE Warning] client already created: s_server = %d, s_client = %d\n", s_server, s_client);
        return 0;
    }

    /*
     * Get a socket to work with.  This socket will
     * be in the UNIX domain, and will be a
     * stream socket.
     */
    if ((s_client = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        perror("client: socket");
        return -1;
    }

    /*
     * Create the address we will be connecting to.
     */
    saun.sun_family = AF_UNIX;
    strcpy(saun.sun_path, IPC_SKT_ADDR);

    /*
     * Try to connect to the address.  For this to
     * succeed, the server must already have bound
     * this address, and must have issued a listen()
     * request.
     *
     * The third argument indicates the "length" of
     * the structure, not just the length of the
     * socket name.
     */
    len = sizeof(saun.sun_family) + strlen(saun.sun_path);

    if (connect(s_client, (const struct sockaddr *)&saun, len) < 0) {
        perror("client: connect");
        return -1;
    }

    return 0;
}

__attribute__((unused))
static int close_skt(void)
{
    if(s_server > 0)
        close(s_server);
    if(s_client > 0)
        close(s_client);

    s_server = -1;
    s_client = -1;

    return 0;
}

__attribute__((unused))
static int send_message(const char *buf, const int buf_len)
{
    if(s_client < 0) {
        fprintf(stderr, "[CRETE ERROR] send_message(): s_server = %d, s_client = %d\n", s_server, s_client);
        return -1;
    }

    int ret, len;
    const char *write_ptr;

    len = sizeof(buf_len);
    write_ptr = (char *)&buf_len;
    while (len != 0 && (ret = write (s_client, write_ptr, len)) != 0) {
        if (ret == -1) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "[CRETE ERROR] send_message(): send 'buf_len' failed: sizeof(buf_len) = %lu, ret = %d, errno = %s\n",
                    sizeof(buf_len), ret, strerror(errno));
            return -1;
        }
        len -= ret;
        write_ptr += ret;
    }

    len = buf_len;
    write_ptr = buf;
    while (len != 0 && (ret = write (s_client, write_ptr, len)) != 0) {
        if (ret == -1) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "[CRETE ERROR] send_message(): send 'buf' failed: buf_len = %d, ret = %d, errno = %s\n",
                    buf_len, ret, strerror(errno));
            return -1;
        }
        len -= ret;
        write_ptr += ret;
    }

    return 0;
}

__attribute__((unused))
static int receive_message(char *buf, const int buf_len)
{
    if(s_client < 0) {
        fprintf(stderr, "[CRETE ERROR] receive_message(): s_server = %d, s_client = %d\n", s_server, s_client);
        return -1;
    }

    int msg_len, ret, len;
    char *read_ptr;

    len = sizeof(msg_len);
    read_ptr = (char *)&msg_len;
    while (len != 0 && (ret = read (s_client, read_ptr, len)) != 0) {
        if (ret == -1) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "[CRETE ERROR] receive_message(): read 'len' failed: sizeof(len) = %lu, ret = %d, errno = %s\n",
                    sizeof(msg_len), ret, strerror(errno));
            return -1;
        }
        len -= ret;
        read_ptr += ret;
    }

    if(buf_len < msg_len)
    {
        fprintf(stderr, "[CRETE ERROR] receive_message(): input 'buf' is too small: buf_len = %d, msg_len = %d\n", buf_len, msg_len);
        return -1;
    }

    len = msg_len;
    read_ptr = buf;
    while (len != 0 && (ret = read (s_client, read_ptr, len)) != 0) {
        if (ret == -1) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "[CRETE ERROR] send_message(): read message failed: buf_len = %d, ret = %d, errno = %s\n",
                    buf_len, ret, strerror(errno));
            return -1;
        }
        len -= ret;
        read_ptr += ret;
    }

    return ret;
}

#endif /* LIB_INCLUDE_EXTERNAL_SOCKET_IPC_H_ */
