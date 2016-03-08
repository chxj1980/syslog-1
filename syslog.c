#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "syslog.h"

#define MAX_LINE 1024

static char *filename = "/var/log/syslog";

static void analysis_syslog_line(const char *buf, size_t len)
{
    const char *p = NULL;
    const char *q = NULL;
    int offset = 0;
    int  Iskernel = 0;
    int  Ishavepid = 1;
    static int i = 0;
    struct _syslog_s syslog_s;

    if ( (buf == NULL) || (len == 0) )
        return;

    memset(&syslog_s, 0, sizeof(syslog_s));
    q = buf;

    // time
    strncpy(syslog_s.time, q, 15);
    q += 16;

    //system
    p = strchr(q, ' ');
    assert(p != NULL);
    offset = p - q;
    strncpy(syslog_s.system, q, (size_t)offset);
    q += offset + 1;

    //program
    if (strncmp(q, "kernel", strlen("kernel"))== 0) {
        Iskernel = 1;
    }
    if (Iskernel == 1)
        p = strchr(q, ':');
    else
        p = strchr(q, '[');
    if (p == NULL) {
        Ishavepid = 0;
        p = strchr(q, ':');
        assert(p != NULL);
    } else {
        Ishavepid = 1;
    }
    offset = p - q;
    strncpy(syslog_s.program, q, (size_t)offset);
    q += offset;

    //pid
    if (Ishavepid == 1) {
        q = strchr(q, '[');
        assert(q != NULL);
        q ++;
        p = strchr(q, ']');
        assert(p != NULL);
        offset = p - q;
        strncpy(syslog_s.pid, q, (size_t)offset);
        if (Iskernel == 1)
            q += offset + 2;
        else
            q += offset + 3;
    } else {
      //  q += offset + 1;
    }

    //content
    p = strchr(q, '\0');
    assert(p != NULL);
    offset = p - q;
    strncpy(syslog_s.content, q, (size_t)offset);

    printf("\n-----------------\n");
    printf("line    :%s\n", buf);
    printf("time    :%s\n", syslog_s.time);
    printf("system  :%s\n", syslog_s.system);
    printf("program :%s\n", syslog_s.program);
    printf("pid     :%s\n", syslog_s.pid);
    printf("content :%s\n", syslog_s.content);

    i++;
    printf("i:%d\n", i);
    return;
}

void read_syslog_file(const char *filename)
{
    char buf[MAX_LINE];  /*缓冲区*/
    FILE *fp = NULL;            /*文件指针*/
    size_t len = 0;             /*行字符个数*/
    int ret = 0;
    memset(buf, 0, MAX_LINE);

    assert(filename != NULL);
    fp = fopen(filename, "r");
    assert(fp != NULL);

    while(fgets(buf,MAX_LINE,fp) != NULL) {
        len = strlen(buf);
        buf[len-1] = '\0';  /*去掉换行符*/
        if (buf[0] == '\0')
            break;
        analysis_syslog_line(buf, len);
        memset(buf, 0, 1024);
    }

    ret = fclose(fp);
    assert(ret == 0);

    return ;
}

int main(int argc, char *argv[])
{
    if (argc > 2) {
        printf("useage: ./syslog filename\n");
        return 0;
    } else {
        filename = (argc == 2) ? argv[1] : filename;
    }
    read_syslog_file(filename);
    return 0;
}
