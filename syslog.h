#ifndef __SYSLOG__H_
#define __SYSLOG__H_

/*
 * syslog struct
 */
struct _syslog_s {
    char time[20];
    char system[255];
    char program[255];
    char pid[20];
    char content[1024];
};

void read_syslog_file(const char *filename);

#endif //__SYSLOG_H_
