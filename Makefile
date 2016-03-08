all:syslog

syslog:syslog.c
	gcc -g -Wall syslog.c -o syslog
clean:
	rm syslog 
