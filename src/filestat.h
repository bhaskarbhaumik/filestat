/*
# +-------------------------------------------------------------------+
# | Program Name  :  filestat.c                                       |
# | Author        :  Bhaskar Bhaumik (web.bhaskar.bhaumik@gmail.com)  |
# | Version       :  0.1                                              |
# | Date Created  :  October 13, 2018                                 |
# | Description   :  This program gives various stats about a file.   |
# | Revision      :                                                   |
# |    Ver  Date        Author       Comment                          |
# |    ~~~  ~~~~~~~~~~  ~~~~~~~~~~~  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~   |
# |    1.0  2018-10-13  bhaskar      Initial version.                 |
# +-------------------------------------------------------------------+
*/
#ifndef _FILE_STAT_H
#define _FILE_STAT_H

#define _GNU_SOURCE

#ifdef __cplusplus
extern "C" {
#endif


#define S_IRWXS         0007000

#ifndef S_IFMT
#define S_IFMT          0170000
#endif

#ifndef S_IFLNK
#define S_IFLNK         0120000         /* symbolic link */
#endif

#ifndef S_IFSOCK
#define S_IFSOCK        0140000         /* socket */
#endif

#ifndef S_ISVTX
#define S_ISVTX         0001000         /* save text even after use */
#endif

#define __S_ISLNK(m)      (((m)&(S_IFMT)) == (S_IFLNK))
#define __S_ISSOCK(m)     (((m)&(S_IFMT)) == (S_IFSOCK))

#define FILE_STAT_VERSION   "filestat  version 0.1"
#define FILE_STAT_COPYRIGHT "Author: Bhaskar Bhaumik (Created on October 13, 2018)"
#define DEFAULT_CONTACT     "Bhaskar Bhaumik (mailto:we.bhaskar.bhaumik@gmail.com)"
#define STD_OUTPUT          "-"
#define DIR_PATH_CHAR       '/'
#define EXE_EXT_SEP_CHAR    '.'
#define DEFAULT_FORMAT      "%n %s\n"

#define OUT_TYPE_UNKNOWN    0
#define OUT_TYPE_RAW        1
#define OUT_TYPE_TXT        2
#define OUT_TYPE_TAB        3
#define OUT_TYPE_CSV        4
#define OUT_TYPE_HTM        5
#define OUT_TYPE_XML        6

#define BUFLEN              (1 << 16)
#define CKSUM_NA            "N/A"

struct fts {
    time_t ats_sec;
    long ats_nsec;
    time_t mts_sec;
    long mts_nsec;
    time_t cts_sec;
    long cts_nsec;
};
typedef struct fts FTS;

extern char *progname;

char *get_progname(const char *path);
void version(void);
void usage(void);
int is_valid_out_type(char *out_type);
void print_file_stat_header(FILE *out_fp, int otyp);
void print_file_stat_footer(FILE *out_fp, int otyp);
void process_arg(FILE *out_fp, int otyp, int recurse, const char *filename);
int print_file_stat(FILE *out_fp, int otyp, const char *filename);
char *get_realpath(const char *file_name);
char *tm2isots(time_t sec, long nanosec);
char *compute_cksum(const char *filename);
char *compute_md5sum(const char *filename);
char *compute_sha256sum(const char *filename);
int mdfile(FILE *fp, unsigned char *digest);
int sha256file(FILE *fp, unsigned char *digest);
int cksum(FILE *fp, char *cs);
void segv(int sig);
int memcheck(void *x);

#ifdef __cplusplus
}
#endif

#endif /* _FILE_STAT_H */
