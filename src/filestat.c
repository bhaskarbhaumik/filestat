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
/*

    -r, --recursive Recursive traverse all the .

    -t, --type      Type of the output. One of the following options:
                    raw, txt (default), tab, csv, html, xml

    -o, --output    Output file. stdout is default.

    -f, --format    Specify format. Applicable only with output type
                    raw.

*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <getopt.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

#include <sys/file.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>

#include <openssl/md5.h>
#include <openssl/sha.h>

#include "filestat.h"

jmp_buf jump;

extern char *optarg;
extern int optind;
extern int optopt;
extern int opterr;
extern int optreset;
struct option longopts[] = {
    {"version",   no_argument,       NULL, 'v'},
    {"help",      no_argument,       NULL, 'h'},
    {"type",      required_argument, NULL, 't'},
    {"output",    required_argument, NULL, 'o'},
    {"recursive", no_argument,       NULL, 'r'},
    {NULL, 0, NULL, 0}
};

char *header_text[] = {
    "File Name",
    "Full Path",
    "File Size",
    "File User",
    "File UID",
    "File Group",
    "File GID",
    "File Type",
    "File Permission",
    "Octal Permission",
    "Sticky",
    "Access Time",
    "Modify Time",
    "Change Time",
    "Device ID",
    "File Inode",
    "Links",
    "Block Size",
    "Blocks",
    "Checksum",
    "MD5 Digest",
    "SHA256 Digest",
    (char *)NULL
};

const static uint_fast32_t crctab[256] = {
    0x00000000,
    0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc, 0x17c56b6b,
    0x1a864db2, 0x1e475005, 0x2608edb8, 0x22c9f00f, 0x2f8ad6d6,
    0x2b4bcb61, 0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
    0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9, 0x5f15adac,
    0x5bd4b01b, 0x569796c2, 0x52568b75, 0x6a1936c8, 0x6ed82b7f,
    0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3, 0x709f7b7a,
    0x745e66cd, 0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
    0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5, 0xbe2b5b58,
    0xbaea46ef, 0xb7a96036, 0xb3687d81, 0xad2f2d84, 0xa9ee3033,
    0xa4ad16ea, 0xa06c0b5d, 0xd4326d90, 0xd0f37027, 0xddb056fe,
    0xd9714b49, 0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
    0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1, 0xe13ef6f4,
    0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d, 0x34867077, 0x30476dc0,
    0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c, 0x2e003dc5,
    0x2ac12072, 0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16,
    0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca, 0x7897ab07,
    0x7c56b6b0, 0x71159069, 0x75d48dde, 0x6b93dddb, 0x6f52c06c,
    0x6211e6b5, 0x66d0fb02, 0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1,
    0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
    0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e, 0xbfa1b04b,
    0xbb60adfc, 0xb6238b25, 0xb2e29692, 0x8aad2b2f, 0x8e6c3698,
    0x832f1041, 0x87ee0df6, 0x99a95df3, 0x9d684044, 0x902b669d,
    0x94ea7b2a, 0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e,
    0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2, 0xc6bcf05f,
    0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683, 0xd1799b34,
    0xdc3abded, 0xd8fba05a, 0x690ce0ee, 0x6dcdfd59, 0x608edb80,
    0x644fc637, 0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
    0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f, 0x5c007b8a,
    0x58c1663d, 0x558240e4, 0x51435d53, 0x251d3b9e, 0x21dc2629,
    0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5, 0x3f9b762c,
    0x3b5a6b9b, 0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
    0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623, 0xf12f560e,
    0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2, 0xe6ea3d65,
    0xeba91bbc, 0xef68060b, 0xd727bbb6, 0xd3e6a601, 0xdea580d8,
    0xda649d6f, 0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
    0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7, 0xae3afba2,
    0xaafbe615, 0xa7b8c0cc, 0xa379dd7b, 0x9b3660c6, 0x9ff77d71,
    0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad, 0x81b02d74,
    0x857130c3, 0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640,
    0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c, 0x7b827d21,
    0x7f436096, 0x7200464f, 0x76c15bf8, 0x68860bfd, 0x6c47164a,
    0x61043093, 0x65c52d24, 0x119b4be9, 0x155a565e, 0x18197087,
    0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
    0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088, 0x2497d08d,
    0x2056cd3a, 0x2d15ebe3, 0x29d4f654, 0xc5a92679, 0xc1683bce,
    0xcc2b1d17, 0xc8ea00a0, 0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb,
    0xdbee767c, 0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18,
    0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4, 0x89b8fd09,
    0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5, 0x9e7d9662,
    0x933eb0bb, 0x97ffad0c, 0xafb010b1, 0xab710d06, 0xa6322bdf,
    0xa2f33668, 0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
};

char *progname;
extern int errno;

int main(int argc, char *argv[])
{
    int optc;
    int otyp;
    int recurse;
    int null_output;
    FILE *out_fp = (FILE *)NULL;
    char *out_type = (char *)NULL;
    char *out_file = (char *)NULL;

    progname = get_progname(argv[0]);
    if(argc < 2) {
        usage();
        exit(0);
    }

    otyp = 0;
    recurse = 0;
    null_output = 1;

    while((optc = getopt_long(argc, argv, "vht:o:r", longopts, (int *)0)) != EOF) {
        switch (optc) {
            case 'v':
                version();
                exit(0);
                break;
            case 'h':
                usage();
                exit(0);
                break;
            case 'o':
                if(out_file != (char *)NULL) {
                    fprintf(stderr, "%s: output file already specified (%s).\n", progname, out_file);
                    continue;
                } else {
                    out_file = strdup(optarg);
                    if(strcmp(out_file, STD_OUTPUT) == 0) {
                        out_fp = stdout;
                    } else {
                        if((out_fp = fopen(out_file, "w")) == (FILE *)NULL) {
                            perror(out_file);
                            exit(1);
                        }
                    }
                }
                break;
            case 't':
                if(out_type) {
                    fprintf(stderr, "%s: output file type already specified (%s).\n", progname, out_type);
                    continue;
                } else {
                    out_type = strdup(optarg);
                    if((otyp = is_valid_out_type(out_type)) == OUT_TYPE_UNKNOWN) {
                        fprintf(stderr, "%s: invalid output file type specified (%s); please see the usage below:\n", progname, out_type);
                        usage();
                        exit(1);
                    }
                }
                break;
            case 'r':
                recurse = 1;
                break;
            default:
                usage();
                exit(1);
                break;
        }
    }
    if(out_file == (char *)NULL) {
        out_fp = stdout;
    }
    if(optind < argc) null_output = 0;

    /* Main processing */
    if(!null_output) print_file_stat_header(out_fp, otyp);
    while(optind < argc) {
        process_arg(out_fp, otyp, recurse, argv[optind++]);
    }
    if(!null_output) print_file_stat_footer(out_fp, otyp);

    /* Close files and do cleanup */
    if(out_file != (char *)NULL) {
        free(out_file);
    }
    if(out_fp != (FILE *)NULL && out_fp != stdout) {
        fclose(out_fp);
    }
    return 0;
}

char *get_progname(const char *path)
{
    char *s, *p;

    s = strrchr(path, DIR_PATH_CHAR);
    s = (s != (char *)NULL) ? (char *)(s + 1) : (char *)path;
    if((p = strchr(s, EXE_EXT_SEP_CHAR)))
        *p = '\0';
    return strdup(s);
}

void version()
{
    printf("%s - " FILE_STAT_VERSION ".\n", progname);
    printf(FILE_STAT_COPYRIGHT "\n");
    return;
}

void usage()
{
    version();
    printf("\
\nusage: %s [-hrv] [-t type] [-o output-file] [file_or_dir_1 file_or_dir_2 ...]\n\
\t-h --help      give this help\n\
\t-r --recursive recursively traverse any input directory\n\
\t-v --version   display version number\n\
\t-o --output    output file. stdout is default.\n\
\t-t --type      type of the output; one of the following options:\n\
\t               raw, txt (default), tab, csv, htm, xml.\n\
If file name is specified as '" STD_OUTPUT "', input will be read from stdin.\n\n\
Please contact " DEFAULT_CONTACT " for bug reporting or clarification.\n", progname);
    return;
}

int is_valid_out_type(char *out_type)
{
    if(out_type == (char *)NULL) return OUT_TYPE_UNKNOWN;
    if(strcasecmp(out_type, "raw") == 0)      return OUT_TYPE_RAW;
    else if(strcasecmp(out_type, "txt") == 0) return OUT_TYPE_TXT;
    else if(strcasecmp(out_type, "tab") == 0) return OUT_TYPE_TAB;
    else if(strcasecmp(out_type, "csv") == 0) return OUT_TYPE_CSV;
    else if(strcasecmp(out_type, "htm") == 0) return OUT_TYPE_HTM;
    else if(strcasecmp(out_type, "xml") == 0) return OUT_TYPE_XML;
    else return OUT_TYPE_UNKNOWN;
}

void print_file_stat_header(FILE *out_fp, int otyp)
{
    int i = 0;
    switch(otyp) {
        case OUT_TYPE_TAB:
        case OUT_TYPE_CSV:
            fprintf(out_fp, "%s", header_text[i]);
            while(header_text[++i] != (char *)NULL) {
                fprintf(out_fp, (otyp == OUT_TYPE_TAB? "\t%s": ",%s"), header_text[i]);
            }
            fprintf(out_fp, "\r\n");
            break;
        case OUT_TYPE_HTM:
            fprintf(out_fp, "<!doctype html public \"-//W3C//DTD HTML 4.0 Final//EN\">\n<html>\n<head>\n\t<title>File Statistics</title>\n</head>\n<body>\n\t");
            fprintf(out_fp, "<table align='left' border='1' cellspacing='0' cellpadding='2' width='100%%' style='border-collapse: collapse'>\n\t\t<tr align='left' valign='middle'>\n");
            fprintf(out_fp, "\t\t\t<th>%s</th>\n", header_text[i]);
            while(header_text[i] != (char *)NULL) {
                fprintf(out_fp, "\t\t\t<th>%s</th>\n", header_text[i]);
                i++;
            }
            fprintf(out_fp, "\t\t</tr>\n");
            break;
        case OUT_TYPE_XML:
            fprintf(out_fp, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<fileset>\n");
            break;
        case OUT_TYPE_RAW:
        case OUT_TYPE_TXT:
        default:
            fprintf(out_fp, "F i l e   S t a t i s t i c s\n");
    }
    return;
}

void print_file_stat_footer(FILE *out_fp, int otyp)
{
    switch(otyp) {
        case OUT_TYPE_HTM:
            fprintf(out_fp, "\t</table>\n</body>\n</html>\n");
            break;
        case OUT_TYPE_XML:
            fprintf(out_fp, "</fileset>\n");
            break;
        case OUT_TYPE_CSV:
        case OUT_TYPE_TAB:
        case OUT_TYPE_RAW:
        case OUT_TYPE_TXT:
        default:
            break;
    }
    return;
}

void process_arg(FILE *out_fp, int otyp, int recurse, const char *filename)
{
    if(print_file_stat(out_fp, otyp, filename) == 1 && recurse == 1) {
        DIR *dp;
        if((dp = opendir(filename)) == (DIR *)NULL) {
            perror(filename);
            return;
        } else {
            struct dirent *p;
            char *newent = (char *)malloc(1024 * sizeof(char));
            for(p = readdir(dp); p != (struct dirent *)NULL; p = readdir(dp)) {
                if(strcmp(p->d_name, ".") == 0 || strcmp(p->d_name, "..") == 0) continue;
                (void)strcpy(newent, filename);
                (void)strcat(newent, "/");
                (void)strcat(newent, (const char *)p->d_name);
                process_arg(out_fp, otyp, recurse, newent);
            }
            free(newent);
            closedir(dp); dp = (DIR *)NULL;
        }
    }
    return;
}

int print_file_stat(FILE *out_fp, int otyp, const char *filename)
{
    int rc, sep;
    char *sticky;
    char *fullpath;
    char *filetype;
    char *cksum_str;
    char *md5sum_str;
    char *sha256sum_str;
    char *readable_perm;
    struct stat statbuf;
    FTS sbts;

    struct passwd *usrptr;
    struct group  *grpptr;

    if(filename == (const char *)NULL) return -1;

    fullpath = get_realpath(filename);
    //fullpath = canonicalize_file_name(filename);

    /* Get the file stats */
    if(stat(filename, &statbuf) != 0) {
        perror(filename);
        return -1;
    }

#if defined(__linux__)
    sbts.ats_sec = statbuf.st_atim.tv_sec;
    sbts.ats_nsec = statbuf.st_atim.tv_nsec;
    sbts.mts_sec = statbuf.st_mtim.tv_sec;
    sbts.mts_nsec = statbuf.st_mtim.tv_nsec;
    sbts.cts_sec = statbuf.st_ctim.tv_sec;
    sbts.cts_nsec = statbuf.st_ctim.tv_nsec;
#elif defined(__APPLE__) && defined(__MACH__)
    sbts.ats_sec = statbuf.st_atimespec.tv_sec;
    sbts.ats_nsec = statbuf.st_atimespec.tv_nsec;
    sbts.mts_sec = statbuf.st_mtimespec.tv_sec;
    sbts.mts_nsec = statbuf.st_mtimespec.tv_nsec;
    sbts.cts_sec = statbuf.st_ctimespec.tv_sec;
    sbts.cts_nsec = statbuf.st_ctimespec.tv_nsec;
#endif

    if((usrptr = getpwuid(statbuf.st_uid)) == (struct passwd *)NULL) return -1; /* Get the file owner user name */
    if((grpptr = getgrgid(statbuf.st_gid)) == (struct group  *)NULL) return -1; /* Get the file owner group name */

    filetype = (char *)malloc(23 * sizeof(char));
    readable_perm = (char *)malloc(11 * sizeof(char));

    /* Get the file type */
    if(S_ISFIFO(statbuf.st_mode)) {
        readable_perm[0] = 'p';
        strcpy(filetype, "fifo file");
    } else if(S_ISDIR(statbuf.st_mode)) {
        readable_perm[0] = 'd';
        strcpy(filetype, "directory");
    } else if(S_ISCHR(statbuf.st_mode)) {
        readable_perm[0] = 'c';
        strcpy(filetype, "character special file");
    } else if(S_ISBLK(statbuf.st_mode)) {
        readable_perm[0] = 'b';
        strcpy(filetype, "block special file");
    } else if(S_ISLNK(statbuf.st_mode)) {
        readable_perm[0] = 'l';
        strcpy(filetype, "symbolic link file");
    } else if(S_ISSOCK(statbuf.st_mode)) {
        readable_perm[0] = 's';
        strcpy(filetype, "socket file");
    } else {
        readable_perm[0] = '-';
        strcpy(filetype, "regular file");
    }

    if(readable_perm[0] == '-') {
        cksum_str = compute_cksum(filename);
        md5sum_str = compute_md5sum(filename);
        sha256sum_str = compute_sha256sum(filename);
    } else {
        cksum_str = strdup(CKSUM_NA);
        md5sum_str = strdup(CKSUM_NA);
        sha256sum_str = strdup(CKSUM_NA);
    }
    /* Get the file access */
    readable_perm[1] = ((statbuf.st_mode)&(S_IRUSR))? 'r': '-';
    readable_perm[2] = ((statbuf.st_mode)&(S_IWUSR))? 'w': '-';
    readable_perm[3] = ((statbuf.st_mode)&(S_IXUSR))? 'x': '-';
    readable_perm[4] = ((statbuf.st_mode)&(S_IRGRP))? 'r': '-';
    readable_perm[5] = ((statbuf.st_mode)&(S_IWGRP))? 'w': '-';
    readable_perm[6] = ((statbuf.st_mode)&(S_IXGRP))? 'x': '-';
    readable_perm[7] = ((statbuf.st_mode)&(S_IROTH))? 'r': '-';
    readable_perm[8] = ((statbuf.st_mode)&(S_IWOTH))? 'w': '-';
    readable_perm[9] = ((statbuf.st_mode)&(S_IXOTH))? 'x': '-';

    readable_perm[10] = '\0';

    /* Get the sticky bit details */
    sticky = (char *)malloc(25 * sizeof(char));

    if((statbuf.st_mode)&(S_ISUID)) {
        readable_perm[3] = 's';
        strcpy(sticky, "set user on execution");
    } else if((statbuf.st_mode)&(S_ISGID)) {
        readable_perm[6] = 's';
        strcpy(sticky, "set group on execution");
    } else if((statbuf.st_mode)&(S_ISVTX)) {
        readable_perm[9] = 't';
        strcpy(sticky, "save text even after use");
    } else {
        sticky[0] = '\0';
    }

    rc = (int)(readable_perm[0] == 'd');

    switch(otyp) {
        case OUT_TYPE_TAB:
        case OUT_TYPE_CSV:
            sep = (otyp == OUT_TYPE_TAB)? '\t': ',';
            fprintf(out_fp, "\"%s\"%c\"%s\"%c%d%c%s%c%d%c%s%c%d%c%s%c%s%c%o%c%s%c%s%c%s%c%s%c%d%c%d%c%d%c%d%c%d%c%s%c%s%c%s\r\n",
                    filename, sep,
                    fullpath, sep,
                    (int)statbuf.st_size, sep,
                    usrptr->pw_name, sep,
                    (int)statbuf.st_uid, sep,
                    grpptr->gr_name, sep,
                    (int)statbuf.st_gid, sep,
                    filetype, sep,
                    readable_perm, sep,
                    statbuf.st_mode, sep,
                    sticky, sep,
                    tm2isots(sbts.ats_sec, sbts.ats_nsec), sep,
                    tm2isots(sbts.mts_sec, sbts.mts_nsec), sep,
                    tm2isots(sbts.cts_sec, sbts.cts_nsec), sep,
                    (int)statbuf.st_dev, sep,
                    (int)statbuf.st_ino, sep,
                    (int)statbuf.st_nlink, sep,
                    (int)statbuf.st_blksize, sep,
                    (int)statbuf.st_blocks, sep,
                    cksum_str, sep,
                    md5sum_str, sep,
                    sha256sum_str);
            break;
        case OUT_TYPE_HTM:
            fprintf(out_fp, "\t\t<tr align='left' valign='middle'>\n\t\t\t<td>%s</td>\n\t\t\t<td>%s</td>\n\t\t\t<td>%d</td>\n\t\t\t<td>%s</td>\n\t\t\t<td>%d</td>\n\t\t\t<td>%s</td>\n\t\t\t<td>%d</td>\n\t\t\t<td>%s</td>\n\t\t\t<td>%s</td>\n\t\t\t<td>%o</td>\n\t\t\t<td>%s</td>\n\t\t\t<td>%s</td>\n\t\t\t<td>%s</td>\n\t\t\t<td>%s</td>\n\t\t\t<td>%d</td>\n\t\t\t<td>%d</td>\n\t\t\t<td>%d</td>\n\t\t\t<td>%d</td>\n\t\t\t<td>%d</td>\n\t\t\t<td>%s</td>\n\t\t\t<td>%s</td>\n\t\t\t<td>%s</td>\n\t\t</tr>\n",
                    filename,
                    fullpath,
                    (int)statbuf.st_size,
                    usrptr->pw_name,
                    (int)statbuf.st_uid,
                    grpptr->gr_name,
                    (int)statbuf.st_gid,
                    filetype,
                    readable_perm,
                    statbuf.st_mode,
                    sticky,
                    tm2isots(sbts.ats_sec, sbts.ats_nsec),
                    tm2isots(sbts.mts_sec, sbts.mts_nsec),
                    tm2isots(sbts.cts_sec, sbts.cts_nsec),
                    (int)statbuf.st_dev,
                    (int)statbuf.st_ino,
                    (int)statbuf.st_nlink,
                    (int)statbuf.st_blksize,
                    (int)statbuf.st_blocks,
                    cksum_str,
                    md5sum_str,
                    sha256sum_str);
            break;
        case OUT_TYPE_XML:
            fprintf(out_fp, "\t<file>\n\t\t<filename>%s</filename>\n\t\t<path>%s</path>\n\t\t<size>%d</size>\n\t\t<user>%s</user>\n\t\t<uid>%d</uid>\n\t\t<group>%s</group>\n\t\t<gid>%d</gid>\n\t\t<type>%s</type>\n\t\t<perm>%s</perm>\n\t\t<octalperm>%o</octalperm>\n\t\t<sticky>%s</sticky>\n\t\t<atime>%s</atime>\n\t\t<mtime>%s</mtime>\n\t\t<ctime>%s</ctime>\n\t\t<devid>%d</devid>\n\t\t<inode>%d</inode>\n\t\t<links>%d</links>\n\t\t<blocksize>%d</blocksize>\n\t\t<blocks>%d</blocks>\n\t\t<cksum>%s</cksum>\n\t\t<md5sum>%s</md5sum>\n\t\t<sha256sum>%s</sha256sum>\n\t</file>\n",
                    filename,
                    fullpath,
                    (int)statbuf.st_size,
                    usrptr->pw_name,
                    statbuf.st_uid,
                    grpptr->gr_name,
                    statbuf.st_gid,
                    filetype,
                    readable_perm,
                    statbuf.st_mode,
                    sticky,
                    tm2isots(sbts.ats_sec, sbts.ats_nsec),
                    tm2isots(sbts.mts_sec, sbts.mts_nsec),
                    tm2isots(sbts.cts_sec, sbts.cts_nsec),
                    (int)statbuf.st_dev,
                    (int)statbuf.st_ino,
                    (int)statbuf.st_nlink,
                    (int)statbuf.st_blksize,
                    (int)statbuf.st_blocks,
                    cksum_str,
                    md5sum_str,
                    sha256sum_str);
            break;
        case OUT_TYPE_RAW:
        case OUT_TYPE_TXT:
        default:
            fprintf(out_fp, "File Name  : %s\n", filename);
            fprintf(out_fp, "Full Path  : %s\n", fullpath);
            fprintf(out_fp, "File Size  : %d bytes\n", (int)statbuf.st_size);
            fprintf(out_fp, "File User  : %s [uid %d]\n", usrptr->pw_name, statbuf.st_uid);
            fprintf(out_fp, "File Group : %s [gid %d]\n", grpptr->gr_name, statbuf.st_gid);
            fprintf(out_fp, "File Type  : %s\n", filetype);
            fprintf(out_fp, "File Access: %s [octal %o] %s\n", readable_perm, statbuf.st_mode, sticky);
            fprintf(out_fp, "Access Time: %s [time of last access]\n", tm2isots(sbts.ats_sec, sbts.ats_nsec));
            fprintf(out_fp, "Modify Time: %s [time of last data modification]\n", tm2isots(sbts.mts_sec, sbts.mts_nsec));
            fprintf(out_fp, "Change Time: %s [time of last file status change]\n", tm2isots(sbts.cts_sec, sbts.cts_nsec));
            fprintf(out_fp, "Device ID  : %d\n", (int)statbuf.st_dev);
            fprintf(out_fp, "File i-Node: %d\n", (int)statbuf.st_ino);
            fprintf(out_fp, "Links      : %d\n", (int)statbuf.st_nlink);
            fprintf(out_fp, "Block Size : %d\n", (int)statbuf.st_blksize);
            fprintf(out_fp, "Blocks     : %d\n", (int)statbuf.st_blocks);
            fprintf(out_fp, "Checksum   : %s\n", cksum_str);
            fprintf(out_fp, "MD5 Digest : %s\n", md5sum_str);
            fprintf(out_fp, "SHA256 SUM : %s\n\n", sha256sum_str);
    }
    if(!memcheck(fullpath))      free(fullpath);
    if(!memcheck(filetype))      free(filetype);
    if(!memcheck(readable_perm)) free(readable_perm);
    if(!memcheck(sticky))        free(sticky);
    if(!memcheck(cksum_str))     free(cksum_str);
    if(!memcheck(md5sum_str))    free(md5sum_str);
    if(!memcheck(sha256sum_str)) free(sha256sum_str);

    return rc;
}

char *get_realpath(const char *filename)
{
    int path_max;
    char *resolved_path;
#ifdef PATH_MAX
    path_max = PATH_MAX;
#else
    path_max = pathconf(filename, _PC_PATH_MAX);
    if (path_max <= 0)
        path_max = 4096;
#endif
    resolved_path = (char *)malloc(path_max * sizeof(char));
    if(!realpath(filename, resolved_path)) {
        perror(filename);
        exit(1);
    }
    return resolved_path;
}

char *tm2isots(time_t sec, long nanosec)
{
    char *ts;
    struct tm *t;
    ts = (char *)malloc(30 * sizeof(char));
    t = localtime(&sec);
    if(!strftime(ts, 29, "%Y-%m-%d %H:%M:%S.", t)) {
        fprintf(stderr, "error: can't format timestamp");
        return (char *)NULL;
    }
    sprintf(&ts[20], "%09ld", nanosec);
    ts[29] = '\0';
    return ts;
}

char *compute_cksum(const char *filename)
{
    FILE *fp;
    char *sum;
    if((fp = fopen(filename, "r")) == (FILE *)NULL) {
        perror(filename);
        return (char *)"-";
    }
    sum = (char *)calloc(12, sizeof(char));
    if(cksum(fp, sum) != 0) {
        fprintf(stderr, "%s: can't compute the checksum for the input file '%s'\n", progname, filename);
        return (char *)"-";
    }
    if(fp != (FILE *)NULL) {
        fclose(fp);
    }

    return sum;
}

char *compute_md5sum(const char *filename)
{
    int i;
    FILE *fp;
    char *sum;
    unsigned char *digest;
    if((fp = fopen(filename, "r")) == (FILE *)NULL) {
        perror(filename);
        return (char *)"-";
    }
    digest = (unsigned char *)calloc(17, sizeof(unsigned char));
    if(mdfile(fp, digest) != 0) {
        fprintf(stderr, "%s: can't compute the md5 message digest for the input file '%s'\n", progname, filename);
        return (char *)"-";
    }
    if(fp != (FILE *)NULL) {
        fclose(fp);
    }

    sum = (char *)malloc(33 * sizeof(char));
    for (i = 0; i < 16; ++i) {
        sprintf(&(sum[2*i]), "%02x", digest[i]);
    }
    sum[32] = '\0';
    free(digest);

    return sum;
}

int mdfile(FILE *fp, unsigned char *digest)
{
    unsigned char buf[1024];
    MD5_CTX ctx;
    int n;

    MD5_Init(&ctx);
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
        MD5_Update(&ctx, buf, n);
    MD5_Final(digest, &ctx);
    if (ferror(fp))
        return -1;
    return 0;
}

/* Calculate and print the checksum and length in bytes
   of file FILE, or of the standard input if FILE is "-".
   If PRINT_NAME is true, print FILE next to the checksum and size.
   Return true if successful.  */

int cksum(FILE *fp, char *cs)
{
    unsigned char buf[BUFLEN];
    uint_fast32_t crc = 0;
    uintmax_t length = 0;
    size_t bytes_read;

    while ((bytes_read = fread(buf, 1, BUFLEN, fp)) > 0) {
        unsigned char *cp = buf;

        if (length + bytes_read < length) {
            perror("file too long");
            return 1;
        }
        length += bytes_read;
        while (bytes_read--)
            crc = (crc << 8) ^ crctab[((crc >> 24) ^ *cp++) & 0xFF];
        if (feof(fp))
            break;
    }

    if (ferror(fp)) {
        perror("error");
        return 1;
    }

    for (; length; length >>= 8)
        crc = (crc << 8) ^ crctab[((crc >> 24) ^ length) & 0xFF];

    crc = ~crc & 0xFFFFFFFF;

    sprintf(cs, "%u", (unsigned int) crc);

    return 0;
}

char *compute_sha256sum(const char *filename)
{
    int i;
    FILE *fp;
    char *sum;
    unsigned char *digest;
    if((fp = fopen(filename, "r")) == (FILE *)NULL) {
        perror(filename);
        return (char *)"-";
    }
    digest = (unsigned char *)calloc(33, sizeof(unsigned char));
    if(sha256file(fp, digest) != 0) {
        fprintf(stderr, "%s: can't compute the SHA256 message digest for the input file '%s'\n", progname, filename);
        return (char *)"-";
    }
    if(fp != (FILE *)NULL) {
        fclose(fp);
    }

    sum = (char *)malloc(65 * sizeof(char));
    for (i = 0; i < 32; ++i) {
        sprintf(&(sum[2*i]), "%02x", digest[i]);
    }
    sum[64] = '\0';
    free(digest);
    return sum;
}

int sha256file(FILE *fp, unsigned char *digest)
{
    unsigned char buf[1024];
    SHA256_CTX ctx;
    int n;

    SHA256_Init(&ctx);
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
        SHA256_Update(&ctx, buf, n);
    SHA256_Final(digest, &ctx);
    if (ferror(fp))
        return -1;
    return 0;
}

void segv(int sig)
{
    longjmp(jump, 1);
    return;
}

int memcheck(void *x)
{
    volatile char c;
    int illegal = 0;
    signal(SIGSEGV, segv);
    if(!setjmp(jump)) {
        c = *(char *) (x);
    } else {
        illegal = 1;
    }
    signal(SIGSEGV, SIG_DFL);
    return illegal;
}
