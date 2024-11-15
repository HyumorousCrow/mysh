#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#define MAXLINE 1024
#define MAXARGS 128
#define MAXJOBS 16
#define MAXJID 1<<16
#define UNDEF 0
#define FG 1
#define BG 2
#define ST 3

extern char **environ;
char prompt[] = "tsh> ";
int verbose = 0;
int nextjid = 1;
char sbuf[MAXLINE];

struct job_t {
    pid_t pid;
    int jid;
    int state;
    char cmdline[MAXLINE];
};
struct job_t jobs[MAXJOBS];

void eval(char *cmdline);
int builtin_cmd(char **argv);
void do_bgfg(char **argv);
void waitfg(pid_t pid);
void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
int parseline(const char *cmdline, char **argv);
void sigquit_handler(int sig);
void clearjob(struct job_t *job);
void initjobs(struct job_t *jobs);
int maxjid(struct job_t *jobs);
int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline);
int deletejob(struct job_t *jobs, pid_t pid);
pid_t fgpid(struct job_t *jobs);
struct job_t *getjobpid(struct job_t *jobs, pid_t pid);
struct job_t *getjobjid(struct job_t *jobs, int jid);
int pid2jid(pid_t pid);
void listjobs(struct job_t *jobs);
void usage(void);
void unix_error(char *msg);
void app_error(char *msg);
typedef void handler_t(int);
handler_t *Signal(int signum, handler_t *handler);
pid_t Fork(void);

int main(int argc, char **argv) {
    char c;
    char cmdline[MAXLINE];
    int emit_prompt = 1;

    dup2(1, 2);

    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h':
            usage();
            break;
        case 'v':
            verbose = 1;
            break;
        case 'p':
            emit_prompt = 0;
            break;
        default:
            usage();
        }
    }

    Signal(SIGINT, sigint_handler);
    Signal(SIGTSTP, sigtstp_handler);
    Signal(SIGCHLD, sigchld_handler);
    Signal(SIGQUIT, sigquit_handler);

    initjobs(jobs);

    while (1) {
        if (emit_prompt) {
            printf("%s", prompt);
            fflush(stdout);
        }
        if ((fgets(cmdline, MAXLINE, stdin) == NULL) && ferror(stdin))
            app_error("fgets error");
        if (feof(stdin)) {
            fflush(stdout);
            exit(0);
        }
        eval(cmdline);
        fflush(stdout);
    }
    exit(0);
}

void eval(char *cmdline) {
    int bg;
    int state;
    pid_t pid;
    char buf[MAXLINE];
    char *argv[MAXARGS];

    strcpy(buf, cmdline);
    bg = parseline(buf, argv);
    if (argv[0] == NULL) {
        return;
    }

    sigset_t mask_all, mask_one, prev_one;

    sigfillset(&mask_all);
    sigemptyset(&mask_one);
    sigaddset(&mask_one, SIGCHLD);

    if (!builtin_cmd(argv)) {
        sigprocmask(SIG_BLOCK, &mask_all, &prev_one);
        if ((pid = Fork()) == 0) {
            sigprocmask(SIG_BLOCK, &prev_one, NULL);
            setpgid(0, 0);
            if (execve(argv[0], argv, environ) < 0) {
                printf("%s: Command not found!", argv[0]);
                exit(0);
            }
        }

        state = bg ? BG : FG;
        sigprocmask(SIG_BLOCK, &mask_all, NULL);
        addjob(jobs, pid, state, cmdline);
        sigprocmask(SIG_SETMASK, &prev_one, NULL);

        if (!bg) {
            waitfg(pid);
        } else {
            printf("[%d] (%d) %s", pid2jid(pid), pid, cmdline);
        }
    }
    return;
}

int parseline(const char *cmdline, char **argv) {
    static char array[MAXLINE];
    char *buf = array;
    char *delim;
    int argc;
    int bg;

    strcpy(buf, cmdline);
    buf[strlen(buf) - 1] = ' ';
    while (*buf && (*buf == ' '))
        buf++;

    argc = 0;
    if (*buf == '\'') {
        buf++;
        delim = strchr(buf, '\'');
    } else {
        delim = strchr(buf, ' ');
    }

    while (delim) {
        argv[argc++] = buf;
        *delim = '\0';
        buf = delim + 1;
        while (*buf && (*buf == ' '))
            buf++;

        if (*buf == '\'') {
            buf++;
            delim = strchr(buf, '\'');
        } else {
            delim = strchr(buf, ' ');
        }
    }
    argv[argc] = NULL;

    if (argc == 0)
        return 1;

    if ((bg = (*argv[argc - 1] == '&')) != 0) {
        argv[--argc] = NULL;
    }
    return bg;
}

int builtin_cmd(char **argv) {
    if (!strcmp(argv[0], "quit")) {
        exit(0);
    }
    if (!strcmp(argv[0], "&")) {
        return 1;
    }
    if (!strcmp(argv[0], "jobs")) {
        listjobs(jobs);
        return 1;
    }
    return 0;
}

void do_bgfg(char **argv) {
    sigset_t mask_all, prev_all;
    sigfillset(&mask_all);
    struct job_t *job;
    sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
    if (argv[1][0] == '%') {
        int jid = atoi(&argv[1][1]);
        job = getjobjid(jobs, jid);
    } else {
        pid_t pid = atoi(argv[1]);
        job = getjobpid(jobs, pid);
    }
    sigprocmask(SIG_SETMASK, &prev_all, NULL);

    if (!strcmp(argv[0], "bg")) {
        if (kill(-job->pid, SIGCONT) < 0)
            unix_error("SIGCONT error");
        job->state = BG;
        printf("[%d] (%d) %s", job->jid, job->pid, job->cmdline);

    } else {
        if (job->state == ST)
            if (kill(-job->pid, SIGCONT) < 0)
                unix_error("SIGCONT error");
        job->state = FG;
        waitfg(job->pid);
    }

    return;
}

void waitfg(pid_t pid) {
    sigset_t mask_empty, mask_all, prev_all;

    sigemptyset(&mask_empty);
    sigfillset(&mask_all);

    while (fgpid(jobs) == pid) {
        sigsuspend(&mask_empty);
    }

    sigprocmask(SIG_SETMASK, &prev_all, NULL);
}

void sigchld_handler(int sig) {
    int olderrno = errno;
    int status;
    pid_t pid;
    sigset_t mask_all, prev_all;

    sigfillset(&mask_all);

    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        if (WIFEXITED(status)) {
            sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
            deletejob(jobs, pid);
            sigprocmask(SIG_SETMASK, &prev_all, NULL);
        } else if (WIFSIGNALED(status)) {
            sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
            printf("Job [%d] (%d) terminated by signal %d\n",
                   pid2jid(pid), pid, WTERMSIG(status));
            deletejob(jobs, pid);
            sigprocmask(SIG_SETMASK, &prev_all, NULL);
        } else if (WIFSTOPPED(status)) {
            printf("Job [%d] (%d) stopped by signal %d\n",
                   pid2jid(pid), pid, WSTOPSIG(status));
        }
    }

    if (pid < 0 && errno != ECHILD) {
        unix_error("waitpid error");
    }

    errno = olderrno;
}

void sigint_handler(int sig) {
    int olderrno = errno;
    pid_t pid;
    sigset_t mask_all, prev_all;

    sigfillset(&mask_all);
    sigprocmask(SIG_BLOCK, &mask_all, &prev_all);

    pid = fgpid(jobs);
    if (pid > 0) {
        if (kill(-pid, SIGINT) < 0) {
            unix_error("kill (SIGINT) error");
        }
    }

    sigprocmask(SIG_SETMASK, &prev_all, NULL);
    errno = olderrno;
}

void sigtstp_handler(int sig) {
    int olderrno = errno;
    int rc;
    sigset_t mask_all, prev_all;
    sigfillset(&mask_all);
    sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
    pid_t pid = fgpid(jobs);
    sigprocmask(SIG_SETMASK, &prev_all, NULL);
    if (pid) {
        if ((rc = kill(-pid, sig)) < 0)
            unix_error("SIGTSTP error");
    }
    errno = olderrno;
    return;
}

void clearjob(struct job_t *job) {
    job->pid = 0;
    job->jid = 0;
    job->state = UNDEF;
    job->cmdline[0] = '\0';
}

void initjobs(struct job_t *jobs) {
    int i;

    for (i = 0; i < MAXJOBS; i++)
        clearjob(&jobs[i]);
}

int maxjid(struct job_t *jobs) {
    int i, max = 0;

    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].jid > max)
            max = jobs[i].jid;
    return max;
}

int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline) {
    int i;

    if (pid < 1)
        return 0;

    for (i = 0; i < MAXJOBS; i++) {
        if (jobs[i].pid == 0) {
            jobs[i].pid = pid;
            jobs[i].state = state;
            jobs[i].jid = nextjid++;
            if (nextjid > MAXJOBS)
                nextjid = 1;
            strcpy(jobs[i].cmdline, cmdline);
            if (verbose) {
                printf("Added job [%d] %d %s\n", jobs[i].jid, jobs[i].pid, jobs[i].cmdline);
            }
            return 1;
        }
    }
    printf("Tried to create too many jobs\n");
    return 0;
}

int deletejob(struct job_t *jobs, pid_t pid) {
    int i;

    if (pid < 1)
        return 0;

    for (i = 0; i < MAXJOBS; i++) {
        if (jobs[i].pid == pid) {
            clearjob(&jobs[i]);
            nextjid = maxjid(jobs) + 1;
            return 1;
        }
    }
    return 0;
}

pid_t fgpid(struct job_t *jobs) {
    int i;

    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].state == FG)
            return jobs[i].pid;
    return 0;
}

struct job_t *getjobpid(struct job_t *jobs, pid_t pid) {
    int i;

    if (pid < 1)
        return NULL;
    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].pid == pid)
            return &jobs[i];
    return NULL;
}

struct job_t *getjobjid(struct job_t *jobs, int jid) {
    int i;

    if (jid < 1)
        return NULL;
    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].jid == jid)
            return &jobs[i];
    return NULL;
}

int pid2jid(pid_t pid) {
    int i;

    if (pid < 1)
        return 0;
    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].pid == pid) {
            return jobs[i].jid;
        }
    return 0;
}

void listjobs(struct job_t *jobs) {
    int i;

    for (i = 0; i < MAXJOBS; i++) {
        if (jobs[i].pid != 0) {
            printf("[%d] (%d) ", jobs[i].jid, jobs[i].pid);
            switch (jobs[i].state) {
            case BG:
                printf("Running ");
                break;
            case FG:
                printf("Foreground ");
                break;
            case ST:
                printf("Stopped ");
                break;
            default:
                printf("listjobs: Internal error: job[%d].state=%d ", i, jobs[i].state);
            }
            printf("%s", jobs[i].cmdline);
        }
    }
}

void usage(void) {
    printf("Usage: shell [-hvp]\n");
    printf("   -h   print this message\n");
    printf("   -v   print additional diagnostic information\n");
    printf("   -p   do not emit a command prompt\n");
    exit(1);
}

void unix_error(char *msg) {
    fprintf(stdout, "%s: %s\n", msg, strerror(errno));
    exit(1);
}

void app_error(char *msg) {
    fprintf(stdout, "%s\n", msg);
    exit(1);
}

handler_t *Signal(int signum, handler_t *handler) {
    struct sigaction action, old_action;

    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_RESTART;

    if (sigaction(signum, &action, &old_action) < 0)
        unix_error("Signal error");
    return (old_action.sa_handler);
}

void sigquit_handler(int sig) {
    printf("Terminating after receipt of SIGQUIT signal\n");
    exit(1);
}

pid_t Fork(void) {
    pid_t pid;

    if ((pid = fork()) < 0) {
        unix_error("Fork error");
    }
    return pid;
}

