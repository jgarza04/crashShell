#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>


#define MAXLINE 1024

typedef enum {
    running = 0,
    finished = 1,
    suspended = 2,
    continued = 3,
    killed = 4,
    killedDumped = 5,
}p_status;

typedef struct{
	int num;
	int pNum;
	pid_t pid;
	char command[512];
	p_status status;
}job;

static const char * const status_names[] = {
    "running",
    "finished",
    "suspended",
    "continued",
    "killed",
    "killed (core dumped)"
};

static int numJobs = 0;
static job jobs[32];
static int totalJobs = 0;

// Helper function to turn an integer to a string so that I can print it in a signal safe way.
static void intToString(int num, char *buf, size_t buf_size) {
    if (buf_size == 0)
        return;

    size_t i = 0;
    int temp = num;
    int is_negative = 0;

    if (num < 0) {
        is_negative = 1;
        num = -num;
    }

    // Handle zero explicitly
    if (num == 0) {
        if (i < buf_size - 1)
            buf[i++] = '0';
    } else {
        // Convert number to string in reverse order
        while (num > 0 && i < buf_size - 1) {
            buf[i++] = '0' + (num % 10);
            num /= 10;
        }
    }

    if (is_negative && i < buf_size - 1) {
        buf[i++] = '-';
    }

    buf[i] = '\0';

    // Reverse the string in place
    size_t start = 0, end = i - 1;
    while (start < end) {
        char tmp = buf[start];
        buf[start] = buf[end];
        buf[end] = tmp;
        start++;
        end--;
    }
}


void eval(const char **toks, bool bg) { // bg is true iff command ended with &
    assert(toks);
    if (*toks == NULL) return;
    if (strcmp(toks[0], "quit") == 0) {
        if (toks[1] != NULL) {
            const char *msg = "ERROR: quit takes no arguments\n";
            write(STDERR_FILENO, msg, strlen(msg));
        } else {
            exit(0);
        }
    }

    // Implement jobs command
    if(strcmp(toks[0], "jobs") == 0){
	    if(toks[1] != NULL) {
		    const char *msg = "ERROR: jobs takes no arguments\n";
            write(STDERR_FILENO, msg, strlen(msg));
	    }else{
		    for(int i = 0; i < numJobs; i++){
			    char jobsiteration[256];
        		snprintf(jobsiteration, sizeof(jobsiteration),"[%d] (%d)  %s  %s\n",jobs[i].pNum, jobs[i].pid, status_names[jobs[i].status], jobs[i].command);
            	ssize_t error = write(STDOUT_FILENO, jobsiteration, strlen(jobsiteration));
		    }
	    }
	    return;
    }


    if(strcmp(toks[0], "bg") == 0){
        if(toks[1] == NULL){
            const char *msg = "ERROR: bg needs some arguments\n";
            write(STDERR_FILENO, msg, strlen(msg));
            return;
        }else{
            for(int i = 1; toks[i] != NULL; ++i){
                if(toks[i][0] == '%'){
                    char *endptr;
                    errno = 0;
                    long job_num = strtol(toks[i] + 1, &endptr, 10);

                    if (errno != 0 || endptr == toks[i] + 1 || *endptr != '\0') {
                        char errormessage[256];
		                snprintf(errormessage, sizeof(errormessage),"ERROR: bad argument for bg: %s\n", toks[i]);
	                    ssize_t error = write(STDERR_FILENO, errormessage, strlen(errormessage));
                        continue;
                    }

                    bool found = false;
                    for(int j = 0; j < numJobs; ++j){
                        if(jobs[j].pNum == job_num){
                            found = true;
                            pid_t pid = jobs[j].pid;
                            if(jobs[j].status == suspended){
                                if (kill(-pid, SIGCONT) == -1) {
                                    perror("SIGCONT failed");
                                    continue;
                                }
                                /*
                                sigset_t mask;
                                sigemptyset(&mask);
                                sigaddset(&mask, SIGCHLD);

                                if(sigprocmask(SIG_BLOCK, &mask, NULL) != 0){
                                    const char *errormessage = "sigprocmask blocking error\n";
                                    write(STDERR_FILENO, errormessage, strlen(errormessage));
                                    return;
                                }

                                jobs[j].status = running;

                                if(sigprocmask(SIG_UNBLOCK, &mask, NULL) != 0){
                                    const char *errormessage = "sigprocmask blocking error\n";
                                    write(STDERR_FILENO, errormessage, strlen(errormessage));
                                    return;
                                }*/
                                /*char continuedmessage[256];
                                snprintf(continuedmessage, sizeof(continuedmessage),"[%d] (%d)  continued  %s\n", jobs[j].pNum, jobs[j].pid, jobs[j].command);
	                            ssize_t error2 = write(STDOUT_FILENO, continuedmessage, strlen(continuedmessage));*/
                            }
                        }
                    }
                    if(!found){
                        char errormessage[256];		                
                        snprintf(errormessage, sizeof(errormessage),"ERROR: no job %d\n", job_num);
		                ssize_t error = write(STDERR_FILENO, errormessage, strlen(errormessage));
                        continue;
                    }
                }else{
                    char *endptr;
                    errno = 0;
                    long job_pid = strtol(toks[i], &endptr, 10);

                    
                    if (errno != 0 || endptr == toks[i] || *endptr != '\0') {
                        char errormessage[256];
		                snprintf(errormessage, sizeof(errormessage),"ERROR: bad argument for bg: %s\n", toks[i]);
	                    ssize_t error = write(STDERR_FILENO, errormessage, strlen(errormessage));
                        continue;
                    }

                    bool found = false;
                    for(int j = 0; j < numJobs; ++j){
                        if(jobs[j].pid == job_pid){
                            found = true;
                            if(jobs[j].status == suspended){
                                if (kill(-job_pid, SIGCONT) == -1) {
                                    perror("SIGCONT failed");
                                    continue;
                                }
                                
                                /*
                                sigset_t mask;
                                sigemptyset(&mask);
                                sigaddset(&mask, SIGCHLD);

                                if(sigprocmask(SIG_BLOCK, &mask, NULL) != 0){
                                    const char *errormessage = "sigprocmask blocking error\n";
                                    write(STDERR_FILENO, errormessage, strlen(errormessage));
                                    return;
                                }

                                jobs[j].status = running;

                                if(sigprocmask(SIG_UNBLOCK, &mask, NULL) != 0){
                                    const char *errormessage = "sigprocmask blocking error\n";
                                    write(STDERR_FILENO, errormessage, strlen(errormessage));
                                    return;
                                }
                                char continuedmessage[256];
                                snprintf(continuedmessage, sizeof(continuedmessage),"[%d] (%d)  continued  %s\n", jobs[j].pNum, jobs[j].pid, jobs[j].command);
	                            ssize_t error2 = write(STDOUT_FILENO, continuedmessage, strlen(continuedmessage));*/
                            }
                        }
                    }
                    if(!found){
                        char errormessage[256];		                
                        snprintf(errormessage, sizeof(errormessage),"ERROR: no PID %d\n", job_pid);
		                ssize_t error = write(STDERR_FILENO, errormessage, strlen(errormessage));
                        continue;
                    }
                }
            }
        }
        return;
    }

    // Implement fg command
    if(strcmp(toks[0], "fg") == 0){
        if(toks[1] == NULL || toks[2] != NULL){
            const char *msg = "ERROR: fg needs exactly one argument\n";
            write(STDERR_FILENO, msg, strlen(msg));
            return;
        }else{
            if(toks[1][0] == '%'){
                char *endptr;
                errno = 0;
                long job_id = strtol(toks[1] + 1, &endptr, 10);
                    
                if (errno != 0 || endptr == toks[1] + 1 || *endptr != '\0') {
                    char errormessage[256];
		            snprintf(errormessage, sizeof(errormessage),"ERROR: bad argument for fg: %s\n", toks[1]);
	                ssize_t error = write(STDERR_FILENO, errormessage, strlen(errormessage));
                    return;
                }

                // Find the job
                bool found = false;
				for(int j = 0; j < numJobs; ++j){
				    if(jobs[j].pNum == job_id){
					    // Here is where I need to bring the process to the foreground
                        found = true;
                        pid_t pid = jobs[j].pid;
                        if(jobs[j].status == suspended){
                            if (kill(-pid, SIGCONT) == -1) {
                                perror("SIGCONT failed");
                                return;
                            }
                        }

                        sigset_t mask;
                        sigemptyset(&mask);
                        sigaddset(&mask, SIGCHLD);

                        if(sigprocmask(SIG_BLOCK, &mask, NULL) != 0){
                            const char *errormessage = "sigprocmask blocking error\n";
                            write(STDERR_FILENO, errormessage, strlen(errormessage));
                            return;
                        }

                        jobs[j].status = running;
                        
                        if(sigprocmask(SIG_UNBLOCK, &mask, NULL) != 0){
                            const char *errormessage = "sigprocmask blocking error\n";
                            write(STDERR_FILENO, errormessage, strlen(errormessage));
                            return;
                        }

                        if (tcsetpgrp(STDIN_FILENO, jobs[j].pid) == -1) {
                            perror("bringing process to foreground failed\n");
                            return;
                        }

                        int status;
                        while (waitpid(jobs[j].pid, &status, WUNTRACED) == -1) {
                            if (errno == EINTR)
                                continue;
                            else
                                break;
                        }

                        if (tcsetpgrp(STDIN_FILENO, getpgrp()) == -1) {
                            perror("bringing control back to terminal failed\n");
                            return;
                        }

                        if(sigprocmask(SIG_BLOCK, &mask, NULL) != 0){
                            const char *errormessage = "sigprocmask blocking error\n";
                            write(STDERR_FILENO, errormessage, strlen(errormessage));
                            return;
                        };

                        if(WIFEXITED(status) || WIFSIGNALED(status)){
                            if(WIFEXITED(status)){
                                char finishedmessage[256];
                                snprintf(finishedmessage, sizeof(finishedmessage),"[%d] (%d)  finished  %s\n", jobs[j].pNum, jobs[j].pid, jobs[j].command);
	                            ssize_t error2 = write(STDOUT_FILENO, finishedmessage, strlen(finishedmessage));
                            }else{
                                char finishedmessage[256];
                                snprintf(finishedmessage, sizeof(finishedmessage),"[%d] (%d)  killed  %s\n", jobs[j].pNum, jobs[j].pid, jobs[j].command);
	                            ssize_t error2 = write(STDOUT_FILENO, finishedmessage, strlen(finishedmessage));
                            }
                            for(int i = j; i < numJobs - 1; ++i){
                                jobs[i] = jobs[i + 1];   
                            }
                            --numJobs;
                        }else if(WIFSTOPPED(status)) {
                            char finishedmessage[256];
                            snprintf(finishedmessage, sizeof(finishedmessage),"[%d] (%d)  suspended  %s\n", jobs[j].pNum, jobs[j].pid, jobs[j].command);
	                        ssize_t error2 = write(STDOUT_FILENO, finishedmessage, strlen(finishedmessage));
                            
                            jobs[j].status = suspended;
                            
                            
                        }
                        if(sigprocmask(SIG_UNBLOCK, &mask, NULL) != 0){
                            const char *errormessage = "sigprocmask unblocking error\n";
                            write(STDERR_FILENO, errormessage, strlen(errormessage));
                            return;
                        };

                        return;
				    }
			    }

                if(!found){
                    char errormessage[256];		                
                    snprintf(errormessage, sizeof(errormessage),"ERROR: no job %d\n", job_id);
		            ssize_t error = write(STDERR_FILENO, errormessage, strlen(errormessage));
                    return;
                }


            }else{
                char *endptr;
                errno = 0;
                long job_pid = strtol(toks[1], &endptr, 10);
                    
                if (errno != 0 || endptr == toks[1] || *endptr != '\0') {
                    char errormessage[256];
		            snprintf(errormessage, sizeof(errormessage),"ERROR: bad argument for fg: %s\n", toks[1]);
	                ssize_t error = write(STDERR_FILENO, errormessage, strlen(errormessage));
                    return;
                }

                // Find the job
                bool found = false;
				for(int j = 0; j < numJobs; ++j){
				    if(jobs[j].pid == job_pid){
					    // Here is where I need to bring the process to the foreground
                        found = true;

                        if(jobs[j].status == suspended){
                            if (kill(-job_pid, SIGCONT) == -1) {
                                perror("SIGCONT failed");
                                return;
                            }
                        }

                        sigset_t mask;
                        sigemptyset(&mask);
                        sigaddset(&mask, SIGCHLD);

                        if(sigprocmask(SIG_BLOCK, &mask, NULL) != 0){
                            const char *errormessage = "sigprocmask blocking error\n";
                            write(STDERR_FILENO, errormessage, strlen(errormessage));
                            return;
                        }

                        jobs[j].status = running;
                        
                        if(sigprocmask(SIG_UNBLOCK, &mask, NULL) != 0){
                            const char *errormessage = "sigprocmask blocking error\n";
                            write(STDERR_FILENO, errormessage, strlen(errormessage));
                            return;
                        }

                        

                        if (tcsetpgrp(STDIN_FILENO, jobs[j].pid) == -1) {
                            perror("bringing process to foreground failed\n");
                            return;
                        }

                        int status;
                        while (waitpid(jobs[j].pid, &status, WUNTRACED) == -1) {
                            if (errno == EINTR)
                                continue;
                            else
                                break;
                        }

                        if (tcsetpgrp(STDIN_FILENO, getpgrp()) == -1) {
                            perror("bringing control back to terminal failed\n");
                            return;
                        }

                        

                        if(sigprocmask(SIG_BLOCK, &mask, NULL) != 0){
                            const char *errormessage = "sigprocmask blocking error\n";
                            write(STDERR_FILENO, errormessage, strlen(errormessage));
                            return;
                        }

                        if(WIFEXITED(status) || WIFSIGNALED(status)){
                            if(WIFEXITED(status)){
                                char finishedmessage[256];
                                snprintf(finishedmessage, sizeof(finishedmessage),"[%d] (%d)  finished  %s\n", jobs[j].pNum, jobs[j].pid, jobs[j].command);
	                            ssize_t error2 = write(STDOUT_FILENO, finishedmessage, strlen(finishedmessage));
                            }else{
                                char finishedmessage[256];
                                snprintf(finishedmessage, sizeof(finishedmessage),"[%d] (%d)  killed  %s\n", jobs[j].pNum, jobs[j].pid, jobs[j].command);
	                            ssize_t error2 = write(STDOUT_FILENO, finishedmessage, strlen(finishedmessage));
                            }
                            for(int i = j; i < numJobs - 1; ++i){
                                jobs[i] = jobs[i + 1];   
                            }
                            --numJobs;
                        }else if(WIFSTOPPED(status)) {
                            char finishedmessage[256];
                            snprintf(finishedmessage, sizeof(finishedmessage),"[%d] (%d)  suspended  %s\n", jobs[j].pNum, jobs[j].pid, jobs[j].command);
	                        ssize_t error2 = write(STDOUT_FILENO, finishedmessage, strlen(finishedmessage));
                            
                            jobs[j].status = suspended;
                            
                        }
                        if(sigprocmask(SIG_UNBLOCK, &mask, NULL) != 0){
                            const char *errormessage = "sigprocmask unblocking error\n";
                            write(STDERR_FILENO, errormessage, strlen(errormessage));
                            return;
                        };

                        return;
				    }
			    }

                if(!found){
                    char errormessage[256];		                
                    snprintf(errormessage, sizeof(errormessage),"ERROR: no PID %d\n", job_pid);
		            ssize_t error = write(STDERR_FILENO, errormessage, strlen(errormessage));
                    return;
                }
            }
        }
        return;
    }

    // Implement nuke command
    if(strcmp(toks[0], "nuke") == 0){
	    if(toks[1] == NULL){
		    for(int i = 0; i < numJobs; ++i){
			    if(kill(jobs[i].pid, SIGKILL) == -1){
                    perror("Kill failed\n");
                    return;
                }
		    }
	    }else {
		    for(int i = 1; toks[i] != NULL; ++i){
			    if(toks[i][0] == '%'){
				    char *endptr;
                    errno = 0;
                    long job_id = strtol(toks[i] + 1, &endptr, 10);
                    
                    if (errno != 0 || endptr == toks[i] + 1 || *endptr != '\0') {
                        char errormessage[256];
		                snprintf(errormessage, sizeof(errormessage),"ERROR: bad argument for nuke: %s\n", toks[i]);
		                ssize_t error = write(STDERR_FILENO, errormessage, strlen(errormessage));
                        continue;
                    }
                    
                    bool killed = false;
				    for(int j = 0; j < numJobs; ++j){
					    if(jobs[j].pNum == job_id){
						    if(kill(jobs[j].pid, SIGKILL) == -1){
                                perror("Kill failed\n");
                                return;
                            }
                            killed = true;
					    }
				    }
                    if(!killed){
                        char errormessage[256];
		                snprintf(errormessage, sizeof(errormessage),"ERROR: no job %d\n", job_id);
		                ssize_t error = write(STDERR_FILENO, errormessage, strlen(errormessage));
                        continue;
                    }
			    }else{
                    char *endptr;
                    errno = 0;
                    long job_pid = strtol(toks[i], &endptr, 10);
                    
                    if (errno != 0 || endptr == toks[i] || *endptr != '\0') {
                        char errormessage[256];
		                snprintf(errormessage, sizeof(errormessage),"ERROR: bad argument for nuke: %s\n", toks[i]);
		                ssize_t error = write(STDERR_FILENO, errormessage, strlen(errormessage));
                        continue;
                    }
                    
                    bool killed = false;
                    for(int j = 0; j < numJobs; ++j){
					    if(job_pid == jobs[j].pid){
						    if(kill(jobs[j].pid, SIGKILL) == -1){
                                perror("Kill failed\n");
                                return;
                            }
                            killed = true;
					    }
				    }
                    if(!killed){
                        char errormessage[256];
		                snprintf(errormessage, sizeof(errormessage),"ERROR: no PID %d\n", job_pid);
		                ssize_t error = write(STDERR_FILENO, errormessage, strlen(errormessage));
                        continue;
                    }
                }
		    }
	    }

	    return;
    }


    // Check if there is space for another process
    if(numJobs >= 32){
        // For commands other than quit
        const char *msg = "ERROR: too many jobs\n";
        write(STDERR_FILENO, msg, strlen(msg));
	    return;
    }

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);

    if(sigprocmask(SIG_BLOCK, &mask, NULL) != 0){
        const char *errormessage = "sigprocmask blocking error\n";
        write(STDERR_FILENO, errormessage, strlen(errormessage));
        return;
    };

    // Foreground process
    if(!bg){
        pid_t newProcess = fork();
        if(newProcess < 0){
	        const char *errormessage = "ERROR: cannot initialize process\n";
	        write(STDERR_FILENO, errormessage, strlen(errormessage));
            if(sigprocmask(SIG_UNBLOCK, &mask, NULL) != 0){
                const char *errormessage = "sigprocmask unblocking error\n";
                write(STDERR_FILENO, errormessage, strlen(errormessage));
                return;
            }
	        return;
        }
        if (newProcess == 0) { 
            // Child process

            if (setpgid(0, 0) < 0) {
                const char *errormessage = "Foreground job processing error\n";
                write(STDERR_FILENO, errormessage, strlen(errormessage));
                return;
            }

            // Restore default signal handling for suspend-related signals so the foreground job can be suspended.
            signal(SIGTSTP, SIG_DFL);
            signal(SIGTTIN, SIG_DFL);
            signal(SIGTTOU, SIG_DFL);
            signal(SIGINT, SIG_DFL);
            signal(SIGTSTP, SIG_DFL);
            signal(SIGQUIT, SIG_DFL);
            

            // Unblock the signal
            if(sigprocmask(SIG_UNBLOCK, &mask, NULL) != 0){
                const char *errormessage = "sigprocmask unblocking error\n";
                write(STDERR_FILENO, errormessage, strlen(errormessage));
                return;
            }

            execvp(toks[0], (char * const*)toks);
            // If this code is being run, it means that execvp was not successfull
            char errormessage[256];
		    snprintf(errormessage, sizeof(errormessage),"ERROR: cannot run %s\n", toks[0]);
		    ssize_t error = write(STDERR_FILENO, errormessage, strlen(errormessage));
		    exit(1);
        }else{
            // Parent process
            numJobs++;
	        totalJobs++;
	        jobs[numJobs - 1].num = numJobs;
	        jobs[numJobs - 1].pNum = totalJobs;
	        jobs[numJobs - 1].pid = newProcess;
	        strncpy(jobs[numJobs - 1].command, toks[0], sizeof(jobs[numJobs - 1].command) - 1);
	        jobs[numJobs - 1].command[sizeof(jobs[numJobs - 1].command) - 1] = '\0';
	        jobs[numJobs - 1].status = running;

            if(sigprocmask(SIG_UNBLOCK, &mask, NULL) != 0){
                const char *errormessage = "sigprocmask unblocking error\n";
                write(STDERR_FILENO, errormessage, strlen(errormessage));
                return;
            }

            if (tcsetpgrp(STDIN_FILENO, newProcess) != 0){
                const char *errormessage = "Foreground job processing error\n";
                write(STDERR_FILENO, errormessage, strlen(errormessage));
                return;
            }
            
            
            int status;
            while (waitpid(newProcess, &status, WUNTRACED) == -1){
                if (errno == EINTR)
                    continue;
                else
                    break;
            }


            if (tcsetpgrp(STDIN_FILENO, getpgrp()) == -1) {
                const char *errormessage = "Foreground job processing error\n";
                write(STDERR_FILENO, errormessage, strlen(errormessage));
                return;
            }

            
            if(WIFEXITED(status)){
                char finishedmessage[256];
                snprintf(finishedmessage, sizeof(finishedmessage),"[%d] (%d)  finished  %s\n", jobs[numJobs - 1].pNum, jobs[numJobs - 1].pid, jobs[numJobs - 1].command);
	            ssize_t error2 = write(STDOUT_FILENO, finishedmessage, strlen(finishedmessage));
            }else if (WIFSIGNALED(status)){
                char finishedmessage[256];
                snprintf(finishedmessage, sizeof(finishedmessage),"[%d] (%d)  killed  %s\n", jobs[numJobs - 1].pNum, jobs[numJobs - 1].pid, jobs[numJobs - 1].command);
	            ssize_t error2 = write(STDOUT_FILENO, finishedmessage, strlen(finishedmessage));
            }else if (WIFSTOPPED(status)){
                char finishedmessage[256];
                snprintf(finishedmessage, sizeof(finishedmessage),"[%d] (%d)  suspended  %s\n", jobs[numJobs - 1].pNum, jobs[numJobs - 1].pid, jobs[numJobs - 1].command);
	            ssize_t error2 = write(STDOUT_FILENO, finishedmessage, strlen(finishedmessage));
                if(sigprocmask(SIG_BLOCK, &mask, NULL) != 0){
                    const char *errormessage = "sigprocmask blocking error\n";
                    write(STDERR_FILENO, errormessage, strlen(errormessage));
                    return;
                }
                jobs[numJobs - 1].status = suspended;
                if(sigprocmask(SIG_UNBLOCK, &mask, NULL) != 0){
                    const char *errormessage = "sigprocmask unblocking error\n";
                    write(STDERR_FILENO, errormessage, strlen(errormessage));
                    return;
                }   
                return;
            }

            if(sigprocmask(SIG_BLOCK, &mask, NULL) != 0){
                const char *errormessage = "sigprocmask blocking error\n";
                write(STDERR_FILENO, errormessage, strlen(errormessage));
                return;
            }

            memset(&jobs[numJobs - 1], 0, sizeof(job));
            --numJobs;

            if(sigprocmask(SIG_UNBLOCK, &mask, NULL) != 0){
                const char *errormessage = "sigprocmask unblocking error\n";
                write(STDERR_FILENO, errormessage, strlen(errormessage));
                return;
            }

        }
    }else{
        // Initialize a background process
        pid_t newProcess = fork();
        if(newProcess < 0){
	        const char *errormessage = "ERROR: cannot initialize process\n";
	        write(STDERR_FILENO, errormessage, strlen(errormessage));
            if(sigprocmask(SIG_UNBLOCK, &mask, NULL) != 0){
                const char *errormessage = "sigprocmask unblocking error\n";
                write(STDERR_FILENO, errormessage, strlen(errormessage));
                return;
            }
	        return;
        }

        if(newProcess == 0){
            if (setpgid(0, 0) < 0) {
                const char *errormessage = "Foreground job processing error\n";
                write(STDERR_FILENO, errormessage, strlen(errormessage));
                exit(1);
            }

            if(sigprocmask(SIG_UNBLOCK, &mask, NULL) != 0){
                const char *errormessage = "sigprocmask unblocking error\n";
                write(STDERR_FILENO, errormessage, strlen(errormessage));
                return;
            }
		    execvp(toks[0], (char* const*)toks);
            // If this code is being run, it means that execvp was not successfull
            char errormessage[256];
		    snprintf(errormessage, sizeof(errormessage),"ERROR: cannot run %s\n", toks[0]);
		    ssize_t error = write(STDERR_FILENO, errormessage, strlen(errormessage));
		    exit(1);
        }else{
            // Parent will add it to the number of jobs and then see if it needs to wait to finish
	        numJobs++;
	        totalJobs++;
	        jobs[numJobs - 1].num = numJobs;
	        jobs[numJobs - 1].pNum = totalJobs;
	        jobs[numJobs - 1].pid = newProcess;
	        strncpy(jobs[numJobs - 1].command, toks[0], sizeof(jobs[numJobs - 1].command) - 1);
	        jobs[numJobs - 1].command[sizeof(jobs[numJobs - 1].command) - 1] = '\0';
	        jobs[numJobs - 1].status = running;

            if(sigprocmask(SIG_UNBLOCK, &mask, NULL) != 0){
                const char *errormessage = "sigprocmask unblocking error\n";
                write(STDERR_FILENO, errormessage, strlen(errormessage));
                return;
            }
            char runningmessage[256];
            snprintf(runningmessage, sizeof(runningmessage),"[%d] (%d)  running  %s\n", jobs[numJobs - 1].pNum, jobs[numJobs - 1].pid, jobs[numJobs - 1].command);
	        ssize_t error = write(STDOUT_FILENO, runningmessage, strlen(runningmessage));
        }
    }
	    


}

void sigchld_handler(int sig){
    int previousErrno = errno;
	pid_t pid;
	int status;

	// Take case of all of the signals that changed state
	while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED | WCONTINUED)) > 0) {
		// Find the job that changed state
        job j;
        for(int i = 0; i < numJobs; i++){
		j = jobs[i];
			if(jobs[i].pid == pid){
				if (WIFEXITED(status)){
					// Exited normally
					j.status = finished;
					char numString[32];
                    intToString(j.pNum, numString, sizeof(numString));
                    char pidString[32];
                    intToString(j.pid, pidString, sizeof(pidString));

					write(STDOUT_FILENO, "[", 1);
                    write(STDOUT_FILENO, numString, strlen(numString));
                    write(STDOUT_FILENO, "] (", 3);
                    write(STDOUT_FILENO, pidString, strlen(pidString));
                    write(STDOUT_FILENO, ")  ", 3);
                    write(STDOUT_FILENO, status_names[j.status], strlen(status_names[j.status]));
                    write(STDOUT_FILENO, "  ", 2);
                    write(STDOUT_FILENO, j.command, strlen(j.command));
                    write(STDOUT_FILENO, "\n", 1);
                    for(int k = i + 1; k < numJobs; ++k){
                        jobs[k - 1] = jobs[k];
                    }
                    --numJobs;
				}else if(WIFSIGNALED(status)){
				    // Child terminated with signal, check if core dumped
				    if(WCOREDUMP(status)){
					    j.status = killedDumped;
					    char numString[32];
                        intToString(j.pNum, numString, sizeof(numString));
                        char pidString[32];
                        intToString(j.pid, pidString, sizeof(pidString));

					    write(STDOUT_FILENO, "[", 1);
                        write(STDOUT_FILENO, numString, strlen(numString));
                        write(STDOUT_FILENO, "] (", 3);
                        write(STDOUT_FILENO, pidString, strlen(pidString));
                        write(STDOUT_FILENO, ")  ", 3);
                        write(STDOUT_FILENO, status_names[j.status], strlen(status_names[j.status]));
                        write(STDOUT_FILENO, "  ", 2);
                        write(STDOUT_FILENO, j.command, strlen(j.command));
                        write(STDOUT_FILENO, "\n", 1); 
				    }else{
					    j.status = killed;
                        char numString[32];
                        intToString(j.pNum, numString, sizeof(numString));
                        char pidString[32];
                        intToString(j.pid, pidString, sizeof(pidString));

					    write(STDOUT_FILENO, "[", 1);
                        write(STDOUT_FILENO, numString, strlen(numString));
                        write(STDOUT_FILENO, "] (", 3);
                        write(STDOUT_FILENO, pidString, strlen(pidString));
                        write(STDOUT_FILENO, ")  ", 3);
                        write(STDOUT_FILENO, status_names[j.status], strlen(status_names[j.status]));
                        write(STDOUT_FILENO, "  ", 2);
                        write(STDOUT_FILENO, j.command, strlen(j.command));
                        write(STDOUT_FILENO, "\n", 1);
				    }
                    for(int k = i + 1; k < numJobs; ++k){
                        jobs[k - 1] = jobs[k];
                    }
                    --numJobs;   
			    }else if(WIFSTOPPED(status)) {
                    // Process has been suspended.
                    jobs[i].status = suspended;
                    j.status = suspended;
                    char numString[32];
                    intToString(j.pNum, numString, sizeof(numString));
                    char pidString[32];
                    intToString(j.pid, pidString, sizeof(pidString));

					write(STDOUT_FILENO, "[", 1);
                    write(STDOUT_FILENO, numString, strlen(numString));
                    write(STDOUT_FILENO, "] (", 3);
                    write(STDOUT_FILENO, pidString, strlen(pidString));
                    write(STDOUT_FILENO, ")  ", 3);
                    write(STDOUT_FILENO, status_names[j.status], strlen(status_names[j.status]));
                    write(STDOUT_FILENO, "  ", 2);
                    write(STDOUT_FILENO, j.command, strlen(j.command));
                    write(STDOUT_FILENO, "\n", 1);

                    if (tcsetpgrp(STDIN_FILENO, getpgrp()) == -1) {
                        const char *errormessage = "Foreground job processing error\n";
                        write(STDERR_FILENO, errormessage, strlen(errormessage));
                        return;
                    }

                    break;
                } else if (WIFCONTINUED(status)) {
                    // Process has been resumed.
                    jobs[i].status = running;
                    j.status = running;
                    char numString[32];
                    intToString(j.pNum, numString, sizeof(numString));
                    char pidString[32];
                    intToString(j.pid, pidString, sizeof(pidString));

					write(STDOUT_FILENO, "[", 1);
                    write(STDOUT_FILENO, numString, strlen(numString));
                    write(STDOUT_FILENO, "] (", 3);
                    write(STDOUT_FILENO, pidString, strlen(pidString));
                    write(STDOUT_FILENO, ")  continued  ", 15);
                    write(STDOUT_FILENO, j.command, strlen(j.command));
                    write(STDOUT_FILENO, "\n", 1);
                    break;
                }  	

                break;

			}
		}
	}
    errno = previousErrno;
}

void parse_and_eval(char *s) {
    assert(s);
    const char *toks[MAXLINE+1];
    
    while (*s != '\0') {
        bool end = false;
        bool bg = false;
        int t = 0;

        while (*s != '\0' && !end) {
            while (*s == '\n' || *s == '\t' || *s == ' ') ++s;
            if (*s != ';' && *s != '&' && *s != '\0') toks[t++] = s;
            while (strchr("&;\n\t ", *s) == NULL) ++s;
            switch (*s) {
            case '&':
                bg = true;
                end = true;
                break;
            case ';':
                end = true;
                break;
            }
            if (*s) *s++ = '\0';
        }
        toks[t] = NULL;
        eval(toks, bg);
    }
}

void prompt() {
    const char *prompt = "crash> ";
    ssize_t nbytes = write(STDOUT_FILENO, prompt, strlen(prompt));
}

int repl() {
    char *buf = NULL;
    size_t len = 0;
    while (prompt(), getline(&buf, &len, stdin) != -1) {
        parse_and_eval(buf);
    }

    if (buf != NULL) free(buf);
    if (ferror(stdin)) {
        perror("ERROR");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {

    // Ignore signals that would suspend the shell.
    signal(SIGTSTP, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);

    if (setpgid(0, 0) < 0) {
        perror("setpgid for shell failed");
        exit(1);
    }

    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        perror("sigaction");
        exit(1);
    }

    return repl();
}
