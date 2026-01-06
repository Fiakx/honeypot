#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#define PORT 2323
#define LOG_FILE "honeypot.log"

// types de fichiers
typedef enum { TYPE_DIR, TYPE_FILE } NodeType;

// struc du systeme de fichiers (arbre)
typedef struct Node {
    char name[64];
    NodeType type;
    char content[1024]; 
    struct Node *parent;
    struct Node *child;  
    struct Node *next;   
} Node;

typedef struct {
    Node *current_node;
    char ip[INET_ADDRSTRLEN];
} Session;

// gestion

Node* create_node(const char *name, NodeType type, Node *parent) {
    Node *n = malloc(sizeof(Node));
    if (!n) return NULL;
    strncpy(n->name, name, 63);
    n->type = type;
    memset(n->content, 0, 1024);
    n->parent = parent;
    n->child = NULL;
    n->next = NULL;
    return n;
}

void add_child(Node *parent, Node *new_child) {
    if (!parent->child) {
        parent->child = new_child;
    } else {
        Node *tmp = parent->child;
        while (tmp->next) tmp = tmp->next;
        tmp->next = new_child;
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

// init avec l'arborescence standard
Node* init_filesystem() {
    Node *root = create_node("/", TYPE_DIR, NULL);
    root->parent = root; 

    add_child(root, create_node("bin", TYPE_DIR, root));
    add_child(root, create_node("home", TYPE_DIR, root));
    Node *etc = create_node("etc", TYPE_DIR, root);
    add_child(root, etc);
    
    Node *passwd = create_node("passwd", TYPE_FILE, etc);
    strcpy(passwd->content, "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash");
    add_child(etc, passwd);

    return root;
}

//logs améliorées

void log_event(const char *ip, const char *command) {
    FILE *f = fopen(LOG_FILE, "a");
    if (!f) return;
    
    time_t now = time(NULL);
    char *ts = ctime(&now);
    ts[strlen(ts) - 1] = '\0';
    
    fprintf(f, "[%s] [IP:%s] %s\n", ts, ip, command);
    fflush(f); // force l'écriture disque
    fclose(f);
}

// j'ai essayé de faire un moteur de commande réaliste (projet encore en cours de dev)

void handle_command(int sock, char *input, Session *s) {
    char buffer[2048] = {0};
    input[strcspn(input, "\r\n")] = 0; // on nettoie tout
    if (strlen(input) == 0) return;

    log_event(s->ip, input); // ça enregisstre la commande exact

    char input_copy[1024];
    strcpy(input_copy, input);
    char *cmd = strtok(input_copy, " ");
    char *arg = strtok(NULL, " ");

    // c'est là que les commandes sont simulées (il en manque plein pour un bon réalisme
    if (strcmp(cmd, "ls") == 0) {
        Node *tmp = s->current_node->child;
        while (tmp) {
            strcat(buffer, tmp->name);
            strcat(buffer, (tmp->type == TYPE_DIR) ? "/  " : "  ");
            tmp = tmp->next;
        }
        strcat(buffer, "\r\n");
    } 
    else if (strcmp(cmd, "cd") == 0) {
        if (!arg || strcmp(arg, "/") == 0) {
            while (s->current_node->parent != s->current_node) s->current_node = s->current_node->parent;
        } else if (strcmp(arg, "..") == 0) {
            s->current_node = s->current_node->parent;
        } else {
            Node *target = find_child(s->current_node, arg);
            if (target && target->type == TYPE_DIR) s->current_node = target;
            else sprintf(buffer, "-bash: cd: %s: No such directory\r\n", arg);
        }
    }
    else if (strcmp(cmd, "mkdir") == 0 && arg) {
        add_child(s->current_node, create_node(arg, TYPE_DIR, s->current_node));
    }
    else if (strcmp(cmd, "touch") == 0 && arg) {
        add_child(s->current_node, create_node(arg, TYPE_FILE, s->current_node));
    }
    else if (strcmp(cmd, "cat") == 0 && arg) {
        Node *target = find_child(s->current_node, arg);
        if (target && target->type == TYPE_FILE) sprintf(buffer, "%s\r\n", target->content);
        else sprintf(buffer, "cat: %s: No such file\r\n", arg);
    }
    else if (strcmp(cmd, "pwd") == 0) {
        sprintf(buffer, "%s\r\n", s->current_node->name);
    }
    else if (strcmp(cmd, "whoami") == 0) {
        strcpy(buffer, "root\r\n");
    }
    else if (strcmp(cmd, "exit") == 0) {
        close(sock);
        exit(0);
    }
    else {
        sprintf(buffer, "-bash: %s: command not found\r\n", cmd);
    }

    send(sock, buffer, strlen(buffer), 0);
}

// gestion des co

void run_honeypot(int client_sock, struct sockaddr_in addr, Node *fs_root) {
    Session s;
    s.current_node = fs_root;
    strcpy(s.ip, inet_ntoa(addr.sin_addr));

    log_event(s.ip, "ALERTE: NOUVELLE CONNEXION");

    char *banner = "Debian GNU/Linux 11\r\nlogin: ";
    send(client_sock, banner, strlen(banner), 0);
    
    char junk[1024];
    recv(client_sock, junk, 1024, 0);
    send(client_sock, "Password: ", 10, 0);
    recv(client_sock, junk, 1024, 0);

    while (1) {
        char prompt[256];
        sprintf(prompt, "root@debian:%s# ", s.current_node->name);
        send(client_sock, prompt, strlen(prompt), 0);

        char input[1024] = {0};
        int bytes = recv(client_sock, input, 1024, 0);
        if (bytes <= 0) break;

        handle_command(client_sock, input, &s);
    }
    close(client_sock);
}

int main() {
    Node *fs_root = init_filesystem();
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in address = { .sin_family = AF_INET, .sin_addr.s_addr = INADDR_ANY, .sin_port = htons(PORT) };
    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 10);

    printf("[+] Honeypot High-Interaction actif sur le port %d\n", PORT);

    while (1) {
        struct sockaddr_in c_addr;
        socklen_t len = sizeof(c_addr);
        int client_sock = accept(server_fd, (struct sockaddr *)&c_addr, &len);
        
        if (fork() == 0) {
            run_honeypot(client_sock, c_addr, fs_root);
            exit(0);
        }
        close(client_sock);
    }
    return 0;
}

// si vous avez ddes questions n'hésitez pas @fiakx sur discord
