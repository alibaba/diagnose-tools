#ifndef DIAG_CONTAINERS_H
#define DIAG_CONTAINERS_H

#include <string>
#include <map>

using namespace std;

enum diag_container_type {
        diag_docker,
        diag_pouch,
};

struct diag_ns {
        std::string ns;
        std::string proc_ns;
        int fd;
};

struct diag_container {
        enum diag_container_type type;
        std::string id;
        int cores;
        unsigned long memory;
        unsigned long pid;
        std::string proc_comm;
        std::string comm;
        std::map<std::string, struct diag_ns> map_ns;

        int load(std::string type, std::string id);
        int enter(void);

        void dump(void);
};

extern map<string, struct diag_container> map_containers;

int refill_map_containers(void);
int open_root_ns_fd(void);
int enter_root_ns(void);

int diag_init_env_path(void);

#endif /* DIAG_CONTAINERS_H */
