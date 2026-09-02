#include "maelys_git_cli.h"

#include <sys/stat.h>

int main(int argc, char **argv) {
    /* Every file the agent creates (configuration, journal) is private. */
    (void)umask(0077);
    return maelys_cli_main(&maelys_git_cli_agent_app, argc, argv);
}
