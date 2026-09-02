#include "maelys_git_cli.h"

int main(int argc, char **argv) {
    return maelys_cli_main(&maelys_git_cli_admin_app, argc, argv);
}
