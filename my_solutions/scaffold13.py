# This challenge is the exact same as the first challenge, except that it was
# compiled as a static binary. Normally, Angr automatically replaces standard
# library functions with SimProcedures that work much more quickly.
#
# Here are a few SimProcedures Angr has already written for you. They implement
# standard library functions. You will not need all of them:
# angr.SIM_PROCEDURES['libc']['malloc']
# angr.SIM_PROCEDURES['libc']['fopen']
# angr.SIM_PROCEDURES['libc']['fclose']
# angr.SIM_PROCEDURES['libc']['fwrite']
# angr.SIM_PROCEDURES['libc']['getchar']
# angr.SIM_PROCEDURES['libc']['strncmp']
# angr.SIM_PROCEDURES['libc']['strcmp']
# angr.SIM_PROCEDURES['libc']['scanf']
# angr.SIM_PROCEDURES['libc']['printf']
# angr.SIM_PROCEDURES['libc']['puts']
# angr.SIM_PROCEDURES['libc']['exit']
# angr.SIM_PROCEDURES['glibc']['__libc_start_main']
#
# As a reminder, you can hook functions with something similar to:
# project.hook(malloc_address, angr.SIM_PROCEDURES['libc']['malloc']())
#
# There are many more, see:
# https://github.com/angr/angr/tree/master/angr/procedures/libc
#
# Additionally, note that, when the binary is executed, the main function is not
# the first piece of code called. In the _start function, __libc_start_main is 
# called to start your program. The initialization that occurs in this function
# can take a long time with Angr, so you should replace it with a SimProcedure.
# angr.SIM_PROCEDURES['glibc']['__libc_start_main']
# Note 'glibc' instead of 'libc'.

import angr
import sys

def main(argv):
    path_to_binary = argv[1]
    project = angr.Project(path_to_binary)

    initial_state = project.factory.entry_state()

    # TODO ako prva 3 zakomentiram, nece mi nac rjesenje
    project.hook(0x804eeb0, angr.SIM_PROCEDURES['libc']['printf']())
    project.hook(0x804eef0, angr.SIM_PROCEDURES['libc']['scanf']())
    project.hook(0x804f4c0, angr.SIM_PROCEDURES['libc']['puts']())
    project.hook(0x080491f0, angr.SIM_PROCEDURES['glibc']['__libc_start_main']())

    simulation = project.factory.simgr(initial_state)

    # Define a function that checks if you have found the state you are looking
    # for.
    def is_successful(state):
        # Dump whatever has been printed out by the binary so far into a string.
        stdout_output = state.posix.dumps(sys.stdout.fileno())

        # Return whether 'Good Job.' has been printed yet.
        # (!)
        return b'Good Job.' in stdout_output  # :boolean

    # Same as above, but this time check if the state should abort. If you return
    # False, Angr will continue to step the state. In this specific challenge, the
    # only time at which you will know you should abort is when the program prints
    # "Try again."
    def should_abort(state):
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        return b'Try again.' in stdout_output  # :boolean

    # Tell Angr to explore the binary and find any state that is_successful identfies
    # as a successful state by returning True.
    simulation.explore(find=is_successful, avoid=should_abort)

    if simulation.found:
        solution_state = simulation.found[0]
        print(solution_state.posix.dumps(sys.stdin.fileno()))
    else:
        raise Exception('Could not find the solution')


if __name__ == '__main__':
    main(sys.argv)
