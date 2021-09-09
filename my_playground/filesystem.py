import angr
import claripy
import sys


def main(argv):
  path_to_binary = "./program"
  project = angr.Project(path_to_binary)

  start_address = 0x11e9
  initial_state = project.factory.entry_state()

  filename = "datoteka"  # :string
  symbolic_file_size_bytes = 12

  password = claripy.BVS('password', symbolic_file_size_bytes * 8)
  sim_file = angr.SimFile(filename, content=password)
  # sim_file.set_state(initial_state)

  initial_state.fs.insert(filename, sim_file)

  simulation = project.factory.simgr(initial_state)
  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Good Job.' in stdout_output

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Try Again.' in stdout_output

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    # solution = solution_state.se.eval(password,cast_to=bytes).decode('utf-8')
    solution = solution_state.solver.eval(password, cast_to=bytes).decode('utf-8')

    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
