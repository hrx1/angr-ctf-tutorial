import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = 0x8048601
  initial_state = project.factory.blank_state(addr=start_address)

  initial_state.regs.ebp = initial_state.regs.esp

  padding_length_in_bytes = 13 * 4  # :integer
  initial_state.regs.esp -= padding_length_in_bytes

  # The binary is calling scanf("%8s %8s %8s %8s").
  # (!)
  password0 = claripy.BVS('password0', 8*8) # 8 znakova, svaki je 1B
  password1 = claripy.BVS('password1', 8*8) # 8 znakova, svaki je 1B
  password2 = claripy.BVS('password2', 8*8) # 8 znakova, svaki je 1B
  password3 = claripy.BVS('password3', 8*8) # 8 znakova, svaki je 1B

  # Determine the address of the global variable to which scanf writes the user
  # input. The function 'initial_state.memory.store(address, value)' will write
  # 'value' (a bitvector) to 'address' (a memory location, as an integer.) The
  # 'address' parameter can also be a bitvector (and can be symbolic!).
  # (!)

  password0_address = 0xb1085d8
  initial_state.memory.store(password0_address, password0)

  password1_address = 0xb1085d0
  initial_state.memory.store(password1_address, password1)

  password2_address = 0xb1085c8
  initial_state.memory.store(password2_address, password2)

  password3_address = 0xb1085c0
  initial_state.memory.store(password3_address, password3)

 # NJIHOVO:
  # password0_address = 0xa29faa0
  # initial_state.memory.store(password0_address, password0)
  # password1_address = 0xa29faa8
  # initial_state.memory.store(password1_address, password1)
  # password2_address = 0xa29fab0
  # initial_state.memory.store(password2_address, password2)
  # password3_address = 0xa29fab8
  # initial_state.memory.store(password3_address, password3)


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

    # Solve for the symbolic values. We are trying to solve for a string.
    # Therefore, we will use eval, with named parameter cast_to=str
    # which returns a string instead of an integer.
    # (!)
    passwords = [password0, password1, password2, password3]
    solutions = [solution_state.se.eval(p,cast_to=bytes).decode('utf-8') for p in passwords[::-1]]

    solution = ' '.join(solutions) #Kopirano iz rjesenja. Kako da ja znam da ide razmak izmedju?

    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
