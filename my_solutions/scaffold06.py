import angr
import claripy
import sys

# QZOVICSN WLFOPPFI

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = 0x8048699
  initial_state = project.factory.blank_state(addr=start_address)

  # The binary is calling scanf("%8s %8s").
  # (!)
  password0 = claripy.BVS('password0', 8 * 8)
  password1 = claripy.BVS('password1', 8 * 8)

  # Instead of telling the binary to write to the address of the memory
  # allocated with malloc, we can simply fake an address to any unused block of
  # memory and overwrite the pointer to the data. This will point the pointer
  # with the address of pointer_to_malloc_memory_address0 to fake_heap_address.
  # Be aware, there is more than one pointer! Analyze the binary to determine
  # global location of each pointer.
  # Note: by default, Angr stores integers in memory with big-endianness. To
  # specify to use the endianness of your architecture, use the parameter
  # endness=project.arch.memory_endness. On x86, this is little-endian.
  # (!)
  fake_heap_address0 = 0x04444444
  pointer_to_malloc_memory_address0 = 0x0a4da758
  # pointer_to_malloc_memory_address0 = 0x58a74d0a
  initial_state.memory.store(pointer_to_malloc_memory_address0, fake_heap_address0, endness=project.arch.memory_endness)

  fake_heap_address1 = 0x04444454
  pointer_to_malloc_memory_address1 = 0x0a4da760
  # pointer_to_malloc_memory_address1 = 0x60a74d0a
  initial_state.memory.store(pointer_to_malloc_memory_address1, fake_heap_address1, endness=project.arch.memory_endness)

  # Store our symbolic values at our fake_heap_address. Look at the binary to
  # determine the offsets from the fake_heap_address where scanf writes.
  # (!)
  initial_state.memory.store(fake_heap_address0, password0)
  initial_state.memory.store(fake_heap_address1, password1)

  # initial_state.regs.edx = pointer_to_malloc_memory_address1
  # initial_state.regs.eax = pointer_to_malloc_memory_address0

  initial_state.regs.ebp = initial_state.regs.esp

  padding_length_in_bytes = 28 * 4  # :integer
  initial_state.regs.esp -= padding_length_in_bytes


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

    passwords = [password0, password1]
    solutions = [solution_state.se.eval(p,cast_to=bytes).decode('utf-8') for p in passwords]

    solution = ' '.join(solutions) #Kopirano iz rjesenja. Kako da ja znam da ide razmak izmedju?

    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
