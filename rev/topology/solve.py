import angr
import claripy
import sys
from pwn import *
import collections

# exported `f` from ghidra
fp_data = b'\x49\x23\x10\x00\x00\x00\x00\x00\x79\x48\x10\x00\x00\x00\x00\x00\x0f\x72\x10\x00\x00\x00\x00\x00\x93\x9b\x10\x00\x00\x00\x00\x00\xf1\xb7\x10\x00\x00\x00\x00\x00\x30\xd2\x10\x00\x00\x00\x00\x00\x1d\xff\x10\x00\x00\x00\x00\x00\x53\x22\x11\x00\x00\x00\x00\x00\x91\x45\x11\x00\x00\x00\x00\x00\x79\x6d\x11\x00\x00\x00\x00\x00\x9d\x94\x11\x00\x00\x00\x00\x00\xde\xb7\x11\x00\x00\x00\x00\x00\x99\xdd\x11\x00\x00\x00\x00\x00\xf2\xfb\x11\x00\x00\x00\x00\x00\xe1\x20\x12\x00\x00\x00\x00\x00\x0b\x3d\x12\x00\x00\x00\x00\x00\x92\x58\x12\x00\x00\x00\x00\x00\x57\x77\x12\x00\x00\x00\x00\x00\x92\xa1\x12\x00\x00\x00\x00\x00\x4f\xcb\x12\x00\x00\x00\x00\x00\x79\xe8\x12\x00\x00\x00\x00\x00\x9c\x16\x13\x00\x00\x00\x00\x00\x9f\x33\x13\x00\x00\x00\x00\x00\x45\x54\x13\x00\x00\x00\x00\x00\xdb\x77\x13\x00\x00\x00\x00\x00\x9a\x9b\x13\x00\x00\x00\x00\x00\xce\xc0\x13\x00\x00\x00\x00\x00\x75\xed\x13\x00\x00\x00\x00\x00\xaa\x20\x14\x00\x00\x00\x00\x00\xbf\x47\x14\x00\x00\x00\x00\x00\x8d\x68\x14\x00\x00\x00\x00\x00\x2d\x8b\x14\x00\x00\x00\x00\x00\x8d\xa9\x14\x00\x00\x00\x00\x00\x83\xc8\x14\x00\x00\x00\x00\x00\x45\xf6\x14\x00\x00\x00\x00\x00\xbc\x1a\x15\x00\x00\x00\x00\x00\x10\x46\x15\x00\x00\x00\x00\x00\xd6\x70\x15\x00\x00\x00\x00\x00\x72\x93\x15\x00\x00\x00\x00\x00\x94\xbd\x15\x00\x00\x00\x00\x00\x71\xe5\x15\x00\x00\x00\x00\x00\xb1\x07\x16\x00\x00\x00\x00\x00\x13\x1c\x16\x00\x00\x00\x00\x00\xc4\x3c\x16\x00\x00\x00\x00\x00\xb4\x66\x16\x00\x00\x00\x00\x00\xee\x8c\x16\x00\x00\x00\x00\x00\x26\xb3\x16\x00\x00\x00\x00\x00\x26\xd5\x16\x00\x00\x00\x00\x00\x3c\xfc\x16\x00\x00\x00\x00\x00\xf9\x21\x17\x00\x00\x00\x00\x00\x7e\x3f\x17\x00\x00\x00\x00\x00\x82\x6b\x17\x00\x00\x00\x00\x00\xa8\x92\x17\x00\x00\x00\x00\x00\xa6\xc1\x17\x00\x00\x00\x00\x00\xe0\xe7\x17\x00\x00\x00\x00\x00\x8d\x05\x18\x00\x00\x00\x00\x00\xe7\x26\x18\x00\x00\x00\x00\x00\x4b\x47\x18\x00\x00\x00\x00\x00\xdb\x72\x18\x00\x00\x00\x00\x00\x6e\xa1\x18\x00\x00\x00\x00\x00\x7f\xc3\x18\x00\x00\x00\x00\x00\xa9\xe5\x18\x00\x00\x00\x00\x00\xc6\x13\x19\x00\x00\x00\x00\x00\x98\x31\x19\x00\x00\x00\x00\x00\x78\x59\x19\x00\x00\x00\x00\x00\x27\x78\x19\x00\x00\x00\x00\x00\xb6\xa2\x19\x00\x00\x00\x00\x00\xb5\xc8\x19\x00\x00\x00\x00\x00\x2d\xef\x19\x00\x00\x00\x00\x00\x8b\x11\x1a\x00\x00\x00\x00\x00\x6b\x36\x1a\x00\x00\x00\x00\x00\x37\x5c\x1a\x00\x00\x00\x00\x00\xbc\x7d\x1a\x00\x00\x00\x00\x00\x52\xa1\x1a\x00\x00\x00\x00\x00\xf9\xc1\x1a\x00\x00\x00\x00\x00\x3d\xe6\x1a\x00\x00\x00\x00\x00\xaf\xfb\x1a\x00\x00\x00\x00\x00\xef\x25\x1b\x00\x00\x00\x00\x00\x41\x47\x1b\x00\x00\x00\x00\x00\x83\x70\x1b\x00\x00\x00\x00\x00\x9c\x8a\x1b\x00\x00\x00\x00\x00\xdc\xb3\x1b\x00\x00\x00\x00\x00\xab\xde\x1b\x00\x00\x00\x00\x00\x5c\x10\x1c\x00\x00\x00\x00\x00\x72\x34\x1c\x00\x00\x00\x00\x00\x3f\x56\x1c\x00\x00\x00\x00\x00\x0b\x7c\x1c\x00\x00\x00\x00\x00\x84\x9d\x1c\x00\x00\x00\x00\x00\x4a\xcd\x1c\x00\x00\x00\x00\x00\x4e\xf0\x1c\x00\x00\x00\x00\x00\x74\x03\x1d\x00\x00\x00\x00\x00\xf4\x22\x1d\x00\x00\x00\x00\x00\xad\x44\x1d\x00\x00\x00\x00\x00\x0d\x70\x1d\x00\x00\x00\x00\x00\x51\xa4\x1d\x00\x00\x00\x00\x00\x0b\xc4\x1d\x00\x00\x00\x00\x00\xe4\xee\x1d\x00\x00\x00\x00\x00\xfa\x13\x1e\x00\x00\x00\x00\x00\xae\x37\x1e\x00\x00\x00\x00\x00'

def run_simulation(func_ptr, flag_part):
  path_to_binary = "./topology" # path of the binary program
  project = angr.Project(path_to_binary, main_opts={'base_addr': 0x00100000})
  solution = claripy.BVS('flag_part', 64) # 64 bit value - ulong

  # start from the specified checking function, and pass current 8-byte block as a ulong*
  initial_state = project.factory.call_state(func_ptr, angr.PointerWrapper(solution, buffer=True))
  # injecting block number to check
  initial_state.regs.rax = flag_part
  simulation = project.factory.simgr(initial_state)
  simulation.run()

  # solve for eax = 0 - generates the 'OK' response
  simulation.deadended[0].solver.add(simulation.deadended[0].regs.eax == 0)

  # get the 8-byte block generating the 0 response
  result = simulation.deadended[0].solver.eval(solution, cast_to=bytes)
  return result

fptrs = []
for i in range(0, len(fp_data), 8):
    fptr = u64(fp_data[i:i+8])
    fptrs.append(fptr)

# print(fptrs)

def get_flag_part(partid):
    results = []
    for x in fptrs:
        # +19 to skip the block counter logic in each function, as we will inject the block number ourselves
        res = run_simulation(x + 19, partid)
        results.append(res)

    counts = collections.Counter(results)
    new_list = sorted(results, key=lambda x: -counts[x])
    print(new_list)
    return new_list[0]

flag_sofar = b'zer0pts{'
for i in range(1, 10):
    flag_sofar += get_flag_part(i)
    print('==================================================')
    print(f'FLAG UPDATE({i}):', flag_sofar)
    print('==================================================')

print('done :)')

# print(run_simulation(0x0010488c, 0))
