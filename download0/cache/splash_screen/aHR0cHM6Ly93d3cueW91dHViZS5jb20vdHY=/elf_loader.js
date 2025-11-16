// https://github.com/shahrilnet/remote_lua_loader/blob/main/payloads/elf_loader.lua
// Only expected to load john tornblom's elfldr.elf
// credit to nullptr for porting to lua and specter for the original code

const ELF_SHADOW_MAPPING_ADDR = 0x920100000n;
const ELF_MAPPING_ADDR = 0x926100000n;

async function elf_parse(elf_data) {
    // ELF sizes and offsets
    const SIZE_ELF_HEADER = 0x40n;
    const SIZE_ELF_PROGRAM_HEADER = 0x38n;
    const SIZE_ELF_SECTION_HEADER = 0x40n;
    
    const OFFSET_ELF_HEADER_ENTRY = 0x18n;
    const OFFSET_ELF_HEADER_PHOFF = 0x20n;
    const OFFSET_ELF_HEADER_SHOFF = 0x28n;
    const OFFSET_ELF_HEADER_PHNUM = 0x38n;
    const OFFSET_ELF_HEADER_SHNUM = 0x3cn;
    
    const OFFSET_PROGRAM_HEADER_TYPE = 0x00n;
    const OFFSET_PROGRAM_HEADER_FLAGS = 0x04n;
    const OFFSET_PROGRAM_HEADER_OFFSET = 0x08n;
    const OFFSET_PROGRAM_HEADER_VADDR = 0x10n;
    const OFFSET_PROGRAM_HEADER_FILESZ = 0x20n;
    const OFFSET_PROGRAM_HEADER_MEMSZ = 0x28n;
    
    const OFFSET_SECTION_HEADER_TYPE = 0x4n;
    const OFFSET_SECTION_HEADER_OFFSET = 0x18n;
    const OFFSET_SECTION_HEADER_SIZE = 0x20n;
    
    const OFFSET_RELA_OFFSET = 0x00n;
    const OFFSET_RELA_INFO = 0x08n;
    const OFFSET_RELA_ADDEND = 0x10n;
    
    const RELA_ENTSIZE = 0x18n;
    
    // Allocate memory for ELF data and copy it
    const elf_store = malloc(elf_data.length);
    write_buffer(elf_store, elf_data);
    
    const elf_entry = read64(elf_store + OFFSET_ELF_HEADER_ENTRY);
    const elf_entry_point = ELF_MAPPING_ADDR + elf_entry;
    
    const elf_program_headers_offset = read64(elf_store + OFFSET_ELF_HEADER_PHOFF);
    const elf_program_headers_num = read16(elf_store + OFFSET_ELF_HEADER_PHNUM);
    
    const elf_section_headers_offset = read64(elf_store + OFFSET_ELF_HEADER_SHOFF);
    const elf_section_headers_num = read16(elf_store + OFFSET_ELF_HEADER_SHNUM);
    
    let executable_start = 0n;
    let executable_end = 0n;
    
    // Parse program headers
    for (let i = 0n; i < elf_program_headers_num; i++) {
        const phdr_offset = elf_program_headers_offset + (i * SIZE_ELF_PROGRAM_HEADER);
        const p_type = read32(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_TYPE);
        const p_flags = read32(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_FLAGS);
        const p_offset = read64(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_OFFSET);
        const p_vaddr = read64(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_VADDR);
        const p_filesz = read64(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_FILESZ);
        const p_memsz = read64(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_MEMSZ);
        const aligned_memsz = (p_memsz + 0x3FFFn) & 0xFFFFC000n;
        
        if (p_type === 0x01n) {
            const PROT_RW = PROT_READ | PROT_WRITE;
            const PROT_RWX = PROT_READ | PROT_WRITE | PROT_EXECUTE;
            
            if ((p_flags & 0x1n) === 0x1n) {
                executable_start = p_vaddr;
                executable_end = p_vaddr + p_memsz;
                
                // Create shm with exec permission
                const exec_handle = syscall(SYSCALL.jitshm_create, 0n, aligned_memsz, 0x7n);
                
                // Create shm alias with write permission
                const write_handle = syscall(SYSCALL.jitshm_alias, exec_handle, 0x3n);
                
                // Map shadow mapping and write into it
                syscall(SYSCALL.mmap, ELF_SHADOW_MAPPING_ADDR, aligned_memsz, 
                        PROT_RW, 0x11n, write_handle, 0n);
                
                // Copy data to shadow mapping
                for (let j = 0n; j < p_memsz; j++) {
                    const byte = read8(elf_store + p_offset + j);
                    write8(ELF_SHADOW_MAPPING_ADDR + j, byte);
                }
                
                // Map executable segment
                syscall(SYSCALL.mmap, ELF_MAPPING_ADDR + p_vaddr, aligned_memsz, 
                        PROT_RWX, 0x11n, exec_handle, 0n);
            } else {
                // Copy regular data segment
                syscall(SYSCALL.mmap, ELF_MAPPING_ADDR + p_vaddr, aligned_memsz, 
                        PROT_RW, 0x1012n, 0xFFFFFFFFn, 0n);
                
                // Copy data
                for (let j = 0n; j < p_memsz; j++) {
                    const byte = read8(elf_store + p_offset + j);
                    write8(ELF_MAPPING_ADDR + p_vaddr + j, byte);
                }
            }
        }
    }
    
    // Apply relocations
    for (let i = 0n; i < elf_section_headers_num; i++) {
        const shdr_offset = elf_section_headers_offset + (i * SIZE_ELF_SECTION_HEADER);
        
        const sh_type = read32(elf_store + shdr_offset + OFFSET_SECTION_HEADER_TYPE);
        const sh_offset = read64(elf_store + shdr_offset + OFFSET_SECTION_HEADER_OFFSET);
        const sh_size = read64(elf_store + shdr_offset + OFFSET_SECTION_HEADER_SIZE);
        
        if (sh_type === 0x4n) {
            const rela_table_count = sh_size / RELA_ENTSIZE;
            
            // Parse relocs and apply them
            for (let j = 0n; j < rela_table_count; j++) {
                const rela_entry_offset = sh_offset + j * RELA_ENTSIZE;
                const r_offset = read64(elf_store + rela_entry_offset + OFFSET_RELA_OFFSET);
                const r_info = read64(elf_store + rela_entry_offset + OFFSET_RELA_INFO);
                const r_addend = read64(elf_store + rela_entry_offset + OFFSET_RELA_ADDEND);
                
                if ((r_info & 0xFFn) === 0x08n) {
                    let reloc_addr = ELF_MAPPING_ADDR + r_offset;
                    const reloc_value = ELF_MAPPING_ADDR + r_addend;
                    
                    // If the relocation falls in the executable section, we need to redirect the write to the
                    // writable shadow mapping or we'll crash
                    if (r_offset >= executable_start && r_offset < executable_end) {
                        reloc_addr = ELF_SHADOW_MAPPING_ADDR + r_offset;
                    }
                    
                    write64(reloc_addr, reloc_value);
                }
            }
        }
    }
    
    return elf_entry_point;
}

async function elf_run(elf_entry_point, filepath) {
    const rwpipe = malloc(8);
    const rwpair = malloc(8);
    const args = malloc(0x30);
    const thr_handle_addr = malloc(8);
    
    write32(rwpipe, ipv6_kernel_rw.data.pipe_read_fd);
    write32(rwpipe + 0x4n, ipv6_kernel_rw.data.pipe_write_fd);
    
    write32(rwpair, ipv6_kernel_rw.data.master_sock);
    write32(rwpair + 0x4n, ipv6_kernel_rw.data.victim_sock);
    
    const payloadout = malloc(4);
    
    // We are reusing syscall_wrapper from gettimeofdayAddr
    write64(args + 0x00n, syscall_wrapper - 0x7n);                  // arg1 = syscall wrapper
    write64(args + 0x08n, rwpipe);                                  // arg2 = int *rwpipe[2]
    write64(args + 0x10n, rwpair);                                  // arg3 = int *rwpair[2]
    write64(args + 0x18n, ipv6_kernel_rw.data.pipe_addr);          // arg4 = uint64_t kpipe_addr
    write64(args + 0x20n, kernel.addr.data_base);                   // arg5 = uint64_t kdata_base_addr
    write64(args + 0x28n, payloadout);                              // arg6 = int *payloadout
    
    await log("spawning " + filepath);
    
    // Spawn elf in new thread
    const ret = call(Thrd_create, thr_handle_addr, elf_entry_point, args);
    if (ret !== 0n) {
        throw new Error("Thrd_create() error: " + toHex(ret));
    }
    
    const thr_handle = read64(thr_handle_addr);
    
    return { thr_handle, payloadout };
}

async function elf_wait_for_exit(thr_handle, payloadout) {
    // Will block until elf terminates
    const ret = call(Thrd_join, thr_handle, 0n);
    if (ret !== 0n) {
        throw new Error("Thrd_join() error: " + toHex(ret));
    }
    
    const out = read32(payloadout);
    await log("out = " + toHex(out));
}

async function elf_loader() {
    try {
        check_jailbroken();
        
        const elfldr_data_path = "/data/elfldr.elf";
        const elfldr_download0_path = "/mnt/sandbox/" + get_title_id() + "_000/download0/cache/splash_screen/aHR0cHM6Ly93d3cueW91dHViZS5jb20vdHY=/elfldr.elf";
        
        let existing_path = "";
        if (file_exists(elfldr_data_path)) {
            existing_path = elfldr_data_path;
        } else if (file_exists(elfldr_download0_path)) {
            existing_path = elfldr_download0_path;
        } else {
            throw new Error("file not exist: elfldr.elf not found");
        }
        
        await log("loading elfldr from: " + existing_path);
        
        const elf_data = read_file(existing_path);
        const elf_entry_point = await elf_parse(elf_data);
        const { thr_handle, payloadout } = await elf_run(elf_entry_point, existing_path);
        await elf_wait_for_exit(thr_handle, payloadout);
        
        await log("done");
    } catch (e) {
        await log("Error: " + e.message);
        throw e;
    }
}

async function bin_sender(path) {           
    const TARGET_PORT = 9021;
    const TARGET_IP   = 0x0100007Fn;
    const PAYLOAD_MAX = 5 * 1024 * 1024; //5 MB

    // resolve ip
    let target_ip = 0x0100007Fn; 
    let ip_str = "127.0.0.1";
    const lan_ip = get_current_ip();
    if (lan_ip && lan_ip !== "0.0.0.0" && lan_ip !== "127.0.0.1") {
        // target_ip = ip_to_uint32(lan_ip);
        ip_str = lan_ip;
    }

    await log("[+] Sending to " + ip_str + ":" + TARGET_PORT);

    // ---- open file ------------------------------------------------
    const src_addr = alloc_string(path);
    const src_fd = syscall(SYSCALL.open, src_addr, O_RDONLY);
    if (src_fd === 0xffffffffffffffffn) {
        await log("[-] Cannot open source: " + path);
        return false;
    }
    const stat = malloc(0x100);
    syscall(SYSCALL.fstat, src_fd, stat);
    const file_size = read64(stat + 0x48n);
    if (file_size === 0n || file_size > BigInt(PAYLOAD_MAX)) {
        syscall(SYSCALL.close, src_fd);
        await log("[-] Invalid file size");
        return false;
    }

    // ---- socket ------------------------------------------------
    const sock = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);
    if (sock === 0xffffffffffffffffn) {
        await log("[-] socket() failed");
        return false;
    }

    // ---- sockaddr_in -------------------------------------------
    const addr = malloc(16);
    for (let i = 0; i < 16; i++) write8(addr + BigInt(i), 0n);
    write8 (addr + 1n, AF_INET);
    write16(addr + 2n, htons(BigInt(TARGET_PORT)));
    write32(addr + 4n, TARGET_IP);

    // ---- connect -----------------------------------------------
    const c = syscall(SYSCALL.connect, sock, addr, 16n);                                      
    if (c === 0xffffffffffffffffn) {
        syscall(SYSCALL.close, sock);
        await log("[-] connect() failed");
        return false;
    }
    await log("[+] Connected to target!");

    // ---- read & send -----------------------------------------------
    const buf = malloc(256 * 1024); //256 KB
    let total = 0n;
    let offset = 0n;

    while (offset < file_size) {
        const to_read = file_size - offset > 256n * 1024n ? 256n * 1024n : file_size - offset;
        const read = syscall(SYSCALL.read, src_fd, buf, to_read);
        if (read <= 0n) break;

        let written = 0n;
        while (written < read) {
            const w = syscall(SYSCALL.write, sock, buf + written, read - written);
            if (w <= 0n) {
                syscall(SYSCALL.close, sock);
                syscall(SYSCALL.close, src_fd);
                await log("[-] write failed");
                return false;
            }
            written += w;
        }
        offset += read;
        total += read;

        const pct = Math.floor(Number(total * 100n / file_size));
        if (pct > 0 && pct % 25 === 0) await log("Progress: " + pct + "%");
    }

    syscall(SYSCALL.close, sock);
    syscall(SYSCALL.close, src_fd);

    if (total !== file_size) {
        await log("[-] incomplete send: " + total + "/" + file_size);
        return false;
    }
    await log("[+] Sent " + payload_len + " bytes successfully");

    return true;
}

async function autoload() {
    const INTERNAL          = "/data/payload.bin";
    const PAYLOAD_NAME      = "payload.bin";
    const payload_download0_path = "/mnt/sandbox/" + get_title_id() +
                                   "_000/download0/cache/splash_screen/" +
                                   "aHR0cHM6Ly93d3cueW91dHViZS5jb20vdHY=/payload.bin";

    // usb check                            
    let usb_path = null;
    for (let i = 0; i <= 7; i++) {
        const p = `/mnt/usb${i}/${PAYLOAD_NAME}`;
        if (file_exists(p)) { usb_path = p; break; }
    }
    // either usb and internal not exist
    if (!usb_path && !file_exists(INTERNAL)) {
        await log("[-] No payload in USB or internal");
        send_notification("Using fallback payload");

        if (!file_exists(payload_download0_path)) {
            await log("[-] Fallback missing!");
            send_notification("Fallback payload missing!");
            return;
        }
        // copy from download0 to internal
        if (!(await copy_binary_file(payload_download0_path, INTERNAL))) return;
        send_notification("Payload copied from download0!");
    }
    else if (usb_path) {
        // copy new payload from usb
        if (!(await copy_binary_file(usb_path, INTERNAL))) return;
        send_notification("Payload copied from USB!");
    } else {
        await log("[=] using internal payload: " + INTERNAL);
    }
    // sent payload
    sleep(500);
    try {
        const ok = await bin_sender(INTERNAL);
        if (ok) {
            send_notification("Payload loaded!\nClosing Y2JB...");
            await log("Payload loaded!\nClosing Y2JB...");
        }
    } catch (e) {
        await log("ERROR: " + e.message);
    }
}