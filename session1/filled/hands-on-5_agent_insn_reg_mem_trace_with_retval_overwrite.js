// ハンズオン2と共通
const main_module = Process.mainModule;
const bin_base = main_module.base;
const bin_end = bin_base.add(main_module.size);
send('[Load] Binary base: ' + bin_base);


/* localtime関数のフック：ハンズオン1と共通 */
send('[+] Hooking localtime');
const libc = Process.getModuleByName('libc.so.6');
const ptr_localtime = libc.getExportByName('localtime');

Interceptor.attach(ptr_localtime, {
    onEnter: localtime_enter,
    onLeave: localtime_leave
   }
);

/* exit関数のフック：ハンズオン1と共通 */
send('[+] Hooking exit');
const ptr_exit = libc.getExportByName('exit');

Interceptor.attach(ptr_exit, {
    onEnter: exit_enter
});

function localtime_enter(args) {
    // ハンズオン1と共通
    const time_ptr = args[0];
    const timestamp = time_ptr.readU64();

    send(`[API] localtime`);
    send(`    time_t: ${timestamp} (${new Date(Number(timestamp) * 1000).toUTCString()})`);
}

function localtime_leave(retval) {
    // ハンズオン2と共通
    if (retval.isNull()) {
        send('    Returned NULL');
        return;
    }

    const tm_ptr = retval;
    const tm_sec   = tm_ptr.readS32();
    const tm_min   = tm_ptr.add(4).readS32();
    const tm_hour  = tm_ptr.add(8).readS32();
    const tm_mday  = tm_ptr.add(12).readS32();
    const tm_mon   = tm_ptr.add(16).readS32();
    const tm_year  = tm_ptr.add(20).readS32();
    const tm_wday  = tm_ptr.add(24).readS32();
    const tm_yday  = tm_ptr.add(28).readS32();
    const tm_isdst = tm_ptr.add(32).readS32();

    send(`    struct tm: ${tm_year + 1900}-${tm_mon + 1}-${tm_mday} ${tm_hour}:${tm_min}:${tm_sec}`);
    send(`        wday=${tm_wday}, yday=${tm_yday}, isdst=${tm_isdst}`);

    Stalker.follow(this.threadId, {
        transform: trace_insn
    });

    // 書き換えるためのtm構造体を偽造
    const fake_tm = {
        tm_sec: 37,
        tm_min: 13,
        tm_hour: 3,
        tm_mday: 6,
        tm_mon: 2,
        tm_year: 2026 - 1900,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0
    };

    // 返り値を書き換え
    overwrite_retval(retval, fake_tm);
}

function overwrite_retval(retval, fake_tm) {
    // localtime関数の返り値を書き換える関数
    if (retval.isNull()) {
        console.log('    localtime returned NULL');
        return;
    }

    // tm構造体を読み出した時と同様に、4バイト/32ビットずつ書き込み
    const tm_ptr = retval;
    tm_ptr.add(0).writeS32(fake_tm.tm_sec);
    tm_ptr.add(4).writeS32(fake_tm.tm_min);
    tm_ptr.add(8).writeS32(fake_tm.tm_hour);
    tm_ptr.add(12).writeS32(fake_tm.tm_mday);
    tm_ptr.add(16).writeS32(fake_tm.tm_mon);
    tm_ptr.add(20).writeS32(fake_tm.tm_year);
    tm_ptr.add(24).writeS32(fake_tm.tm_wday);
    tm_ptr.add(28).writeS32(fake_tm.tm_yday);
    tm_ptr.add(32).writeS32(fake_tm.tm_isdst);

    console.log('    [*] Returned struct tm has been overwritten with fake time.');
}

function exit_enter(args) {
    // ハンズオン1と共通
    const exit_status = args[0];

    send(`[API] exit`);
    send(`    status: ${exit_status}`);

    Thread.sleep(.1);
}

/* 命令の追跡のための関数群 */
function trace_insn(insn_iter) {
    // ハンズオン3と共通
    let insn;

    while ((insn = insn_iter.next()) !== null) {
        if (bin_base <= insn.address && insn.address <= bin_end) {
            insn_iter.putCallout(log_insn_before);
        }

        insn_iter.keep();

        if (bin_base <= insn.address && insn.address <= bin_end) {
            insn_iter.putCallout(log_insn_after);
        }
    }
}

function log_insn_before(context) {
    // ハンズオン4と共通
    const insn = Instruction.parse(context.pc);
    send(`[Insn] ${insn.address} (${insn.size}): ${insn.mnemonic} ${insn.opStr}`);

    log_regs(context, insn, 'r');
    log_mems(context, insn, 'r');
}

function log_insn_after(context) {
    // ハンズオン4と共通
    const insn = Instruction.parse(context.pc);
    log_regs(context, insn, 'w');
    log_mems(context, insn, 'w');
}

function get_full_size_reg(reg) {
    // ハンズオン3と共通
    let m = /^(r1[0-5]|r[8-9])(d|w|b)$/.exec(reg);
    if (m) return m[1];

    const map = {
        al: 'rax', ah: 'rax', ax: 'rax', eax: 'rax', rax: 'rax',
        bl: 'rbx', bh: 'rbx', bx: 'rbx', ebx: 'rbx', rbx: 'rbx',
        cl: 'rcx', ch: 'rcx', cx: 'rcx', ecx: 'rcx', rcx: 'rcx',
        dl: 'rdx', dh: 'rdx', dx: 'rdx', edx: 'rdx', rdx: 'rdx',
        sil: 'rsi', si: 'rsi', esi: 'rsi', rsi: 'rsi',
        dil: 'rdi', di: 'rdi', edi: 'rdi', rdi: 'rdi',
        bpl: 'rbp', bp: 'rbp', ebp: 'rbp', rbp: 'rbp',
        spl: 'rsp', sp: 'rsp', esp: 'rsp', rsp: 'rsp',
        eip: 'rip', rip: 'rip',
    };

    return map[reg] ?? reg;
}

function log_regs(context, insn, rw) {
    // ハンズオン3と共通
    let regs;

    if (rw === 'r') {
        regs = insn.regsAccessed.read;
    } else if (rw === 'w') {
        regs = insn.regsAccessed.written;
    }

    if (regs.length > 0) {
        if (rw === 'r')
            send('       Read regs: ');
        else if (rw === 'w')
            send('       Written regs: ');

        for (const reg of regs) {
            const full_size_reg = get_full_size_reg(reg);
            const reg_value = context[full_size_reg]
            send(`           ${reg}: ${reg_value}`);
        }
    }
}

function ptr_mul(addr, scale) {
    // ハンズオン4と共通
    const v1 = BigInt(addr.toString());
    const v2 = BigInt(scale);
    return ptr('0x' + (v1 * v2).toString(16));
}

function calc_addr(op, insn, context) {
    // ハンズオン4と共通
    const base_reg = op.value.base;
    const index_reg = op.value.index;
    const scale = op.value.scale || 1;
    const disp = op.value.disp || 0;

    let addr = ptr(0);

    if (base_reg) {
        if (base_reg === 'rip') {
            addr = insn.address.add(insn.size);
        } else {
            const base = context[get_full_size_reg(base_reg)];
            addr = addr.add(base);
        }
    }

    if (index_reg) {
        const index = context[get_full_size_reg(index_reg)];
        addr = addr.add(ptr_mul(index, scale));
    }

    addr = addr.add(disp);

    return addr;
}

function read_mem_value(addr, size) {
    // ハンズオン4と共通
    switch (size) {
        case 1: return '0x' + addr.readU8().toString(16);
        case 2: return '0x' + addr.readU16().toString(16);
        case 4: return '0x' + addr.readU32().toString(16);
        case 8: return '0x' + addr.readU64().toString(16);
        default: {
            const buf = addr.readByteArray(size);
            return hexdump(buf, { offset: 0, length: size, header: false, ansi: false }).trim();
        }
    }
}

function log_mems(context, insn, rw) {
    // ハンズオン4と共通
    const mems = [];

    for (let index = 0; index < insn.operands.length; index++) {
        const op = insn.operands[index];
        if (op.type === 'mem' && op.access.includes(rw)) mems.push({ index, op });
    }

    if (mems.length > 0) {
        if (rw === 'r')
            send('       Read mems: ');
        else if (rw === 'w')
            send('       Written mems: ');
        for (const mem of mems) {
            const addr = calc_addr(mem.op, insn, context);
            const size = mem.op.size
            const value = read_mem_value(addr, size);
            send(`           op${mem.index + 1}: ${addr} (${size}) ${value}`);
        }
    }
}