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
    // 前半はハンズオン2と共通
    let insn;

    while ((insn = insn_iter.next()) !== null) {
        if (bin_base <= insn.address && insn.address <= bin_end) {
            insn_iter.putCallout(log_insn_before);
        }

        insn_iter.keep();

        /* 命令実行後の処理を新たに追加 */
        if (bin_base <= insn.address && insn.address <= bin_end) {
            // 命令をログ出力するlog_insn_after関数の呼び出し（コールアウト）を追加
            // 本来の命令の実行後にログ出力が挟まる
            insn_iter.putCallout(log_insn_after);
        }
    }
}

function log_insn_before(context) {  // 命令実行時のコンテキスト情報が引数に渡される
    // 前半はハンズオン2と共通
    const insn = Instruction.parse(context.pc);
    send(`[Insn] ${insn.address} (${insn.size}): ${insn.mnemonic} ${insn.opStr}`);

    // 読み出されるレジスタの値を記録
    log_regs(context, insn, 'r');
}

function log_insn_after(context) {  // 命令実行時のコンテキスト情報が引数に渡される
    const insn = Instruction.parse(context.pc);

    // 書き込まれたレジスタの値を記録
    log_regs(context, insn, 'w');
}

function get_full_size_reg(reg) {
    // レジスタ名をフルサイズのレジスタ名に変換するユーティリティ関数
    // 例： eax（32ビット） → rax（64ビット）, bl（8ビット） → rbx（64ビットレジスタ）
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
    let regs;

    // 第3引数 rw に与えられた値によって、アクセスされたレジスタをregs変数に取得
    if (rw === 'r') {
        // rwが'r'の時は読み出されたレジスタを取得
        regs = insn.regsAccessed.read;
    } else if (rw === 'w') {
        // rwが'w'の時は書き込まれたレジスタを取得
        regs = insn.regsAccessed.written;
    }

    // regsが空でなければ、レジスタとその値を記録
    if (regs.length > 0) {
        if (rw === 'r')
            send('       Read regs: ');
        else if (rw === 'w')
            send('       Written regs: ');

        // regsの各レジスタをループで処理
        for (const reg of regs) {
            // レジスタ名をフルサイズのレジスタ名に変換（contextは小さいサイズのレジスタ名を持たないため）
            const full_size_reg = get_full_size_reg(reg);
            // フルサイズのレジスタ名を用いて、contextからレジスタの値を取得
            const reg_value = context[full_size_reg]
            // レジスタとその値をログ出力
            send(`           ${reg}: ${reg_value}`);
        }
    }
}