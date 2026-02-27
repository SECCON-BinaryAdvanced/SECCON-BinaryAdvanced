// プロセスのメインモジュールを取得してベースアドレスと終端アドレスを取得
const main_module = Process.mainModule;
const bin_base = main_module.base;
const bin_end = bin_base.add(main_module.size);
send('[Load] Binary base: ' + bin_base);


/* localtime関数のフック：ハンズオン1と共通 */
// ただし、下部でlocaltime_leave関数の中身に命令を追跡する処理を追加する
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
    // 前半はハンズオンと共通
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

    /* ここからハンズオン1に追加する部分 */

    // Stalkerモジュール（命令の追跡を可能にするモジュール）を用いて現在のスレッドを追跡
    // 命令の変換時にtrace_insn関数が呼び出されるように登録
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
function trace_insn(insn_iter) {  // 変換されるコードブロック内の命令のイテレータが引数に渡される
    let insn;

    // イテレータの命令をコードブロックの終端（イテレータがnullを返す）まで1つずつ処理
    while ((insn = insn_iter.next()) !== null) {
        // 命令のアドレスが解析対象のバイナリのベースから終端までに含まれているかチェック
        // 解析対象バイナリ以外（たとえばAPI関数など）の命令を無用に追跡しないため
        if (bin_base <= insn.address && insn.address <= bin_end) {
            // 命令をログ出力するlog_insn_before関数の呼び出し（コールアウト）を追加
            // 本来の命令の実行前にログ出力が挟まる
            insn_iter.putCallout(log_insn_before);
        }

        // ここで本来の命令を実行
        insn_iter.keep();
    }
}

function log_insn_before(context) {  // 命令実行時のコンテキスト情報が引数に渡される
    // 現在のプログラムカウンタの命令をパース
    const insn = Instruction.parse(context.pc);
    // 命令のアドレス、サイズ、ニーモニック、命令のテキストを記録
    send(`[Insn] ${insn.address} (${insn.size}): ${insn.mnemonic} ${insn.opStr}`);
}