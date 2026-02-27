/* localtime関数のフック */
send('[+] Hooking localtime');
// libcモジュール (libc.so.6) のベースアドレスの取得
const libc = __
// localtime関数のアドレスの取得
const ptr_localtime = __

// Interceptorモジュールを用いて、localtime関数のアドレスにフックを追加
Interceptor.__(__, {
    // localtime関数の入り口で呼び出されるAPIハンドラの登録（主に引数の記録など用）
    // APIハンドラは本スクリプト下部に実装
    __: __,
    // localtime関数の出口で呼び出されるAPIハンドラの登録（主に返り値の記録など用）
    __: __
});

/* exit関数のフック */
send('[+] Hooking exit');
// exit関数のアドレスの取得
const ptr_exit = __

// Interceptorモジュールを用いて、exit関数のアドレスにフックを追加
Interceptor.__(__, {
    // exit関数の終了時に呼び出されるAPIハンドラの登録（主に返り値の記録など用）
    __: ___ 
});

function localtime_enter(args) {
    /*
        参考：
        $ man 3 localtime
        struct tm *localtime(const time_t *timep);

        $ man 3 time_t
        time_t Used for time in seconds.  According to POSIX, it is an integer type.
    */

    // 第一引数 const time_t *timep をargsから取得
    const time_ptr = __;
    // 取得したポインタの指す先のメモリから64ビット読み出し
    const timestamp = __.__();

    // timestampを整形してログ出力
    send(`[API] localtime`);
    send(`    time_t: ${timestamp} (${new Date(Number(timestamp) * 1000).toUTCString()})`);
}

function localtime_leave(retval) {
    // 返り値がNULLの時はその旨をログ出力してリターン
    if (retval.isNull()) {
        send('    Returned NULL');
        return;
    }

    /*
        参考：
        $ man 3 localtime
        struct tm *localtime(const time_t *timep);

        $ man 3 tm
        struct tm {
           int         tm_sec;    // Seconds          [0, 60]
           int         tm_min;    // Minutes          [0, 59]
           int         tm_hour;   // Hour             [0, 23]
           int         tm_mday;   // Day of the month [1, 31]
           int         tm_mon;    // Month            [0, 11]  (January = 0)
           int         tm_year;   // Year minus 1900
           int         tm_wday;   // Day of the week  [0, 6]   (Sunday = 0)
           int         tm_yday;   // Day of the year  [0, 365] (Jan/01 = 0)
           int         tm_isdst;  // Daylight savings flag

           long        tm_gmtoff; // Seconds East of UTC
           const char *tm_zone;   // Timezone abbreviation
       };
    */

    // 返り値 struct tm * をretvalから取得
    const tm_ptr = __;
    // tm_sec を tm_ptrの指す先のメモリから32ビット読み出し
    const tm_sec   = __.__();
    // 以降、tm構造体の定義に従って4バイト/32ビットずつ読み出し
    const tm_min   = __.__(4).__();
    const tm_hour  = __.__(8).__();
    const tm_mday  = __.__(12).__();
    const tm_mon   = __.__(16).__();
    const tm_year  = __.__(20).__();
    const tm_wday  = __.__(24).__();
    const tm_yday  = __.__(28).__();
    const tm_isdst = __.__(32).__();

    // 読み出した時刻を整形してログ出力
    send(`    struct tm: ${tm_year + 1900}-${tm_mon + 1}-${tm_mday} ${tm_hour}:${tm_min}:${tm_sec}`);
    send(`        wday=${tm_wday}, yday=${tm_yday}, isdst=${tm_isdst}`);
}

function exit_enter(args) {
    /*
        参考：
        $ man 3 exit
        [[noreturn]] void exit(int status);
    */

    // 第一引数 status をargsから取得
    const exit_status = args[0];

    // 終了ステータスを整形して出力
    send(`[API] exit`);
    send(`    status: ${exit_status}`);

    // exit関数でプロセスが終了する前にログ出力を完了できるように少し待機
    Thread.sleep(.1);
}