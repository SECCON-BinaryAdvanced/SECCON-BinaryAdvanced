import frida
import sys

""" メッセージ処理部分 """
def on_message(message, data):
    # メッセージの型が send の時、送信されてきた内容を標準出力
    if message['type'] == 'send':
        print(f'[JS] {message['payload']}')

""" 解析対象のバイナリの起動部分 """
# 解析対象のバイナリファイル
target_binary = sys.argv[2]

# 解析対象のバイナリを実行してプロセスを起動、プロセスIDを取得（停止状態で起動される）
pid = frida.spawn(target_binary)
# 解析対象プロセスにFridaの解析エンジンをアタッチ
session = frida.attach(pid)

""" 解析用エージェントスクリプトのロード部分 """
# 解析用エージェントスクリプトのJavaScriptファイル
agent_script = sys.argv[1]

# エージェントスクリプトをファイルから読み込み、スクリプトオブジェクトを作成
with open(agent_script, 'r') as f:
    script = session.create_script(f.read())
# エージェントスクリプトからメッセージイベントが送信されたら、on_message関数で処理するよう登録
script.on('message', on_message)
# エージェントスクリプトをFridaの解析エンジンにロード
script.load()

print('[*] Script loaded. Press Ctrl+C to quit.')
# 解析対象プロセスを再開 → 解析が開始される
frida.resume(pid)

""" 終了処理部分 """
# キーボード割り込み (Ctrl+C) を受信したらFridaの解析エンジンをプロセスからデタッチ
try:
    sys.stdin.read()
except KeyboardInterrupt:
    print('[*] Detaching...')
    session.detach()
