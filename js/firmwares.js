/* =========================================================================
 *  firmwares.js  ―  年代別ファームウェアの定義
 *
 *  各オブジェクトは「ある年代の典型的なブロードバンドルーター」を表す。
 *  flags がセキュリティ上の性質。attacks.js の evaluate(fw) がこの flags を
 *  読んで攻撃の成否を決める。年代・機能を増やしたいときはここに足すだけ。
 *
 *  ※ 製品名・IP・バージョンはすべて架空（教材用）。特定製品の実挙動ではない。
 *  flags の意味:
 *   httpAdmin : 'http' | 'http+https' | 'https'        管理画面の通信
 *   creds     : {user,pass} | 'unique'                 初期ログイン情報（unique=端末固有）
 *   telnet    : 'open' | 'backdoor' | 'off' | 'removed' Telnet/組込みシェル
 *   wps       : 'none' | 'on' | 'locked' | 'off' | 'removed'  Wi-Fi簡単設定(WPS)
 *   diagSanitized : bool   診断ツール(ping等)の入力を無害化しているか
 *   csrfToken     : bool   設定変更にCSRFトークンを要求するか
 *   sameSite      : bool   CookieにSameSite制限があるか
 *   pathTraversal : bool   Webサーバに「../」読み出しの穴があるか
 *   authEnforced  : bool   管理ページが認証を必ず確認するか
 *   sercomm       : bool   TCP/32764 隠しバックドアを持つ系譜か
 *   romPager      : bool   脆弱な組込みHTTPサーバ(RomPager系)を使うか
 *   upnpWan       : bool   UPnPがWAN側から悪用可能か
 *   fwSigned      : bool   ファーム更新イメージに署名検証があるか
 *   autoUpdate    : bool   自動アップデート機能を持つか
 *   wifi          : 'WEP'|'WPA'|'WPA2'|'WPA2/WPA3'|'WPA3'   無線暗号方式
 * ========================================================================= */

const FIRMWARES = [
  {
    id: "fw2004",
    year: 2004,
    version: "FW v1.0",
    codename: "黎明期",
    ip: "192.168.11.1",
    model: "BBRouter LX-100 (模擬)",
    summary: "ブロードバンドが家庭に普及し始めた頃。とにかく『つながること』が最優先で、セキュリティは後回しだった世代。",
    risk: 0.95,
    flags: {
      httpAdmin:"http", creds:{user:"admin",pass:"admin"}, telnet:"open", wps:"none",
      diagSanitized:false, csrfToken:false, sameSite:false, pathTraversal:true,
      authEnforced:false, sercomm:false, romPager:true, upnpWan:true,
      fwSigned:false, autoUpdate:false, wifi:"WEP"
    }
  },
  {
    id: "fw2008",
    year: 2008,
    version: "FW v2.2",
    codename: "WPS登場期",
    ip: "192.168.11.1",
    model: "BBRouter LX-220 (模擬)",
    summary: "無線が当たり前に。ボタン1つで繋がる『かんたん設定(WPS)』が登場した一方、初期パスワードや平文管理はそのまま。",
    risk: 0.85,
    flags: {
      httpAdmin:"http", creds:{user:"admin",pass:"password"}, telnet:"open", wps:"on",
      diagSanitized:false, csrfToken:false, sameSite:false, pathTraversal:true,
      authEnforced:false, sercomm:false, romPager:true, upnpWan:true,
      fwSigned:false, autoUpdate:false, wifi:"WPA"
    }
  },
  {
    id: "fw2012",
    year: 2012,
    version: "FW v3.5",
    codename: "バックドア時代",
    ip: "192.168.11.1",
    model: "BBRouter AC-350 (模擬)",
    summary: "高速化が進む裏で、製造元由来の『隠しバックドア』や組込みHTTPサーバの欠陥が次々発覚。WPSの総当たり手法も公開済み。",
    risk: 0.8,
    flags: {
      httpAdmin:"http", creds:{user:"admin",pass:"admin"}, telnet:"backdoor", wps:"on",
      diagSanitized:false, csrfToken:false, sameSite:false, pathTraversal:false,
      authEnforced:true, sercomm:true, romPager:true, upnpWan:true,
      fwSigned:false, autoUpdate:false, wifi:"WPA2"
    }
  },
  {
    id: "fw2016",
    year: 2016,
    version: "FW v4.1",
    codename: "Mirai 襲来",
    ip: "192.168.11.1",
    model: "BBRouter AC-460 (模擬)",
    summary: "IoT機器を初期パスワードのまま乗っ取る大規模ボットネット『Mirai』が猛威。対策が始まりつつも、出荷時設定の甘さが残る過渡期。",
    risk: 0.55,
    flags: {
      httpAdmin:"http+https", creds:{user:"admin",pass:"admin"}, telnet:"open", wps:"locked",
      diagSanitized:true, csrfToken:true, sameSite:false, pathTraversal:false,
      authEnforced:true, sercomm:false, romPager:false, upnpWan:false,
      fwSigned:true, autoUpdate:false, wifi:"WPA2"
    }
  },
  {
    id: "fw2020",
    year: 2020,
    version: "FW v5.3",
    codename: "自動更新時代",
    ip: "192.168.11.1",
    model: "BBRouter AX-530 (模擬)",
    summary: "法規制(初期パスワード禁止など)とWPA3の普及で底上げ。端末ごとに固有パスワード、Telnet廃止、署名付き自動更新が標準に。",
    risk: 0.22,
    flags: {
      httpAdmin:"https", creds:"unique", telnet:"removed", wps:"off",
      diagSanitized:true, csrfToken:true, sameSite:true, pathTraversal:false,
      authEnforced:true, sercomm:false, romPager:false, upnpWan:false,
      fwSigned:true, autoUpdate:true, wifi:"WPA2/WPA3"
    }
  },
  {
    id: "fw2024",
    year: 2024,
    version: "FW v6.0",
    codename: "現代",
    ip: "192.168.11.1",
    model: "BBRouter AX-600 (模擬)",
    summary: "セキュアブート＋署名検証、WPA3、HTTPSのみ、初回起動時に必ずパスワード設定。歴史的手法の大半が成立しなくなった世代。",
    risk: 0.1,
    flags: {
      httpAdmin:"https", creds:"unique", telnet:"removed", wps:"removed",
      diagSanitized:true, csrfToken:true, sameSite:true, pathTraversal:false,
      authEnforced:true, sercomm:false, romPager:false, upnpWan:false,
      fwSigned:true, autoUpdate:true, wifi:"WPA3"
    }
  }
];

/* 管理画面で flags を人間向けに表示するための説明テーブル。
   返り値 level: 'danger'(危険) | 'warn'(注意) | 'secure'(安全) | 'info' */
const FLAG_DESCRIPTORS = [
  { key:"httpAdmin", label:"管理画面", get:v=>({
      http:        {text:"HTTP（平文）",      level:"danger"},
      "http+https":{text:"HTTP/HTTPS 併用",   level:"warn"},
      https:       {text:"HTTPS のみ",        level:"secure"}
    }[v]) },
  { key:"creds", label:"初期パスワード", get:v=> v==="unique"
      ? {text:"端末固有（ラベル記載）", level:"secure"}
      : {text:`${v.user} / ${v.pass}`,  level:"danger"} },
  { key:"telnet", label:"Telnet", get:v=>({
      open:    {text:"開放",                 level:"danger"},
      backdoor:{text:"隠しバックドアあり",    level:"danger"},
      off:     {text:"無効（実装は残る）",    level:"warn"},
      removed: {text:"削除済み",             level:"secure"}
    }[v]) },
  { key:"wifi", label:"無線暗号", get:v=>({
      WEP:        {text:"WEP",         level:"danger"},
      WPA:        {text:"WPA (TKIP)",  level:"warn"},
      WPA2:       {text:"WPA2",        level:"warn"},
      "WPA2/WPA3":{text:"WPA2/WPA3",   level:"secure"},
      WPA3:       {text:"WPA3 (SAE)",  level:"secure"}
    }[v]) },
  { key:"wps", label:"WPS", get:v=>({
      none:   {text:"非搭載",            level:"info"},
      on:     {text:"有効（ロックなし）", level:"danger"},
      locked: {text:"有効（試行制限あり）",level:"warn"},
      off:    {text:"既定で無効",         level:"secure"},
      removed:{text:"廃止",              level:"secure"}
    }[v]) },
  { key:"diagSanitized", label:"診断ツール", get:v=> v
      ? {text:"入力を無害化",          level:"secure"}
      : {text:"入力をそのままシェルへ", level:"danger"} },
  { key:"csrfToken", label:"CSRF対策", get:v=> v
      ? {text:"トークン検証あり", level:"secure"}
      : {text:"トークンなし",     level:"danger"} },
  { key:"authEnforced", label:"認証強制", get:v=> v
      ? {text:"全ページで確認",         level:"secure"}
      : {text:"直アクセスで抜ける箇所", level:"danger"} },
  { key:"upnpWan", label:"UPnP", get:v=> v
      ? {text:"WAN側から悪用可", level:"danger"}
      : {text:"WAN側は遮断",     level:"secure"} },
  { key:"fwSigned", label:"ファーム署名", get:v=> v
      ? {text:"署名検証あり", level:"secure"}
      : {text:"検証なし",     level:"danger"} },
  { key:"autoUpdate", label:"自動更新", get:v=> v
      ? {text:"対応",   level:"secure"}
      : {text:"手動のみ",level:"warn"} }
];
