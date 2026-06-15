/* =========================================================================
 *  app.js  ―  UI構築・シミュレーション実行・マトリクス・解説
 *  依存: firmwares.js (FIRMWARES, FLAG_DESCRIPTORS) / attacks.js (ATTACKS)
 * ========================================================================= */
(function(){
"use strict";

const $  = (s,r=document)=>r.querySelector(s);
const $$ = (s,r=document)=>[...r.querySelectorAll(s)];
const sleep = ms=>new Promise(r=>setTimeout(r,ms));

const state = { eraId: FIRMWARES[0].id, atkId: null };
let runToken = 0;               // 実行中アニメのキャンセル用

const getFw  = id => FIRMWARES.find(f=>f.id===id);
const getAtk = id => ATTACKS.find(a=>a.id===id);

const STATUS = {
  success:{cls:"success", mark:"✕", chip:"成立",   banner:"⚠ 攻撃成立"},
  partial:{cls:"partial", mark:"△", chip:"条件",   banner:"△ 条件つき成立"},
  failed :{cls:"failed",  mark:"✓", chip:"防御",   banner:"🛡 防御された"},
  na     :{cls:"na",      mark:"・",chip:"対象外", banner:"— 対象外（機能なし）"}
};
const LEVEL_WORD = {danger:"危険", warn:"注意", secure:"安全", info:"—"};
const riskColor = r => r>0.66 ? "var(--danger)" : r>0.33 ? "var(--warn)" : "var(--secure)";

/* ============================ タブ ============================ */
function initTabs(){
  $$("#tabs .tab").forEach(btn=>{
    btn.addEventListener("click",()=>{
      $$("#tabs .tab").forEach(b=>b.classList.toggle("active", b===btn));
      const id = btn.dataset.tab;
      $$(".panel-tab").forEach(p=>p.classList.toggle("active", p.id==="tab-"+id));
      window.scrollTo({top:0, behavior:"smooth"});
    });
  });
}
function gotoTab(id){
  $$("#tabs .tab").forEach(b=>b.classList.toggle("active", b.dataset.tab===id));
  $$(".panel-tab").forEach(p=>p.classList.toggle("active", p.id==="tab-"+id));
}

/* ====================== 年代タイムライン ====================== */
function renderEraTimeline(){
  const wrap = $("#era-timeline");
  wrap.innerHTML = "";
  FIRMWARES.forEach(fw=>{
    const el = document.createElement("button");
    el.className = "era" + (fw.id===state.eraId ? " selected":"");
    el.innerHTML =
      `<div class="yr">${fw.year}</div>`+
      `<div class="ver">${fw.version}</div>`+
      `<div class="code">${fw.codename}</div>`+
      `<div class="risk"><i style="width:${Math.round(fw.risk*100)}%;background:${riskColor(fw.risk)}"></i></div>`;
    el.addEventListener("click",()=>selectEra(fw.id));
    wrap.appendChild(el);
  });
}

/* ====================== ファーム仕様表示 ====================== */
function renderSpec(fw){
  $("#spec-version").textContent = fw.version + " / " + fw.year;
  $("#spec-meta").innerHTML =
    `<div><b>${fw.model}</b></div>`+
    `<div>管理IP: <code>${fw.ip}</code></div>`+
    `<div style="margin-top:6px">${fw.summary}</div>`;

  const list = $("#spec-list");
  list.innerHTML = "";
  FLAG_DESCRIPTORS.forEach(d=>{
    const info = d.get(fw.flags[d.key]);
    if(!info) return;
    const row = document.createElement("div");
    row.className = "spec-row";
    row.innerHTML =
      `<span class="k">${d.label}</span>`+
      `<span class="v">${info.text}</span>`+
      `<span class="badge ${info.level}">${LEVEL_WORD[info.level]}</span>`;
    list.appendChild(row);
  });
}

/* ====================== 攻撃ライブラリ一覧 ====================== */
function renderAttackList(){
  const fw = getFw(state.eraId);
  const list = $("#attack-list");
  list.innerHTML = "";
  ATTACKS.forEach(atk=>{
    const res = atk.evaluate(fw);
    const st  = STATUS[res.status];
    const el = document.createElement("button");
    el.className = "atk" + (atk.id===state.atkId ? " selected":"");
    el.innerHTML =
      `<div class="atk-top">`+
        `<span class="ico">${atk.icon}</span>`+
        `<span class="nm">${atk.name}</span>`+
        `<span class="yr">${atk.year}</span>`+
      `</div>`+
      `<div class="desc">${atk.nameEn} ・ ${atk.category}</div>`+
      `<div class="mini"><span class="dotmini ${st.cls}"></span>この年代では：${st.chip}</div>`;
    el.addEventListener("click",()=>selectAttack(atk.id));
    list.appendChild(el);
  });
}

/* ====================== 選択ハンドラ ====================== */
function selectEra(id){
  runToken++;                       // 実行中アニメを無効化
  state.eraId = id;
  const fw = getFw(id);
  $$("#era-timeline .era").forEach((el,i)=>el.classList.toggle("selected", FIRMWARES[i].id===id));
  renderSpec(fw);
  renderAttackList();
  resetConsole();
  if(state.atkId) showBrief(getAtk(state.atkId));
}

function selectAttack(id){
  runToken++;
  state.atkId = id;
  $$("#attack-list .atk").forEach((el,i)=>el.classList.toggle("selected", ATTACKS[i].id===id));
  showBrief(getAtk(id));
  resetConsole();
  $("#run-btn").disabled = false;
}

function showBrief(atk){
  $("#attack-brief").innerHTML =
    `<b>${atk.icon} ${atk.name}</b>（${atk.nameEn}）<br>`+
    `<span style="font-size:12px">${atk.idea}</span>`;
}

/* ====================== コンソール ====================== */
function resetConsole(){
  const term = $("#terminal");
  term.innerHTML = `<div class="term-empty">// simulated console — 出力はすべて模擬です</div>`;
  $("#result-banner").hidden = true;
  $("#result-detail").hidden = true;
}

function appendLine(term, line){
  const div = document.createElement("div");
  div.className = "tl " + line.t;
  if(line.t === "cmd"){
    const pfx = document.createElement("span");
    pfx.className = "pfx";
    pfx.textContent = "attacker@lab:~$ ";
    div.appendChild(pfx);
    div.appendChild(document.createTextNode(line.s));
  } else {
    div.textContent = line.s;
  }
  term.appendChild(div);
  term.scrollTop = term.scrollHeight;
  return div;
}

async function runAttack(){
  const atk = getAtk(state.atkId);
  if(!atk) return;
  const fw  = getFw(state.eraId);
  const res = atk.evaluate(fw);
  const myToken = ++runToken;

  const term = $("#terminal");
  term.innerHTML = "";
  $("#result-banner").hidden = true;
  $("#result-detail").hidden = true;
  $("#run-btn").disabled = true;

  // ヘッダ行
  appendLine(term,{t:"info", s:`# target: ${fw.ip}  (${fw.model} / ${fw.version})`});
  appendLine(term,{t:"info", s:`# technique: ${atk.name} [${atk.nameEn}]`});
  const cursor = appendLine(term,{t:"out", s:""});
  cursor.innerHTML = '<span class="cursor"></span>';

  for(const line of res.console){
    await sleep(line.t==="cmd" ? 360 : 260);
    if(myToken !== runToken) return;          // 別の選択で中断された
    term.removeChild(cursor);
    appendLine(term, line);
    term.appendChild(cursor);
    term.scrollTop = term.scrollHeight;
  }
  await sleep(300);
  if(myToken !== runToken) return;
  term.removeChild(cursor);

  showResult(atk, res);
  $("#run-btn").disabled = false;
}

function showResult(atk, res){
  const st = STATUS[res.status];
  const banner = $("#result-banner");
  banner.className = "result-banner " + st.cls;
  banner.innerHTML = `<span>${st.banner}</span><span style="font-weight:600;font-size:13px">— ${res.headline}</span>`;
  banner.hidden = false;

  $("#result-detail").innerHTML =
    `<div class="rd-block"><h4>なぜこの結果になるか</h4><p>${res.why}</p></div>`+
    `<div class="rd-block"><h4>歴史的背景・実例</h4><p>${atk.incident}</p></div>`+
    `<div class="rd-block mitig"><h4>これを防いだ対策</h4><p>${atk.mitigation}</p></div>`;
  $("#result-detail").hidden = false;
}

/* ====================== マトリクス ====================== */
function renderMatrix(){
  const table = $("#matrix");
  // header
  let head = `<thead><tr><th style="text-align:left">攻撃手法 \\ 年代</th>`;
  FIRMWARES.forEach(fw=>{
    head += `<th><span class="yr">${fw.year}</span><span class="vv">${fw.version}・${fw.codename}</span></th>`;
  });
  head += `</tr></thead>`;

  let body = "<tbody>";
  ATTACKS.forEach(atk=>{
    body += `<tr><th><span class="ico">${atk.icon}</span>${atk.name}</th>`;
    FIRMWARES.forEach(fw=>{
      const res = atk.evaluate(fw);
      const st  = STATUS[res.status];
      body += `<td><button class="cell ${st.cls}" data-era="${fw.id}" data-atk="${atk.id}" `+
              `title="${fw.year} × ${atk.name}：${st.chip}\n${res.headline}">`+
              `<span class="mk">${st.mark}</span><span class="lbl">${st.chip}</span></button></td>`;
    });
    body += `</tr>`;
  });
  body += "</tbody>";
  table.innerHTML = head + body;

  $$("#matrix .cell").forEach(btn=>{
    btn.addEventListener("click",()=>{
      gotoTab("sim");
      selectEra(btn.dataset.era);
      selectAttack(btn.dataset.atk);
      window.scrollTo({top:0});
      runAttack();
    });
  });
}

/* ====================== 解説・年表 ====================== */
const HISTORY = [
  {y:"1959", h:"MIT / TMRC ―『ハック』の語源", d:"鉄道模型クラブの学生たちが仕組みを工夫する行為を“hack”と呼んだ。Levy『ハッカーズ』が描く出発点。"},
  {y:"1971", h:"ブルーボックスとフリーキング", d:"電話網の制御音を再現して無料通話。仕組みを解析して限界を試す文化＝後のセキュリティ探究の原型。"},
  {y:"1984", h:"Steven Levy『Hackers』", d:"“情報は自由を求める”等のハッカー倫理を記録。技術を深く知ることへの敬意が広まる。"},
  {y:"2001", h:"WEP 崩壊", d:"無線暗号WEPにIV再利用の致命的欠陥。のちにaircrack系で数分解読となり、無線の前提が覆る。"},
  {y:"2003-04", h:"家庭用ブロードバンドルーター普及", d:"“つながること”優先。admin/admin・平文HTTP・Telnet開放が当たり前で、本シミュレーターの最古年代に対応。"},
  {y:"2007-08", h:"WPS（かんたん設定）登場", d:"ボタン一つで接続できる利便性。しかし後にPIN総当たりの温床となる。"},
  {y:"2011", h:"Reaver（WPS PIN総当たり）", d:"8桁PINの検証分割という欠陥で総当たり空間が激減。Wi-Fiパスワードが数時間で抜ける事態に。"},
  {y:"2013", h:"UPnP大量露出 / TCP32764発見", d:"WAN側に露出したUPnPで推定4000万台超が脆弱と判明(Rapid7)。さらに製造元由来の隠しバックドア(TCP32764, Sercomm系)も発見される。"},
  {y:"2014", h:"Misfortune Cookie / DNS改ざん", d:"組込みHTTPサーバRomPagerの欠陥(CVE-2014-9222)で1200万台規模が影響。同年、CSRFや認証バイパスで約30万台のルーターDNSが書き換えられる大規模攻撃(SOHO Pharming)も発生し偽サイトへ誘導。"},
  {y:"2016", h:"Mirai → 大規模DDoS", d:"初期パスワードのIoTをTelnetで乗っ取るワーム。DNS事業者Dynが落ち主要Webが一斉ダウン。“出荷時設定の甘さ”の象徴。"},
  {y:"2017", h:"KRACK", d:"WPA2の鍵再インストールの脆弱性。広く使われた暗号も実装次第で揺らぐと示された。"},
  {y:"2018-20", h:"WPA3 / 初期パスワード規制", d:"WPA3(SAE)がオフライン辞書攻撃に耐性。米SB-327等で共通初期パスワードが事実上禁止に。自動更新も標準化。"},
  {y:"2022-23", h:"署名検証・セキュアブートが標準化", d:"信頼の起点をハードに置き、正規ファームしか起動させない。歴史的手法の大半が成立しない世代へ。"},
  {y:"2024-26", h:"脆弱性の“主役交代”", d:"初期パスワード等は新品で概ね解決。代わりに管理UIのメモリ破壊RCE(DrayTek DRAY:BREAK/CVSS10)、根強いコマンド注入、EOL機の放置によるボットネット(Quad7/RondoDox)、国家関与のSOHO踏み台化、Wi-Fi設計の穴(SSID Confusion)が前面に。"}
];

function renderLearn(){
  const tl = HISTORY.map(e=>
    `<li><span class="ty">${e.y}</span> <span class="th">${e.h}</span><div class="td">${e.d}</div></li>`).join("");

  const deep = ATTACKS.map(a=>
    `<div class="deep">`+
      `<div class="dh"><span class="ico">${a.icon}</span>${a.name}</div>`+
      `<div class="meta">${a.nameEn} ・ 登場:${a.year} ・ ${a.cve}</div>`+
      `<p><b>仕組み:</b> ${a.idea}</p>`+
      `<p><b>実例:</b> ${a.incident}</p>`+
      `<p><b>対策:</b> ${a.mitigation}</p>`+
      `<span class="tag">${a.category}</span>`+
    `</div>`).join("");

  $("#learn-content").innerHTML =
    `<div class="learn-card">`+
      `<h3>ハッカー文化から家庭用ルーターへ ― 年表</h3>`+
      `<p class="sub">本日の授業（Levy『ハッカーズ』/ MIT / フリーキング）から、ルーター・セキュリティの歴史へつなげた流れ</p>`+
      `<ul class="timeline">${tl}</ul>`+
    `</div>`+
    `<div class="learn-card">`+
      `<h3>2024年以降：脆弱性の“かたち”の変化</h3>`+
      `<p class="sub">古い問題は新品では概ね解決。しかし主役が入れ替わり、“現代機＝無敵”ではない。</p>`+
      `<div class="deep-grid">`+
        `<div class="deep"><div class="dh"><span class="ico">✅</span>ほぼ解決済み（新品）</div>`+
          `<p>初期パスワード / Telnet / WEP / WPS / RomPager系。出荷時設定の底上げと法規制で、歴史的手口は新品では通りにくい。</p></div>`+
        `<div class="deep"><div class="dh"><span class="ico">🔥</span>未解決・新たな主流</div>`+
          `<p>① 管理UIのメモリ破壊→RCE　② コマンドインジェクション(依然トップ級)　③ EOL機器の放置→ボットネット　④ 国家関与のSOHO踏み台化　⑤ Wi-Fi設計の穴(SSID Confusion)。</p></div>`+
        `<div class="deep"><div class="dh"><span class="ico">🧾</span>代表例 (2024-2026)</div>`+
          `<p>DrayTek DRAY:BREAK / CVE-2024-41592 (CVSS10)、D-Link旧DSL CVE-2026-0625 (実攻撃中)、TP-Link Quad7、RondoDox、SSID Confusion / CVE-2023-52424、Volt Typhoon。</p>`+
          `<span class="tag">更新の価値は2026年も健在</span></div>`+
      `</div>`+
    `</div>`+
    `<div class="learn-card">`+
      `<h3>攻撃手法ひとつずつ ― 仕組み・実例・対策</h3>`+
      `<p class="sub">シミュレーターで試した各手法の詳しい背景。レポートの引用元の入口にも。</p>`+
      `<div class="deep-grid">${deep}</div>`+
    `</div>`;
}

/* ============================ 起動 ============================ */
function init(){
  initTabs();
  renderEraTimeline();
  renderSpec(getFw(state.eraId));
  renderAttackList();
  renderMatrix();
  renderLearn();
  $("#run-btn").addEventListener("click", runAttack);
  // 既定で最初の攻撃を選んでおく（すぐ試せるように）
  selectAttack(ATTACKS[0].id);
}

document.addEventListener("DOMContentLoaded", init);
})();
