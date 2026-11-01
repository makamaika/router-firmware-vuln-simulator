const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { execFileSync } = require('node:child_process');

function appSource() {
  if (process.env.BASELINE === '1') {
    return execFileSync('git', ['show', 'HEAD:js/app.js'], { encoding: 'utf8' });
  }
  return fs.readFileSync(path.join(__dirname, '../js/app.js'), 'utf8');
}

function setup() {
  const nodes = new Map();
  const timers = [];
  class Element {
    constructor() {
      this.children = [];
      this.hidden = false;
      this.disabled = false;
      this.classList = { toggle() {} };
    }
    set innerHTML(value) { this._html = value; this.children = []; }
    get innerHTML() { return this._html || ''; }
    appendChild(child) { this.children.push(child); return child; }
    removeChild(child) { this.children.splice(this.children.indexOf(child), 1); }
    addEventListener() {}
  }
  const document = {
    querySelector(selector) {
      if (!nodes.has(selector)) nodes.set(selector, new Element());
      return nodes.get(selector);
    },
    querySelectorAll() { return []; },
    createElement() { return new Element(); },
    createTextNode(text) { return { text }; },
    addEventListener() {},
  };
  const firmware = [
    { id: 'old', ip: '192.0.2.1', model: 'Old', version: '1', year: 2004, flags: {} },
    { id: 'new', ip: '192.0.2.2', model: 'New', version: '2', year: 2024, flags: {} },
  ];
  const attacks = ['a', 'b'].map((id) => ({
    id, icon: '*', name: id, nameEn: id, year: 2000, category: 'test', idea: 'test',
    incident: 'test', mitigation: 'test',
    evaluate: () => ({ status: 'failed', console: [{ t: 'out', s: id }], headline: id, why: id }),
  }));
  const source = appSource().replace('document.addEventListener("DOMContentLoaded", init);',
    'globalThis.testApi = { selectEra, selectAttack, runAttack, state };');
  const context = { document, window: {}, FIRMWARES: firmware, ATTACKS: attacks,
    FLAG_DESCRIPTORS: [], setTimeout: (fn) => { timers.push(fn); } };
  vm.runInNewContext(source, context);
  async function tick() {
    assert.ok(timers.length, 'pending animation timer');
    timers.shift()();
    await Promise.resolve();
  }
  async function drain() {
    for (let i = 0; timers.length && i < 20; i++) await tick();
    assert.equal(timers.length, 0);
  }
  return { ...context.testApi, nodes, tick, drain };
}

test('normal completion and selection cancellation restore the run button', async () => {
  const app = setup();
  const button = app.nodes.get('#run-btn') || (() => { app.selectAttack('a'); return app.nodes.get('#run-btn'); })();
  app.selectAttack('a');
  let run = app.runAttack();
  assert.equal(button.disabled, true);
  await app.drain();
  await run;
  assert.equal(button.disabled, false);

  run = app.runAttack();
  app.selectAttack('b');
  assert.equal(button.disabled, false);
  await app.drain();
  await run;
  assert.equal(button.disabled, false);

  run = app.runAttack();
  app.selectEra('new');
  assert.equal(button.disabled, false, 'era change permits running the selected attack');
  await app.drain();
  await run;
  assert.equal(button.disabled, false);
});

test('an old cancelled run cannot change a newer run or its result', async () => {
  const app = setup();
  app.selectAttack('a');
  const button = app.nodes.get('#run-btn');
  const oldRun = app.runAttack();
  app.selectEra('new');
  const newRun = app.runAttack();
  assert.equal(button.disabled, true);
  await app.tick(); // old run exits here
  await oldRun;
  assert.equal(button.disabled, true, 'old run must not enable the new run early');
  await app.drain();
  await newRun;
  assert.equal(button.disabled, false);
  assert.equal(app.nodes.get('#result-banner').hidden, false);
});
