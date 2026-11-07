// Logic/DOM-stub regression checks; these do not certify browser accessibility.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.listeners = {}; this.attributes = {}; this.value = ''; this.classList = { toggle() {}, add() {}, remove() {} }; }
  append(...items) { this.children.push(...items); }
  appendChild(item) { this.append(item); }
  replaceChildren(...items) { this.children = items; }
  setAttribute(key, value) { this.attributes[key] = value; }
  removeAttribute(key) { delete this.attributes[key]; }
  addEventListener(event, handler) { this.listeners[event] = handler; }
  focus() { this.focused = true; }
}
const elements = new Map();
const listeners = {};
const context = vm.createContext({
  assert, URLSearchParams, location: { search: '' }, console, setTimeout, clearTimeout,
  localStorage: { setItem() {}, getItem() { return null; } },
  document: {
    documentElement: new Element('html'),
    getElementById(id) { if (!elements.has(id)) elements.set(id, new Element('div')); return elements.get(id); },
    createElement(tag) { return new Element(tag); },
    createElementNS(_, tag) { return new Element(tag); },
    querySelectorAll() { return []; },
    addEventListener(event, handler) { listeners[event] = handler; }
  },
  elements, listeners, Element,
});
vm.runInContext(fs.readFileSync('netcheck/web/texts.js', 'utf8'), context);
const app = fs.readFileSync('netcheck/web/app.js', 'utf8').replace(/loadLanguage\(\);\s*bindEvents\(\);\s*loadScans\(\);\s*$/, '');
vm.runInContext(app, context);
vm.runInContext(`
const fixture = {id: 1, status: 'ok', devices: [{ip: '192.168.1.1', device_type: 'router'}], findings: [{ip: '192.168.1.1', code: 'HTTP_ADMIN_CLEARTEXT', severity: 'medium', title: {ro: 'Titlu', en: 'Title'}, explain: {ro: 'Explicație', en: 'Explanation'}, fix: {ro: ['Pas'], en: ['Step']}}]};
state.scans = [fixture]; state.currentScanId = 1;
state.lang = 'en'; assert.equal(findingTitle(fixture.findings[0]), 'Title');
assert.equal(localized(fixture.findings[0].fix)[0], 'Step');
state.lang = 'ro'; assert.equal(findingTitle(fixture.findings[0]), 'Titlu');
assert.deepEqual(Object.keys(TEXTS.ro).sort(), Object.keys(TEXTS.en).sort());
let renders = 0; render = () => { renders++; };
state.chatMessages = [{role: 'assistant', text: 'Vechi'}];
setLanguage('en'); assert.equal(state.chatMessages.length, 0);
assert.equal(findingTitle(fixture.findings[0]), 'Title');
const panel = new Element('div');
renderDeviceDetail(panel, fixture, '192.168.1.1');
assert(panel.children.some(child => child.id === 'panel-title'));
panel.children[panel.children.length - 1].listeners.click();
assert.equal(state.panel, 'chat'); assert(elements.get('inspector').focused);
state.chatMessages = [{role: 'user', text: 'Hello'}];
const chat = new Element('div'); renderChat(chat, fixture);
assert(chat.children.some(child => child.id === 'panel-title'));
const log = chat.children.find(child => child.attributes.role === 'log');
assert.equal(log.children[0].children[0].textContent, 'You');
bindEvents(); state.view = 'home'; state.selectedIp = '192.168.1.1';
let prevented = 0;
listeners.keydown({key: 'Escape', preventDefault() { prevented++; }});
assert.equal(state.panel, 'detail');
listeners.keydown({key: 'Escape', preventDefault() { prevented++; }});
assert.equal(state.panel, 'list'); assert.equal(prevented, 2);
elements.get('confirm-dialog').open = true; state.panel = 'chat';
listeners.keydown({key: 'Escape', preventDefault() { prevented++; }});
assert.equal(state.panel, 'chat');
console.log('Learning UI regression checks passed');
`, context);
