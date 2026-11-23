import assert from 'node:assert/strict';
import test from 'node:test';
import {
  chineseLanguage, chineseMailbox, chineseZone, effectiveMailbox, gmailHome,
  languageOptions, mailboxOptions, preferenceGroups, timeZoneOptions
} from '../preferences.mjs';
import { parseProxyPort, proxyPortFromRegistry } from '../shell/proxy-detection.ts';

test('下拉选项保留自定义值，中文相关项在最后且有不推荐标记', () => {
  const sets = [
    [languageOptions, 'zh-Hant', chineseLanguage, 'en-CA'],
    [timeZoneOptions(), 'PRC', chineseZone, 'US/Pacific'],
    [mailboxOptions, 'https://mail.126.com/', chineseMailbox, 'https://mail.example.test/']
  ];
  for (const [presets, chinese, classify, other] of sets) {
    const grouped = preferenceGroups(presets, chinese, classify);
    assert.ok(grouped.regular.length > 0);
    assert.ok(grouped.regular.every(item => !classify(item.value)));
    assert.ok(grouped.last.some(item => item.value === chinese));
    assert.ok(grouped.last.every(item => classify(item.value) && item.label.endsWith('（不推荐）')));
    assert.ok(preferenceGroups(presets, other, classify).regular.some(item => item.value === other));
  }
});

test('主要城市使用中文名称，UTC 偏移随该城市日期变化', () => {
  const winter = timeZoneOptions(new Date('2026-01-15T12:00:00Z'));
  const summer = timeZoneOptions(new Date('2026-07-15T12:00:00Z'));
  const label = (rows, id) => rows.find(option => option.value === id)?.label;
  assert.match(label(winter, 'America/Los_Angeles'), /洛杉矶.*UTC-08:00.*America\/Los_Angeles/);
  assert.match(label(summer, 'America/Los_Angeles'), /洛杉矶.*UTC-07:00/);
  assert.match(label(winter, 'Asia/Kolkata'), /新德里.*UTC\+05:30/);
  assert.match(label(winter, 'Asia/Shanghai'), /上海.*UTC\+08:00/);
  assert.ok(winter.length >= 35);
});

test('未配置邮箱时默认 Gmail，原有 HTTPS 邮箱主页保持可选', () => {
  const saved = 'https://mail.example.test/webmail';
  assert.equal(effectiveMailbox(''), gmailHome);
  assert.equal(effectiveMailbox(saved), saved);
  assert.equal(preferenceGroups(mailboxOptions, saved, chineseMailbox).regular[0].value, gmailHome);
});

test('Windows 端口识别只采纳已开启且单一的本机 HTTP 代理', () => {
  const enabled = '    ProxyEnable    REG_DWORD    0x1\r\n';
  assert.equal(proxyPortFromRegistry(enabled, '    ProxyServer    REG_SZ    127.0.0.1:10810\r\n'), 10810);
  assert.equal(proxyPortFromRegistry(enabled.replace('0x1', '0x0'), '    ProxyServer    REG_SZ    127.0.0.1:10810\r\n'), null);
  assert.equal(proxyPortFromRegistry(enabled, ''), null);
  assert.equal(parseProxyPort('http=127.0.0.1:10810;https=http://localhost:10810;socks=127.0.0.1:9999'), 10810);
  assert.equal(parseProxyPort('http=127.0.0.1:10810;https=127.0.0.1:10811'), null);
  for (const unsupported of [
    'proxy.example.test:10810', 'https://127.0.0.1:10810', 'socks=127.0.0.1:10810',
    '[::1]:10810', '127.0.0.1:0', '127.0.0.1:99999', 'http://name@127.0.0.1:10810'
  ]) {
    assert.equal(parseProxyPort(unsupported), null, unsupported);
  }
});
