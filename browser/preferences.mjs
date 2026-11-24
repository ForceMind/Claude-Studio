export const gmailHome = 'https://mail.google.com/mail/';

export const languageOptions = [
  ['system', '跟随系统'],
  ['en-US', '英语（美国）'],
  ['en-GB', '英语（英国）'],
  ['ja-JP', '日语'],
  ['ko-KR', '韩语'],
  ['de-DE', '德语'],
  ['fr-FR', '法语'],
  ['es-ES', '西班牙语'],
  ['pt-BR', '葡萄牙语（巴西）'],
  ['it-IT', '意大利语'],
  ['vi-VN', '越南语'],
  ['id-ID', '印度尼西亚语'],
  ['zh-CN', '简体中文（中国大陆）'],
  ['zh-TW', '繁体中文（台湾）'],
  ['zh-HK', '繁体中文（香港）'],
  ['zh-SG', '简体中文（新加坡）'],
  ['zh-MO', '繁体中文（澳门）'],
  ['yue-HK', '粤语（香港）']
].map(([value, label]) => ({ value, label }));

const commonZones = [
  ['UTC', '协调世界时'],
  ['Pacific/Honolulu', '檀香山'],
  ['America/Anchorage', '安克雷奇'],
  ['America/Los_Angeles', '洛杉矶、旧金山'],
  ['America/Vancouver', '温哥华'],
  ['America/Phoenix', '凤凰城'],
  ['America/Denver', '丹佛'],
  ['America/Chicago', '芝加哥、达拉斯'],
  ['America/New_York', '纽约'],
  ['America/Toronto', '多伦多'],
  ['America/Mexico_City', '墨西哥城'],
  ['America/Bogota', '波哥大'],
  ['America/Lima', '利马'],
  ['America/Sao_Paulo', '圣保罗'],
  ['America/Argentina/Buenos_Aires', '布宜诺斯艾利斯'],
  ['Europe/London', '伦敦'],
  ['Europe/Dublin', '都柏林'],
  ['Europe/Paris', '巴黎'],
  ['Europe/Berlin', '柏林'],
  ['Europe/Amsterdam', '阿姆斯特丹'],
  ['Europe/Rome', '罗马'],
  ['Europe/Madrid', '马德里'],
  ['Europe/Stockholm', '斯德哥尔摩'],
  ['Europe/Helsinki', '赫尔辛基'],
  ['Europe/Athens', '雅典'],
  ['Europe/Istanbul', '伊斯坦布尔'],
  ['Europe/Moscow', '莫斯科'],
  ['Africa/Cairo', '开罗'],
  ['Africa/Johannesburg', '约翰内斯堡'],
  ['Africa/Nairobi', '内罗毕'],
  ['Asia/Jerusalem', '耶路撒冷'],
  ['Asia/Riyadh', '利雅得'],
  ['Asia/Dubai', '迪拜'],
  ['Asia/Karachi', '卡拉奇'],
  ['Asia/Kolkata', '新德里、孟买'],
  ['Asia/Dhaka', '达卡'],
  ['Asia/Bangkok', '曼谷'],
  ['Asia/Ho_Chi_Minh', '胡志明市'],
  ['Asia/Jakarta', '雅加达'],
  ['Asia/Singapore', '新加坡'],
  ['Asia/Kuala_Lumpur', '吉隆坡'],
  ['Asia/Manila', '马尼拉'],
  ['Asia/Tokyo', '东京'],
  ['Asia/Seoul', '首尔'],
  ['Australia/Perth', '珀斯'],
  ['Australia/Brisbane', '布里斯班'],
  ['Australia/Sydney', '悉尼'],
  ['Australia/Melbourne', '墨尔本'],
  ['Pacific/Auckland', '奥克兰'],
  ['Asia/Shanghai', '北京、上海'],
  ['Asia/Urumqi', '乌鲁木齐'],
  ['Asia/Hong_Kong', '香港'],
  ['Asia/Macau', '澳门'],
  ['Asia/Taipei', '台北']
];

export function timeZoneOptions(date = new Date()) {
  return [
    { value: 'system', label: '跟随系统' },
    ...commonZones.map(([value, city]) => {
      const parts = new Intl.DateTimeFormat('en-US', { timeZone: value, timeZoneName: 'longOffset' }).formatToParts(date);
      const offset = parts.find(part => part.type === 'timeZoneName')?.value ?? 'GMT';
      const utc = offset === 'GMT' ? 'UTC+00:00' : offset.replace(/^GMT/, 'UTC');
      return { value, label: city + '（' + utc + ' · ' + value + '）' };
    })
  ];
}

export const mailboxOptions = [
  [gmailHome, 'Gmail（默认）'],
  ['https://outlook.live.com/mail/', 'Outlook'],
  ['https://mail.yahoo.com/', 'Yahoo Mail'],
  ['https://mail.proton.me/', 'Proton Mail'],
  ['https://www.icloud.com/mail/', 'iCloud Mail'],
  ['https://mail.qq.com/', 'QQ 邮箱'],
  ['https://mail.163.com/', '网易 163 邮箱']
].map(([value, label]) => ({ value, label }));

export const effectiveMailbox = value => value || gmailHome;

const chineseLanguages = new Set(['zh', 'cmn', 'yue', 'nan', 'hak', 'gan', 'wuu', 'hsn']);
export function chineseLanguage(value) {
  try {
    const locale = new Intl.Locale(value);
    return chineseLanguages.has(locale.language) || locale.script === 'Hans' || locale.script === 'Hant';
  } catch {
    return false;
  }
}

const chineseZones = new Set([
  'asia/shanghai', 'asia/urumqi', 'asia/hong_kong', 'asia/macau', 'asia/macao', 'asia/taipei',
  'asia/chongqing', 'asia/chungking', 'asia/harbin', 'asia/kashgar', 'prc', 'roc', 'hongkong'
]);
export const chineseZone = value => chineseZones.has(value.toLowerCase());

const chineseMailboxes = new Set(['mail.qq.com', 'exmail.qq.com', 'mail.163.com', 'mail.126.com', 'mail.yeah.net']);
export function chineseMailbox(value) {
  try { return chineseMailboxes.has(new URL(value).hostname); }
  catch { return false; }
}

/** @param {{ value: string; label: string }[]} presets
 *  @param {string} saved
 *  @param {(value: string) => boolean} discouraged
 */
export function preferenceGroups(presets, saved, discouraged) {
  const regular = [];
  const last = [];
  const options = saved && !presets.some(option => option.value === saved)
    ? [...presets, { value: saved, label: saved }]
    : presets;
  for (const option of options) {
    if (discouraged(option.value)) last.push({ ...option, label: option.label + '（不推荐）' });
    else regular.push(option);
  }
  return { regular, last };
}
