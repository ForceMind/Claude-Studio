const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const [language, directory] = process.argv.slice(2);
const dates = ['2026-01-15T12:00:00Z', '2026-07-15T12:00:00Z'].map(value => new Date(value));
console.log(JSON.stringify({
  marker: readFileSync(join(directory, 'simulated-marker.txt'), 'utf8'),
  locale: new Intl.DateTimeFormat(language || undefined).resolvedOptions().locale,
  defaultLocale: new Intl.DateTimeFormat().resolvedOptions().locale,
  zone: new Intl.DateTimeFormat().resolvedOptions().timeZone,
  offsets: dates.map(date => date.getTimezoneOffset())
}));
