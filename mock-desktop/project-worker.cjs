const fs = require('node:fs/promises');
const path = require('node:path');
const { randomUUID } = require('node:crypto');

async function main() {
  const [operation, directory, key, mode] = process.argv.slice(2);
  const id = process.env.MOCK_PROFILE;
  if (!['A','B'].includes(id) || !['ro','rw'].includes(mode)) throw new Error('INVALID_GRANT');
  const info = await fs.stat(directory, {bigint:true});
  if (info.dev + '/' + info.ino !== key) throw new Error('PROJECT_CHANGED');
  const file = path.join(directory, 'note.txt');
  const stat = await fs.lstat(file);
  if (!stat.isFile() || stat.nlink !== 1) throw new Error('INVALID_TEST_FILE');
  if (operation === 'write') {
    if (mode !== 'rw') throw new Error('READ_ONLY');
    const tmp = path.join(directory, '.studio-' + randomUUID());
    await fs.writeFile(tmp, 'edited by simulated Code ' + id + '\n', {flag: 'wx'});
    try { await fs.rename(tmp, file); }
    finally { await fs.rm(tmp, {force:true}); }
  } else if (operation !== 'read') throw new Error('INVALID_OPERATION');
  console.log(JSON.stringify({profile: id, text: await fs.readFile(file, 'utf8')}));
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
