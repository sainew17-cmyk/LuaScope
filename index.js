
const { Client, GatewayIntentBits, EmbedBuilder, AttachmentBuilder, REST, Routes, SlashCommandBuilder } = require('discord.js');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));
const keepAlive = require('./keep_alive');

require('dotenv').config();
const TOKEN = process.env.DISCORD_TOKEN;
const CLIENT_ID = process.env.CLIENT_ID;

if (!TOKEN) {
  console.error('Missing DISCORD_TOKEN');
  process.exit(1);
}

const MAX_FILE_SIZE = 2 * 1024 * 1024;
const SCAN_DIR = process.env.SCAN_DIR || '/tmp/luascope_scans';
try { fs.mkdirSync(SCAN_DIR, { recursive: true }); } catch {}
const HISTORY_FILE = path.join(SCAN_DIR, 'history.json');

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------
function fileHash(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex').slice(0, 16);
}

function loadHistory() {
  try {
    if (fs.existsSync(HISTORY_FILE)) return JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8'));
  } catch {}
  return [];
}

function saveHistory(entry) {
  try {
    const h = loadHistory();
    h.push(entry);
    fs.writeFileSync(HISTORY_FILE, JSON.stringify(h.slice(-500), null, 2));
  } catch {}
}

function shannonEntropy(str) {
  if (!str) return 0;
  const counts = {};
  for (const c of str) counts[c] = (counts[c] || 0) + 1;
  const len = str.length;
  let e = 0;
  for (const k in counts) {
    const p = counts[k] / len;
    e -= p * Math.log2(p);
  }
  return e;
}

// ---------------------------------------------------------------
// Obfuscator detection
// ---------------------------------------------------------------
const SIGNATURES = {
  "Moonsec v3":  [/local\s+v3\s*=/, /getfenv\s*\(\s*0\s*\)/],
  "Moonsec v2":  [/LPH_NO_VIRTUALIZE/, /LPH_JIT/],
  "Luraph":      [/local\s+_\s*=\s*\(\s*function/, /return\s+_\s*\(\s*\.\.\.\s*\)/],
  "IronBrew2":   [/LPH_/, /0x[0-9A-Fa-f]{4,}\s*,\s*0x/],
  "AztupBrew":   [/AztupBrew/],
  "Prometheus":  [/Prometheus/],
  "Adonis-like": [/string\.reverse/, /table\.concat\s*\(\s*\{/]
};

function detectObf(code) {
  const hits = [];
  for (const [name, patterns] of Object.entries(SIGNATURES)) {
    let score = 0;
    for (const p of patterns) if (p.test(code)) score++;
    if (score > 0) hits.push({ name, score, total: patterns.length });
  }
  hits.sort((a, b) => b.score - a.score);
  return hits;
}

// ---------------------------------------------------------------
// Risk patterns
// ---------------------------------------------------------------
const RISK_PATTERNS = {
  "getrawmetatable": /\bgetrawmetatable\b/g,
  "setrawmetatable": /\bsetrawmetatable\b/g,
  "hookfunction":    /\bhookfunction\b/g,
  "hookmetamethod":  /\bhookmetamethod\b/g,
  "getgenv":         /\bgetgenv\s*\(/g,
  "getgc":           /\bgetgc\s*\(/g,
  "getconnections":  /\bgetconnections\b/g,
  "firesignal":      /\bfiresignal\b/g,
  "firetouchinterest": /\bfiretouchinterest\b/g,
  "fireproximityprompt": /\bfireproximityprompt\b/g,
  "identifyexecutor":/\bidentifyexecutor\b/g,
  "loadstring":      /\bloadstring\s*\(/g,
  "game:HttpGet":    /\bgame:HttpGet\b/g,
  "syn.protect_gui": /\bsyn\.protect_gui\b/g,
  "gethui":          /\bgethui\s*\(/g,
  "setclipboard":    /\bsetclipboard\b/g,
  "checkcaller":     /\bcheckcaller\b/g,
  "newcclosure":     /\bnewcclosure\b/g
};

function scanRisks(code) {
  const hits = [];
  for (const [name, pat] of Object.entries(RISK_PATTERNS)) {
    const m = code.match(pat);
    if (m) hits.push({ name, count: m.length });
  }
  hits.sort((a, b) => b.count - a.count);
  return hits;
}

function extractServices(code) {
  const svcs = new Set();
  const re = /GetService\s*\(\s*["']([^"']+)["']\s*\)/g;
  let m;
  while ((m = re.exec(code)) !== null) svcs.add(m[1]);
  return [...svcs].sort();
}

// ---------------------------------------------------------------
// Deobfuscator
// ---------------------------------------------------------------
function decodeHexStrings(code) {
  return code.replace(/(?:\\x[0-9A-Fa-f]{2})+/g, (seq) => {
    try {
      let out = '';
      for (let i = 0; i < seq.length; i += 4) {
        out += String.fromCharCode(parseInt(seq.slice(i + 2, i + 4), 16));
      }
      return out;
    } catch { return seq; }
  });
}

function decodeDecStrings(code) {
  return code.replace(/(?:\\\d{2,3})+/g, (seq) => {
    try {
      const nums = seq.match(/\\(\d{2,3})/g) || [];
      return nums.map(n => String.fromCharCode(parseInt(n.slice(1)))).join('');
    } catch { return seq; }
  });
}

function decodeB64Strings(code) {
  return code.replace(/"([A-Za-z0-9+/=]{12,})"/g, (full, raw) => {
    if (raw.length % 4 !== 0) return full;
    try {
      const decoded = Buffer.from(raw, 'base64').toString('utf8');
      if (/^[\x20-\x7E\r\n\t]+$/.test(decoded)) {
        return '"' + decoded.replace(/"/g, '\\"') + '"';
      }
    } catch {}
    return full;
  });
}

function resolveConcat(code) {
  const re = /"([^"]*)"(?:\s*\.\.\s*"([^"]*)")+/g;
  let prev;
  do {
    prev = code;
    code = code.replace(re, (m) => {
      const parts = [...m.matchAll(/"([^"]*)"/g)].map(x => x[1]);
      return '"' + parts.join('').replace(/"/g, '\\"') + '"';
    });
  } while (code !== prev);
  return code;
}

function deobfuscate(code) {
  const notes = [];
  let out = code;
  const passes = [
    ['hex', decodeHexStrings, 'Decoded \\xNN byte sequences'],
    ['dec', decodeDecStrings, 'Decoded \\NNN decimal sequences'],
    ['b64', decodeB64Strings, 'Decoded base64 strings'],
    ['cat', resolveConcat, 'Resolved string concatenations']
  ];
  for (let i = 0; i < 3; i++) {
    let changed = false;
    for (const [, fn, note] of passes) {
      const n = fn(out);
      if (n !== out) {
        out = n;
        if (!notes.includes(note)) notes.push(note);
        changed = true;
      }
    }
    if (!changed) break;
  }
  if (out === code) notes.push('No transformations matched - likely VM-based or already clean.');
  return { code: out, notes };
}

// ---------------------------------------------------------------
// Const dumper
// ---------------------------------------------------------------
function dumpConstants(code) {
  const strings = new Set();

  for (const m of code.matchAll(/"([^"\\\n]{3,})"/g)) strings.add(m[1]);
  for (const m of code.matchAll(/'([^'\\\n]{3,})'/g)) strings.add(m[1]);

  for (const m of code.matchAll(/(?:\\x[0-9A-Fa-f]{2}){3,}/g)) {
    try {
      let out = '';
      for (let i = 0; i < m[0].length; i += 4) out += String.fromCharCode(parseInt(m[0].slice(i + 2, i + 4), 16));
      strings.add(out);
    } catch {}
  }

  for (const m of code.matchAll(/(?:\\\d{2,3}){3,}/g)) {
    try {
      const nums = m[0].match(/\\(\d{2,3})/g) || [];
      strings.add(nums.map(n => String.fromCharCode(parseInt(n.slice(1)))).join(''));
    } catch {}
  }

  const all = [...strings].sort((a, b) => b.length - a.length);
  const urls = new Set();
  const hooks = new Set();
  for (const s of all) {
    const matches = s.match(/https?:\/\/[^\s"')]+/g) || [];
    for (const u of matches) {
      urls.add(u);
      if (u.includes('discord.com/api/webhooks/') || u.includes('discordapp.com/api/webhooks/')) hooks.add(u);
    }
  }
  return {
    strings: all.slice(0, 2000),
    urls: [...urls].sort(),
    webhooks: [...hooks].sort(),
    runtime_ok: true,
    lua_errors: []
  };
}

// ---------------------------------------------------------------
// Fetch URL
// ---------------------------------------------------------------
async function fetchUrl(url) {
  if (url.includes('pastebin.com/') && !url.includes('/raw/')) {
    const id = url.split('/').filter(Boolean).pop();
    url = `https://pastebin.com/raw/${id}`;
  }
  if (url.includes('github.com/') && url.includes('/blob/')) {
    url = url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/');
  }
  if (url.includes('hastebin.com/') && !url.includes('/raw/')) {
    const id = url.split('/').filter(Boolean).pop();
    url = `https://hastebin.com/raw/${id}`;
  }
  try {
    const r = await fetch(url, { timeout: 15000 });
    if (!r.ok) return { error: `HTTP ${r.status}` };
    const text = await r.text();
    if (text.length > MAX_FILE_SIZE) return { error: 'File too large (>2 MB)' };
    return { text };
  } catch (e) {
    return { error: e.message };
  }
}

// ---------------------------------------------------------------
// Discord client
// ---------------------------------------------------------------
const client = new Client({ intents: [GatewayIntentBits.Guilds] });

// ---------------------------------------------------------------
// Slash commands
// ---------------------------------------------------------------
const commands = [
  new SlashCommandBuilder()
    .setName('get')
    .setDescription('Fetch a script from a URL')
    .addStringOption(o => o.setName('url').setDescription('URL to fetch').setRequired(true)),

  new SlashCommandBuilder()
    .setName('scan')
    .setDescription('Full static analysis of a Lua file')
    .addAttachmentOption(o => o.setName('file').setDescription('.lua file').setRequired(true)),

  new SlashCommandBuilder()
    .setName('deob')
    .setDescription('Best-effort deobfuscation')
    .addAttachmentOption(o => o.setName('file').setDescription('Lua file').setRequired(false))
    .addStringOption(o => o.setName('url').setDescription('Or a URL').setRequired(false))
    .addStringOption(o => o.setName('code').setDescription('Or paste code').setRequired(false)),

  new SlashCommandBuilder()
    .setName('condumper')
    .setDescription('Dump every string/url/webhook from a Lua script')
    .addAttachmentOption(o => o.setName('file').setDescription('Lua file').setRequired(false))
    .addStringOption(o => o.setName('url').setDescription('Or a URL').setRequired(false))
    .addStringOption(o => o.setName('code').setDescription('Or paste code').setRequired(false)),

  new SlashCommandBuilder()
    .setName('history')
    .setDescription('Last 10 scans'),

  new SlashCommandBuilder()
    .setName('help')
    .setDescription('Show all commands'),
].map(c => c.toJSON());

// ---------------------------------------------------------------
// Ready
// ---------------------------------------------------------------
client.once('ready', async () => {
  console.log(`Logged in as ${client.user.tag}`);
  keepAlive.start(client);

  if (CLIENT_ID) {
    try {
      const rest = new REST({ version: '10' }).setToken(TOKEN);
      await rest.put(Routes.applicationCommands(CLIENT_ID), { body: commands });
      console.log(`Registered ${commands.length} slash commands globally`);
    } catch (e) {
      console.error('Slash command registration failed:', e);
    }
  } else {
    console.warn('CLIENT_ID not set - slash commands not registered');
  }
});

// ---------------------------------------------------------------
// Resolve source
// ---------------------------------------------------------------
async function resolveSource(interaction) {
  const file = interaction.options.getAttachment('file');
  const url = interaction.options.getString('url');
  const code = interaction.options.getString('code');

  if (file) {
    if (file.size > MAX_FILE_SIZE) return { error: 'File too large (max 2 MB)' };
    const r = await fetch(file.url);
    const text = await r.text();
    return { text, name: file.name };
  }
  if (url) {
    const r = await fetchUrl(url);
    if (r.error) return { error: `Fetch failed: ${r.error}` };
    let name = url.split('/').filter(Boolean).pop() || 'fetched.lua';
    if (!/\.(lua|luau|txt)$/i.test(name)) name += '.lua';
    return { text: r.text, name };
  }
  if (code) return { text: code, name: 'pasted.lua' };
  return { error: 'Provide file, url, or code.' };
}

// ---------------------------------------------------------------
// Command handler
// ---------------------------------------------------------------
client.on('interactionCreate', async (interaction) => {
  if (!interaction.isChatInputCommand()) return;

  const cmd = interaction.commandName;
  await interaction.deferReply().catch(() => {});
  const reply = (opts) => interaction.editReply(opts);

  try {
    // /help
    if (cmd === 'help') {
      const e = new EmbedBuilder()
        .setTitle('LuaScope - Commands')
        .setColor(0x5CA5FF)
        .addFields(
          { name: '/get url', value: 'Fetch a script from a URL (pastebin, github, hastebin)' },
          { name: '/scan file', value: 'Full static report - obfuscator, entropy, fingerprints' },
          { name: '/deob [file|url|code]', value: 'Best-effort deobfuscation (simple obfuscators)' },
          { name: '/condumper [file|url|code]', value: 'Dump every hidden string/url/webhook' },
          { name: '/history', value: 'Last 10 scans' },
        );
      return reply({ embeds: [e] });
    }

    // /get
    if (cmd === 'get') {
      const url = interaction.options.getString('url');
      const r = await fetchUrl(url);
      if (r.error) return reply({ content: `Error: ${r.error}` });
      const name = url.split('/').filter(Boolean).pop() || 'fetched.lua';
      const preview = r.text.slice(0, 1500) + (r.text.length > 1500 ? '\n... (truncated)' : '');
      const e = new EmbedBuilder()
        .setTitle(`Fetched - ${name}`)
        .setColor(0x5CA5FF)
        .setDescription('```lua\n' + preview + '\n```')
        .addFields(
          { name: 'Size', value: `${(r.text.length / 1024).toFixed(2)} KB`, inline: true },
          { name: 'Hash', value: '`' + fileHash(r.text) + '`', inline: true },
        );
      const file = new AttachmentBuilder(Buffer.from(r.text), { name });
      return reply({ embeds: [e], files: [file] });
    }

    // /scan
    if (cmd === 'scan') {
      const src = await resolveSource(interaction);
      if (src.error) return reply({ content: `Error: ${src.error}` });
      const code = src.text;
      const entropy = shannonEntropy(code);
      const detected = detectObf(code);
      const risks = scanRisks(code);
      const svcs = extractServices(code);

      let verdict, color;
      if (detected.length && entropy > 5.5) { verdict = 'HEAVILY OBFUSCATED - likely VM-based.'; color = 0xED4245; }
      else if (detected.length) { verdict = `OBFUSCATED - matched ${detected[0].name}.`; color = 0xE67E22; }
      else if (risks.length > 10) { verdict = `SCRIPT WITH ${risks.length} EXECUTOR FINGERPRINTS.`; color = 0xE67E22; }
      else if (risks.length) { verdict = `PLAIN SCRIPT - ${risks.length} exploit refs.`; color = 0xFEE75C; }
      else { verdict = 'CLEAN.'; color = 0x57F287; }

      const e = new EmbedBuilder()
        .setTitle(`Scan - ${src.name}`)
        .setDescription(verdict)
        .setColor(color)
        .addFields({
          name: 'Stats',
          value: `Size: **${(code.length / 1024).toFixed(2)} KB**\nLines: **${code.split('\n').length}**\nChars: **${code.length}**\nEntropy: **${entropy.toFixed(3)}** / 8.0\nHash: \`${fileHash(code)}\``,
        });
      if (detected.length) e.addFields({ name: 'Obfuscator', value: detected.slice(0, 5).map(d => `**${d.name}** - ${d.score}/${d.total} sigs`).join('\n') });
      if (risks.length) e.addFields({ name: 'Fingerprints', value: risks.slice(0, 15).map(r => `\`${r.name}\` x${r.count}`).join('\n') });
      if (svcs.length) e.addFields({ name: 'Services', value: svcs.slice(0, 20).map(s => `\`${s}\``).join(', ') });

      saveHistory({ user: interaction.user.tag, filename: src.name, hash: fileHash(code), type: 'scan', time: new Date().toISOString() });
      return reply({ embeds: [e] });
    }

    // /deob
    if (cmd === 'deob') {
      const src = await resolveSource(interaction);
      if (src.error) return reply({ content: `Error: ${src.error}` });
      const code = src.text;
      const detected = detectObf(code);
      const { code: cleaned, notes } = deobfuscate(code);
      const same = cleaned === code;

      const e = new EmbedBuilder()
        .setTitle(`Deob - ${src.name}`)
        .setColor(0x5CA5FF);
      e.addFields({
        name: 'Obfuscator match',
        value: detected.length ? detected.slice(0, 4).map(d => `**${d.name}** - ${d.score}/${d.total} sigs`).join('\n') : 'No known signature.'
      });
      if (notes.length) e.addFields({ name: 'Transforms applied', value: notes.map(n => `- ${n}`).join('\n') });
      if (same) e.addFields({ name: 'Result', value: 'No transformation applied - likely VM-based. Use /condumper instead.' });
      else e.addFields({ name: 'Output', value: 'Attached below.' });

      saveHistory({ user: interaction.user.tag, filename: src.name, hash: fileHash(code), type: 'deob', time: new Date().toISOString() });

      if (same) return reply({ embeds: [e] });
      const file = new AttachmentBuilder(Buffer.from(cleaned), { name: `${src.name}.deob.lua` });
      return reply({ embeds: [e], files: [file] });
    }

    // /condumper
    if (cmd === 'condumper') {
      const src = await resolveSource(interaction);
      if (src.error) return reply({ content: `Error: ${src.error}` });
      const result = dumpConstants(src.text);

      const e = new EmbedBuilder()
        .setTitle(`Condumper - ${src.name}`)
        .setColor(result.strings.length ? 0x57F287 : 0xFEE75C)
        .addFields(
          { name: 'Total strings', value: String(result.strings.length), inline: true },
          { name: 'URLs', value: String(result.urls.length), inline: true },
          { name: 'Webhooks', value: String(result.webhooks.length), inline: true },
        );
      if (result.webhooks.length) e.addFields({ name: 'Discord webhooks', value: result.webhooks.slice(0, 5).map(h => `\`${h.slice(0, 100)}\``).join('\n') });
      if (result.urls.length) e.addFields({ name: 'URLs', value: result.urls.slice(0, 8).map(u => `\`${u.slice(0, 100)}\``).join('\n') });

      saveHistory({ user: interaction.user.tag, filename: src.name, hash: fileHash(src.text), type: 'condumper', count: result.strings.length, time: new Date().toISOString() });

      const files = [];
      if (result.strings.length) {
        files.push(new AttachmentBuilder(Buffer.from(result.strings.join('\n')), { name: `${src.name}.strings.txt` }));
      }
      return reply({ embeds: [e], files });
    }

    // /history
    if (cmd === 'history') {
      const h = loadHistory().slice(-10).reverse();
      if (!h.length) return reply({ content: 'No scans yet.' });
      const e = new EmbedBuilder()
        .setTitle('Recent scans')
        .setColor(0x5CA5FF)
        .setDescription(h.map(x => `\`${x.hash}\` - ${x.type} - ${x.filename}`).join('\n'));
      return reply({ embeds: [e] });
    }

  } catch (err) {
    console.error(err);
    reply({ content: `Error: ${err.message}` });
  }
});

// ---------------------------------------------------------------
// Login
// ---------------------------------------------------------------
client.login(TOKEN);
