// .env dosyasındaki değişkenleri process.env'e yükler (örn. API_KEY).
// Prod'da .env yerine gerçek ortam değişkeni / secret manager kullanılıyorsa bu satır zararsızdır:
// .env dosyası yoksa dotenv sessizce hiçbir şey yapmaz, zaten set edilmiş değişkenlerin üzerine yazmaz.
require('dotenv').config();

const express = require('express');
const pacote = require('pacote');
const path = require('path');
const os = require('os');
const fs = require('fs');
const crypto = require('crypto');
const { createTwoFilesPatch } = require('diff');
const { TextDecoder } = require('util');

const app = express();
app.disable('x-powered-by'); // Express versiyonunu header üzerinden ifşa etme
app.use(express.json({ limit: '1mb' })); // İstek gövdesi zaten küçük (paket adı + versiyon), büyük body'leri baştan reddet

const API_KEY = process.env.API_KEY;

if (!API_KEY) {
  console.error('HATA: API_KEY ortam değişkeni tanımlı değil. Servis güvenli şekilde başlatılamıyor.');
  process.exit(1);
}

function timingSafeCompare(providedValue, expectedValue) {
  const providedHash = crypto.createHash('sha256').update(String(providedValue)).digest();
  const expectedHash = crypto.createHash('sha256').update(String(expectedValue)).digest();
  return crypto.timingSafeEqual(providedHash, expectedHash);
}

app.use((req, res, next) => {
  const providedKey = req.header('x-api-key');

  if (!providedKey || !timingSafeCompare(providedKey, API_KEY)) {
    return res.status(401).json({
      error_type: 'unauthorized',
      message: 'Geçersiz veya eksik x-api-key header\'ı'
    });
  }

  next();
});


const MAX_STRINGS_RETURNED = 50; // binary'den çıkarılan şüpheli string sayısı sınırı

// --- DoS Limits ---
const MAX_FILE_COUNT_PER_PACKAGE = 5000; // bir paket sürümünde beklenenin çok üzerinde dosya = şüpheli/kaynak tüketimi riski
const MAX_TOTAL_EXTRACTED_BYTES = 200 * 1024 * 1024; // 200MB - tek bir paket sürümü için toplam disk/bellek bütçesi
const MAX_SINGLE_FILE_SCAN_BYTES = 10 * 1024 * 1024; // 10MB - bunun üzerindeki dosyalar tamamen belleğe okunup taranmaz, sadece hash'lenir
const MAX_CONCURRENT_DIFF_REQUESTS = 3; // aynı anda işlenen /diff isteği sayısı sınırı

const MAX_INLINE_DIFF_CHARS = 50000; // ~50KB üzeri metin dosyalarında tam diff yerine özet döneriz
const MAX_DIFF_STORAGE_FILE_BYTES = 5 * 1024 * 1024;
const MAX_DIFF_STORAGE_TOTAL_BYTES = 500 * 1024 * 1024;

const DIFF_STORAGE_DIR = path.join(os.tmpdir(), 'npm-diff-storage');

let activeDiffRequests = 0;

const PACKAGE_NAME_REGEX = /^(@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
// Sadece kesin semver kabul edilir (aralık, "latest" gibi tag, git url, dosya yolu vs. REDDEDİLİR)
const SEMVER_REGEX = /^\d{1,5}\.\d{1,5}\.\d{1,5}(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/;

function isValidPackageName(name) {
  return typeof name === 'string' && name.length > 0 && name.length <= 214 && PACKAGE_NAME_REGEX.test(name);
}

function isValidVersion(version) {
  return typeof version === 'string' && version.length <= 100 && SEMVER_REGEX.test(version);
}

// Dosyanın ilk birkaç byte'ına (magic number) bakarak gerçek tipini tahmin eder
// Uzantı yalan söyleyebilir (örn. "resim.png" aslında bir .exe olabilir), bu yüzden gerçek içeriğe bakıyoruz
function detectFileType(buffer) {
  if (buffer.length < 4) return 'unknown (too small)';

  const hex4 = buffer.subarray(0, 4).toString('hex').toUpperCase();
  const hex2 = buffer.subarray(0, 2).toString('hex').toUpperCase();

  if (hex2 === '4D5A') return 'PE executable (Windows .exe/.dll)';
  if (hex4 === '7F454C46') return 'ELF executable (Linux binary)';
  if (hex4 === 'CAFEBABE' || hex4 === 'CFFAEDFE' || hex4 === 'CEFAEDFE') return 'Mach-O executable (macOS binary)';
  if (hex2 === '504B') return 'ZIP/JAR arşivi';
  if (hex4 === '89504E47') return 'PNG resim';
  if (hex4.startsWith('FFD8')) return 'JPEG resim';
  if (hex4 === '25504446') return 'PDF';

  return 'bilinmeyen binary format';
}

// Binary içindeki okunabilir (ASCII) metin parçalarını çıkarır — "strings" komutunun basit bir versiyonu
function extractPrintableStrings(buffer, minLength = 5) {
  const strings = [];
  let current = '';

  for (let i = 0; i < buffer.length; i++) {
    const byte = buffer[i];
    const isPrintable = byte >= 32 && byte <= 126;

    if (isPrintable) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= minLength) strings.push(current);
      current = '';
    }
  }
  if (current.length >= minLength) strings.push(current);

  return strings;
}

// Metin dosyasının tüm içeriğini TEK PARÇA olarak tarar (satır sınırlarını aşan
// multi-line kalıpları — örn. \ ile bölünmüş curl|bash komutlarını — kaçırmamak için).
// Eşleşme bulunduğunda hangi satırda olduğunu da hesaplayıp rapora ekler.
function scanTextContentForSuspiciousPatterns(content) {
  const matches = [];

  for (const pattern of SUSPICIOUS_STRING_PATTERNS) {
    // 'g' flag'i olmadan regex.exec() sonsuz döngüye girebilir, bu yüzden
    // global bir kopya oluşturuyoruz (orijinal pattern.regex'i bozmadan)
    const globalRegex = new RegExp(pattern.regex.source, pattern.regex.flags.includes('g') ? pattern.regex.flags : pattern.regex.flags + 'g');

    let match;
    while ((match = globalRegex.exec(content)) !== null) {
      const matchedText = match[0];
      const upToMatch = content.slice(0, match.index);
      const lineNumber = upToMatch.split('\n').length; // 1-indexed satır numarası

      matches.push({
        matched_string: matchedText.slice(0, 200),
        reason: pattern.label,
        line: lineNumber
      });

      if (matches.length >= MAX_STRINGS_RETURNED) return matches;

      // Aynı regex'in aynı noktada sonsuz döngüye girmesini önle (sıfır-genişlikli eşleşmeler için)
      if (match[0].length === 0) globalRegex.lastIndex++;
    }
  }

  return matches;
}

function sha256OfFileSync(filePath, chunkSize = 1024 * 1024) {
  const fd = fs.openSync(filePath, 'r');
  const hash = crypto.createHash('sha256');
  const buffer = Buffer.alloc(chunkSize);
  try {
    let bytesRead;
    while ((bytesRead = fs.readSync(fd, buffer, 0, chunkSize, null)) > 0) {
      hash.update(buffer.subarray(0, bytesRead));
    }
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest('hex');
}
function getDirectorySize(dir) {
  if (!fs.existsSync(dir)) return 0;

  let total = 0;

  const stack = [dir];

  while (stack.length) {
    const current = stack.pop();

    for (const entry of fs.readdirSync(current, {
      withFileTypes:true
    })) {
      const fullPath = path.join(current, entry.name);

      if (entry.isDirectory()) {
        stack.push(fullPath);
      } else {
        total += fs.statSync(fullPath).size;
      }
    }
  }

  return total;
}

function saveDiffToStorage(diffContent) {
  const diffSize = Buffer.byteLength(diffContent, 'utf8');

  if (diffSize > MAX_DIFF_STORAGE_FILE_BYTES) {
    throw new Error(
      'LIMIT_EXCEEDED: Diff dosyası storage sınırını aşıyor'
    );
  }

  // Klasörü güvenli oluştur
  fs.mkdirSync(DIFF_STORAGE_DIR, {
    recursive: true,
    mode: 0o700
  });

  // Mevcut storage boyutu
  const currentStorageSize = getDirectorySize(DIFF_STORAGE_DIR);

  if (currentStorageSize + diffSize > MAX_DIFF_STORAGE_TOTAL_BYTES) {
    throw new Error(
      'LIMIT_EXCEEDED: Diff storage toplam kapasitesi dolu'
    );
  }

  // Rastgele dosya adı
  const id = crypto.randomBytes(16).toString('hex');

  const filePath = path.join(
    DIFF_STORAGE_DIR,
    `${id}.patch`
  );

  const tempPath = `${filePath}.tmp`;

  fs.writeFileSync(
    tempPath,
    diffContent,
    {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx'
    }
  );

  fs.renameSync(tempPath, filePath);

  return {
    id,
    filePath,
    size_bytes: diffSize
  };
}

function createHashCache() {
  const cache = new Map();

  return function getFileHash(filePath) {
    if (cache.has(filePath)) {
      return cache.get(filePath);
    }

    const hash = sha256OfFileSync(filePath);
    cache.set(filePath, hash);

    return hash;
  };
}

function readFirstBytes(filePath, n) {
  const fd = fs.openSync(filePath, 'r');
  try {
    const buffer = Buffer.alloc(n);
    const bytesRead = fs.readSync(fd, buffer, 0, n, 0);
    return buffer.subarray(0, bytesRead);
  } finally {
    fs.closeSync(fd);
  }
}

function analyzeTextFile(filePath) {
  const stat = fs.statSync(filePath);
  const sha256 = sha256OfFileSync(filePath);

  if (stat.size > MAX_SINGLE_FILE_SCAN_BYTES) {
    return {
      size_bytes: stat.size,
      sha256,
      suspicious_strings_found: [],
      scan_skipped: true,
      scan_skip_reason: `Dosya boyutu tarama sınırını aşıyor (>${MAX_SINGLE_FILE_SCAN_BYTES} byte), sadece hash hesaplandı`
    };
  }

  const content = fs.readFileSync(filePath, 'utf8');
  const suspiciousMatches = scanTextContentForSuspiciousPatterns(content);

  return {
    size_bytes: stat.size,
    sha256,
    suspicious_strings_found: suspiciousMatches,
    content
  };
}
// Çıkarılan string'leri, mevcut script heuristiklerimizle aynı şüpheli kalıplara karşı tarar
const SUSPICIOUS_STRING_PATTERNS = [
  { regex: /(curl|wget)\s+.*(https?:\/\/)/i, label: 'Uzaktan indirme komutu' },
  { regex: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i, label: 'IP adresine direkt istek' },
  { regex: /\.onion\b/i, label: 'Tor (.onion) adresi' },
  { regex: /(cmd\.exe|powershell|\/bin\/sh|\/bin\/bash)/i, label: 'Komut satırı yorumlayıcı referansı' },
  { regex: /(discord\.com\/api\/webhooks|telegram\.org\/bot)/i, label: 'Bilinen exfiltration kanalı (Discord/Telegram webhook)' }
];

function scanStringsForSuspiciousPatterns(strings) {
  const matches = [];
  for (const str of strings) {
    for (const pattern of SUSPICIOUS_STRING_PATTERNS) {
      if (pattern.regex.test(str)) {
        matches.push({ matched_string: str.slice(0, 200), reason: pattern.label });
      }
    }
  }
  return matches.slice(0, MAX_STRINGS_RETURNED);
}

// Bir binary dosyayı analiz eder: hash, tip, şüpheli string'ler
// MAX_SINGLE_FILE_SCAN_BYTES üzerindeki dosyalarda tam buffer okunmaz.
function analyzeBinaryFile(filePath) {
  const stat = fs.statSync(filePath);
  const sha256 = sha256OfFileSync(filePath);

  if (stat.size > MAX_SINGLE_FILE_SCAN_BYTES) {
    const headerBuffer = readFirstBytes(filePath, 16);
    return {
      size_bytes: stat.size,
      sha256,
      file_type: detectFileType(headerBuffer),
      suspicious_strings_found: [],
      scan_skipped: true,
      scan_skip_reason: `Dosya boyutu tarama sınırını aşıyor (>${MAX_SINGLE_FILE_SCAN_BYTES} byte), sadece hash/tip hesaplandı`
    };
  }

  const buffer = fs.readFileSync(filePath);
  const strings = extractPrintableStrings(buffer);
  const suspiciousMatches = scanStringsForSuspiciousPatterns(strings);

  return {
    size_bytes: stat.size,
    sha256,
    file_type: detectFileType(buffer),
    suspicious_strings_found: suspiciousMatches
  };
}

function listFilesRecursive(dir, baseDir = dir) {
  let results = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results = results.concat(listFilesRecursive(fullPath, baseDir));
    } else {
      const relativePath = path.relative(baseDir, fullPath).split(path.sep).join('/');
      results.push(relativePath);
    }
  }
  return results;
}

// ============================================================
// DoS Limits: bir paketin açıldığı dizindeki toplam dosya sayısını ve toplam
// boyutu kontrol eder. Sınır aşılırsa işlemi durdurmak için hata fırlatır
// (mesaj "LIMIT_EXCEEDED:" ile başlar, classifyError bunu ayrı ele alır).
// ============================================================
function enforceExtractedPackageLimits(dir, label) {
  let totalSize = 0;
  let fileCount = 0;
  const stack = [dir];

  while (stack.length) {
    const current = stack.pop();
    const entries = fs.readdirSync(current, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);

      if (entry.isDirectory()) {
        stack.push(fullPath);
        continue;
      }

      fileCount++;
      if (fileCount > MAX_FILE_COUNT_PER_PACKAGE) {
        throw new Error(`LIMIT_EXCEEDED: ${label} dosya sayısı sınırı aşıldı (>${MAX_FILE_COUNT_PER_PACKAGE})`);
      }

      totalSize += fs.statSync(fullPath).size;
      if (totalSize > MAX_TOTAL_EXTRACTED_BYTES) {
        throw new Error(`LIMIT_EXCEEDED: ${label} toplam boyut sınırı aşıldı (>${MAX_TOTAL_EXTRACTED_BYTES} byte)`);
      }
    }
  }
}

// Metin olduğu bilinen dosya UZANTILARI (script dilleri ve config formatları dahil)
const TEXT_EXTENSIONS = [
  '.js', '.ts', '.json', '.md', '.txt', '.yml', '.yaml', '.mjs', '.cjs', '.jsx', '.tsx', '.html', '.css',
  '.sh', '.bash', '.zsh', '.py', '.rb', '.pl', '.ps1', '.php',
  '.toml', '.ini', '.cfg', '.conf', '.xml', '.svg', '.graphql', '.vue', '.svelte', '.lock'
];

// Uzantısı olmayan ama bilinen METİN dosya adları (küçük/büyük harf duyarsız karşılaştırılır)
const TEXT_FILENAMES = [
  'license', 'licence', 'copying', 'readme', 'changelog', 'authors', 'contributors', 'notice',
  'makefile', 'dockerfile', 'rakefile', 'gemfile', 'procfile',
  '.npmignore', '.gitignore', '.editorconfig', '.eslintrc', '.babelrc', '.prettierrc',
  '.npmrc', '.nvmrc', '.flowconfig', '.browserslistrc', '.dockerignore'
];

function isProbablyText(filePath) {
  // 1. Bilinen text uzantıları
  const ext = path.extname(filePath).toLowerCase();
  if (TEXT_EXTENSIONS.includes(ext)) return true;

  // 2. Bilinen text dosya isimleri
  const baseName = path.basename(filePath).toLowerCase();
  if (TEXT_FILENAMES.includes(baseName)) return true;

  // 3. İçeriğe bak
  const buffer = readFirstBytes(filePath, 4096);

  // Boş dosya text kabul edilir
  if (buffer.length === 0) return true;

  // NUL byte varsa büyük ihtimal binary
  if (buffer.includes(0x00)) return false;

  // UTF-8 olarak decode edilebiliyorsa text kabul et
  try {
    const decoder = new TextDecoder('utf-8', { fatal: true });
    decoder.decode(buffer);
    return true;
  } catch {
    return false;
  }
}

function safeReadJson(filePath) {
  if (!fs.existsSync(filePath)) {
    return { data: {}, parse_error: null };
  }
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    return { data: JSON.parse(raw), parse_error: null };
  } catch (err) {
    return { data: {}, parse_error: 'package.json parse edilemedi (bozuk/geçersiz JSON içeriği)' };
  }
}

function analyzePackageJsonChange(fromDir, toDir) {
  const fromPkgPath = path.join(fromDir, 'package.json');
  const toPkgPath = path.join(toDir, 'package.json');

  if (!fs.existsSync(fromPkgPath) || !fs.existsSync(toPkgPath)) {
    return null;
  }

  const { data: fromPkg, parse_error: fromParseError } = safeReadJson(fromPkgPath);
  const { data: toPkg, parse_error: toParseError } = safeReadJson(toPkgPath);

  const report = buildPackageJsonReport(fromPkg, toPkg);
  const parseErrors = [fromParseError, toParseError].filter(Boolean);
  if (parseErrors.length > 0) {
    report.parse_warning = parseErrors.join(' | ');
  }
  return report;
}

function buildPackageJsonReport(fromPkg, toPkg) {
  const fromScripts = (fromPkg && fromPkg.scripts) || {};
  const toScripts = (toPkg && toPkg.scripts) || {};

  const installScriptChanged =
    fromScripts.postinstall !== toScripts.postinstall ||
    fromScripts.preinstall !== toScripts.preinstall ||
    fromScripts.install !== toScripts.install;

  const fromDeps = Object.keys((fromPkg && fromPkg.dependencies) || {});
  const toDeps = Object.keys((toPkg && toPkg.dependencies) || {});
  const newDependencies = toDeps.filter(d => !fromDeps.includes(d));
  const removedDependencies = fromDeps.filter(d => !toDeps.includes(d));

  return {
    install_script_changed: installScriptChanged,
    scripts_before: {
      preinstall: fromScripts.preinstall || null,
      install: fromScripts.install || null,
      postinstall: fromScripts.postinstall || null
    },
    scripts_after: {
      preinstall: toScripts.preinstall || null,
      install: toScripts.install || null,
      postinstall: toScripts.postinstall || null
    },
    new_dependencies: newDependencies,
    removed_dependencies: removedDependencies
  };
}

function classifyFiles(dir, relPaths) {
  const textFiles = [];
  const binaryFiles = [];

  for (const relPath of relPaths) {
    const fullPath = path.join(dir, relPath);

    if (isProbablyText(fullPath)) {
      const analysis = analyzeTextFile(fullPath);
      textFiles.push({ path: relPath, ...analysis });
    } else {
      const analysis = analyzeBinaryFile(fullPath);
      binaryFiles.push({ path: relPath, ...analysis });
    }
  }

  return { textFiles, binaryFiles };
}

function compareCommonBinaryFiles(fromDir, toDir, commonPaths, getFileHash) {
  const changed = [];

  for (const relPath of commonPaths) {
    const fromFilePath = path.join(fromDir, relPath);
    const toFilePath = path.join(toDir, relPath);

    if (isProbablyText(toFilePath) || isProbablyText(fromFilePath)) continue;

    const fromHash = getFileHash(fromFilePath);
    const toHash = getFileHash(toFilePath);

    if (fromHash !== toHash) {
      const toAnalysis = analyzeBinaryFile(toFilePath);

      changed.push({
        path: relPath,
        sha256_before: fromHash,
        sha256_after: toHash,
        ...toAnalysis
      });
    }
  }

  return changed;
}

function classifyError(err) {
  const rawMessage = (err && err.message) || '';

  if (rawMessage.startsWith('LIMIT_EXCEEDED')) {
    // Bu mesaj bilerek biz tarafımızdan üretildi, sadece sayısal sınırlar içeriyor -> güvenle dönülebilir
    return { error_type: 'limit_exceeded', message: rawMessage.replace('LIMIT_EXCEEDED: ', '') };
  }
  if (rawMessage.includes('No matching version found') || rawMessage.includes('404')) {
    return { error_type: 'package_or_version_not_found', message: 'Belirtilen paket veya versiyon npm registry\'de bulunamadı' };
  }
  if (rawMessage.includes('ENOTFOUND') || rawMessage.includes('ETIMEDOUT') || rawMessage.includes('ECONNREFUSED')) {
    return { error_type: 'network_error', message: 'npm registry\'e bağlanılamadı, lütfen tekrar deneyin' };
  }

  // Bilinmeyen/beklenmeyen hatalar: detay sadece sunucu logunda kalır, istemciye asla iç bilgi (dosya yolu, stack vb.) sızdırılmaz
  console.error('Diff API - beklenmeyen hata:', err);
  return { error_type: 'unknown_error', message: 'İşlem sırasında beklenmeyen bir sunucu hatası oluştu' };
}
function collectSecuritySignals({
  textFiles = [],
  binaryFiles = [],
  largeFiles = []
}) {
  const signals = [];

  for (const file of textFiles) {
    if (
      file.suspicious_strings_found &&
      file.suspicious_strings_found.length > 0
    ) {
      for (const item of file.suspicious_strings_found) {
        signals.push({
          type: 'suspicious_text_pattern',
          file: file.path,
          reason: item.reason,
          matched_string: item.matched_string
        });
      }
    }
  }

  for (const file of binaryFiles) {
    if (
      file.suspicious_strings_found &&
      file.suspicious_strings_found.length > 0
    ) {
      for (const item of file.suspicious_strings_found) {
        signals.push({
          type: 'suspicious_binary_string',
          file: file.path,
          reason: item.reason,
          matched_string: item.matched_string
        });
      }
    }
  }

  for (const file of largeFiles) {
    if (file.scan_skipped) {
      signals.push({
        type: 'large_file_unscanned',
        file: file.path,
        reason: 'Dosya boyutu nedeniyle içerik taraması yapılmadı',
        size_before_bytes: file.size_before_bytes,
        size_after_bytes: file.size_after_bytes
      });
    }
  }

  return signals;
}
app.post('/diff', async (req, res) => {
  const getFileHash = createHashCache();

  if (activeDiffRequests >= MAX_CONCURRENT_DIFF_REQUESTS) {
    return res.status(429).json({
      error_type: 'too_many_requests',
      message: 'Sunucu şu an çok fazla istek işliyor, lütfen daha sonra tekrar deneyin'
    });
  }

  const { package: pkgName, from_version, to_version } = req.body;

  // to_version her zaman zorunlu; from_version artık OPSİYONEL (ilk kontrol senaryosu)
  if (!pkgName || !to_version) {
    return res.status(400).json({
      error_type: 'invalid_request',
      message: 'package ve to_version zorunlu'
    });
  }

  // --- Input Sanitization: paket adı ve versiyon formatlarını doğrula ---
  if (!isValidPackageName(pkgName)) {
    return res.status(400).json({
      error_type: 'invalid_request',
      message: 'Geçersiz paket adı formatı'
    });
  }
  if (!isValidVersion(to_version)) {
    return res.status(400).json({
      error_type: 'invalid_request',
      message: 'Geçersiz to_version formatı (kesin semver bekleniyor, ör. 1.2.3)'
    });
  }
  if (from_version !== undefined && from_version !== null && !isValidVersion(from_version)) {
    return res.status(400).json({
      error_type: 'invalid_request',
      message: 'Geçersiz from_version formatı (kesin semver bekleniyor, ör. 1.2.3)'
    });
  }

  activeDiffRequests++;
  let tempDir;

  try {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-diff-'));

    // --- DURUM A: İlk kontrol (baseline yok, from_version verilmemiş) ---
    if (!from_version) {
      const toDir = path.join(tempDir, `to-${to_version}`);
      await pacote.extract(`${pkgName}@${to_version}`, toDir);
      enforceExtractedPackageLimits(toDir, `${pkgName}@${to_version}`);

      const allFiles = listFilesRecursive(toDir);
      const { textFiles, binaryFiles } = classifyFiles(toDir, allFiles);

      const toPkgPath = path.join(toDir, 'package.json');
      const { data: toPkg } = safeReadJson(toPkgPath);
      const toScripts = toPkg.scripts || {};

      return res.json({
        mode: 'first_check',
        package: pkgName,
        to_version,
        files: allFiles,
        text_files: textFiles,
        binary_files: binaryFiles,
        install_scripts: {
          preinstall: toScripts.preinstall || null,
          install: toScripts.install || null,
          postinstall: toScripts.postinstall || null
        }
      });
    }

    // --- DURUM B: Aynı versiyon isteniyor (tamper/entegrite senaryosu) ---
    if (from_version === to_version) {
      return res.json({
        mode: 'same_version_requested',
        package: pkgName,
        version: to_version,
        message: 'from_version ve to_version aynı. Kod diff\'i anlamsız; tarball bütünlüğü (integrity hash) karşılaştırması n8n workflow\'undaki mevcut adımda (baseline_integrity_hash vs güncel dist.integrity) zaten yapılıyor. Bu servis sadece FARKLI iki versiyon arasında kod diff\'i üretir.'
      });
    }

    // --- DURUM C: Normal diff (iki farklı versiyon) ---
    const fromDir = path.join(tempDir, `from-${from_version}`);
    const toDir = path.join(tempDir, `to-${to_version}`);

    await Promise.all([
      pacote.extract(`${pkgName}@${from_version}`, fromDir),
      pacote.extract(`${pkgName}@${to_version}`, toDir)
    ]);

    enforceExtractedPackageLimits(fromDir, `${pkgName}@${from_version}`);
    enforceExtractedPackageLimits(toDir, `${pkgName}@${to_version}`);

    const fromFiles = listFilesRecursive(fromDir);
    const toFiles = listFilesRecursive(toDir);

    const fromSet = new Set(fromFiles);
    const toSet = new Set(toFiles);

    const filesAdded = toFiles.filter(f => !fromSet.has(f));
    const filesRemoved = fromFiles.filter(f => !toSet.has(f));
    const filesCommonAll = toFiles.filter(f => fromSet.has(f));

    // Eklenen/silinen dosyaları da binary/metin olarak ayır (binary eklenmesi yüksek risk sinyali,
    // text dosyalarda da artık suspicious-string taraması yapılıyor)
    const { textFiles: textAdded, binaryFiles: binaryAdded } = classifyFiles(toDir, filesAdded);
    const { textFiles: textRemoved, binaryFiles: binaryRemoved } = classifyFiles(fromDir, filesRemoved);

    const filesChanged = [];
    const largeFilesChanged = []; // boyut sınırını aşan dosyalar (tam diff üretilmez ve/veya hiç okunmaz)

    for (const relPath of filesCommonAll) {
      const fromFilePath = path.join(fromDir, relPath);
      const toFilePath = path.join(toDir, relPath);

      // ✅ İçerik kontrolü gerektiği için tam path şart; to/from farklı bir dosya olabilir
      // diye ikisini de kontrol edip herhangi biri "text" derse text kabul ediyoruz
      // (ör. yeni versiyonda text, eski versiyonda binary sanılan bir dosyayı kaçırmamak için)
      if (!isProbablyText(toFilePath) && !isProbablyText(fromFilePath)) continue;

      const fromStat = fs.statSync(fromFilePath);
      const toStat = fs.statSync(toFilePath);

      // DoS Limits: MAX_SINGLE_FILE_SCAN_BYTES üzerindeki dosyaların içeriğini hiç belleğe okumuyoruz,
      // sadece hash karşılaştırması yapıyoruz. Büyük dosyaları okuyup regex taramak başlı başına
      // bir DoS vektörü olabilir.
      if (fromStat.size > MAX_SINGLE_FILE_SCAN_BYTES || toStat.size > MAX_SINGLE_FILE_SCAN_BYTES) {
        const fromHash = getFileHash(fromFilePath);
        const toHash = getFileHash(toFilePath);

       if (fromHash !== toHash) {
          largeFilesChanged.push({
          path: relPath,
          size_before_bytes: fromStat.size,
          size_after_bytes: toStat.size,
          sha256_before: fromHash,
          sha256_after: toHash,
          scan_skipped: true,
          note: 'Dosya çok büyük olduğu için içerik diff analizi yapılmadı, hash değişimi tespit edildi'
    });
  }

   continue;
}
    
      const fromHash = getFileHash(fromFilePath);
      const toHash = getFileHash(toFilePath);

      if (fromHash === toHash) {
        continue;
      }

      const fromContent = fs.readFileSync(fromFilePath, 'utf8');
      const toContent = fs.readFileSync(toFilePath, 'utf8');

      // GÜVENLİK TARAMASI: MAX_DIFF_CHARS sınırından BAĞIMSIZ olarak her zaman çalışır.
      // Regex taraması, tam unified diff üretiminden çok daha ucuz bir işlemdir.
      // Bu sayede "diff sınırının üstündeki dosyaya zararlı kod gizleme" ile
      // taramayı bypass etmek mümkün olmuyor (MAX_SINGLE_FILE_SCAN_BYTES'a kadar).
      const suspiciousInNewContent = scanTextContentForSuspiciousPatterns(toContent);

      const patch = createTwoFilesPatch(
        relPath, relPath,
        fromContent, toContent,
        `v${from_version}`, `v${to_version}`
      );
      if (patch.length <= MAX_INLINE_DIFF_CHARS) {

          filesChanged.push({
          path: relPath,
          diff_available: true,
          diff_inline: true,
          diff: patch,
          suspicious_strings_found: suspiciousInNewContent
       });

      } else {
        try {
          const stored = saveDiffToStorage(patch);
          filesChanged.push({
            path: relPath,
            diff_available: true,
            diff_inline: false,
            diff_id: stored.id,
            diff_size_chars: patch.length,
            message: 'Diff boyutu büyük olduğu için storage içine kaydedildi',
            suspicious_strings_found: suspiciousInNewContent
          });
        } catch (storageErr) {
          // ✅ Storage'a yazılamasa bile bu TEK dosya hatalı sayılır, tüm istek düşmez.
          // Güvenlik taraması (suspiciousInNewContent) zaten yapıldı, o bilgi kaybolmaz.
          console.error(`Diff storage hatası (${relPath}):`, storageErr);
          largeFilesChanged.push({
            path: relPath,
            diff_size_chars: patch.length,
            note: 'Diff üretildi ancak storage limiti/hatası nedeniyle kaydedilemedi; sadece güvenlik taraması sonucu mevcut',
            suspicious_strings_found: suspiciousInNewContent
          });
        }
      }
      }

    const packageJsonAnalysis = analyzePackageJsonChange(fromDir, toDir);
    const binaryFilesChanged = compareCommonBinaryFiles(fromDir, toDir, filesCommonAll, getFileHash);
    
    const securitySignals = collectSecuritySignals({
      textFiles: [
        ...filesChanged,
        ...textAdded,
        ...textRemoved
      ],
      binaryFiles: [
        ...binaryAdded,
        ...binaryRemoved,
        ...binaryFilesChanged
      ],
      largeFiles: largeFilesChanged
    });

    res.json({
      mode: 'diff',
      package: pkgName,
      from_version,
      to_version,
      summary: {
        files_added_count: filesAdded.length,
        files_removed_count: filesRemoved.length,
        files_changed_count: filesChanged.length,
        large_files_changed_count: largeFilesChanged.length,
        binary_files_added_count: binaryAdded.length,
        binary_files_removed_count: binaryRemoved.length,
        binary_files_changed_count: binaryFilesChanged.length
      },
      security_signals: securitySignals,
      files_added: filesAdded,
      files_removed: filesRemoved,
      files_changed: filesChanged,
      large_files_changed: largeFilesChanged,
      text_files_added: textAdded,
      text_files_removed: textRemoved,
      binary_files_added: binaryAdded,
      binary_files_removed: binaryRemoved,
      binary_files_changed: binaryFilesChanged,
      package_json_analysis: packageJsonAnalysis
    });
    
  } catch (err) {
    const classified = classifyError(err);
   const statusCode = classified.error_type === 'limit_exceeded' ? 413 : 422;
    res.status(statusCode).json(classified);
  } finally {
    activeDiffRequests--;
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  }
});

// Genel/beklenmeyen Express hatalarını da (ör. malformed JSON body) sanitize edilmiş şekilde döndür
app.use((err, req, res, next) => {
  console.error('Express seviyesinde beklenmeyen hata:', err);
  res.status(400).json({
    error_type: 'invalid_request',
    message: 'İstek işlenemedi (geçersiz format)'
  });
});

const PORT = Number(process.env.PORT) || 3000;

app.listen(PORT, () => {
  console.log(`Servis çalışıyor: http://localhost:${PORT}`);
});