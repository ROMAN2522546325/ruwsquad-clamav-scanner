import { createClient } from '@supabase/supabase-js';
import { createHash } from 'node:crypto';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const SUPABASE_URL = process.env.SUPABASE_URL;
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const BUCKET = process.env.SUPABASE_STORAGE_BUCKET || 'ruwsquad-files';
const BATCH_SIZE = Math.max(1, Math.min(25, Number(process.env.SCAN_BATCH_SIZE) || 10));
const MAX_DOWNLOAD_BYTES = Math.max(1, Number(process.env.MAX_DOWNLOAD_BYTES) || 52_428_800);
const MAX_ASSET_BYTES = Math.max(1, Number(process.env.MAX_ASSET_BYTES) || 12_582_912);
const MAX_TOTAL_SCAN_BYTES = Math.max(MAX_DOWNLOAD_BYTES, Number(process.env.MAX_TOTAL_SCAN_BYTES) || 83_886_080);
const MAX_ATTEMPTS = Math.max(1, Math.min(5, Number(process.env.MAX_SCAN_ATTEMPTS) || 3));

if (!SUPABASE_URL || !SERVICE_KEY) {
  throw new Error('Нужно добавить SUPABASE_URL и SUPABASE_SERVICE_ROLE_KEY в GitHub Actions Secrets.');
}

const supabase = createClient(SUPABASE_URL, SERVICE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false }
});

function shortMessage(value, max = 1200) {
  return String(value || '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, ' ').slice(0, max);
}

function updateResource(id, values) {
  return supabase.from('resources').update(values).eq('id', id);
}

function safeFilename(value, fallback) {
  const base = path.basename(String(value || fallback || 'resource.bin'))
    .replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 90);
  return base || fallback || 'resource.bin';
}

function runClamScan(directoryPath) {
  const args = [
    '--infected', '--stdout',
    '--alert-encrypted=yes', '--alert-exceeds-max=yes',
    '--max-filesize=50M', '--max-scansize=350M',
    '--max-files=10000', '--max-recursion=15',
    '--max-scantime=240000', '--scan-archive=yes',
    directoryPath
  ];
  const result = spawnSync('clamscan', args, {
    encoding: 'utf8', timeout: 300_000, maxBuffer: 8 * 1024 * 1024
  });
  const output = `${result.stdout || ''}\n${result.stderr || ''}`.trim();
  if (result.error) throw result.error;
  if (result.status === 2 || result.status === null) {
    throw new Error(`ClamAV завершился с ошибкой (${result.status ?? 'timeout'}): ${shortMessage(output, 900)}`);
  }
  const detections = output.split(/\r?\n/).filter(line => /FOUND\s*$/.test(line));
  if (detections.length) {
    const limited = detections.some(line => /Heuristics\.(Limits\.Exceeded|Encrypted)/i.test(line));
    if (limited) return {
      status: 'needs_review',
      summary: `ClamAV не смог полностью проверить один из файлов: зашифрованный архив или превышен безопасный лимит. ${shortMessage(detections.join(' | '), 700)}`
    };
    return { status: 'infected', summary: `Обнаружена сигнатура ClamAV: ${shortMessage(detections.join(' | '), 800)}` };
  }
  if (result.status === 0) return {
    status: 'clean',
    summary: 'ClamAV проверил основной файл, обложку и скриншоты: известных сигнатур не обнаружено. Это не абсолютная гарантия безопасности.'
  };
  throw new Error(`ClamAV вернул неизвестный код ${result.status}: ${shortMessage(output, 900)}`);
}

async function downloadToFile(storagePath, outputPath, perFileLimit, label) {
  const { data: blob, error } = await supabase.storage.from(BUCKET).download(storagePath);
  if (error) throw new Error(`Не удалось скачать ${label} из приватного Storage: ${error.message}`);
  if (!blob) throw new Error(`Storage вернул пустой файл: ${label}`);
  const buffer = Buffer.from(await blob.arrayBuffer());
  if (!buffer.length) throw new Error(`Файл пустой: ${label}`);
  if (buffer.length > perFileLimit) {
    const error = new Error(`${label}: фактический размер превышает лимит ${perFileLimit} байт.`);
    error.code = 'FILE_TOO_LARGE';
    throw error;
  }
  await writeFile(outputPath, buffer, { flag: 'wx', mode: 0o600 });
  return { bytes: buffer.length, buffer };
}

async function setNeedsReview(resource, engineVersion, summary) {
  const { data, error } = await updateResource(resource.id, {
    scan_status: 'needs_review', scan_engine: `ClamAV ${engineVersion}`,
    scan_summary: shortMessage(summary), scanned_at: new Date().toISOString()
  }).eq('scan_status', 'scanning').select('id').maybeSingle();
  if (error) throw error;
  if (!data) {
    console.log(`${resource.id}: файл изменился во время проверки; новая версия осталась в очереди.`);
    return 'skipped';
  }
  console.log(`${resource.id} -> needs_review: ${shortMessage(summary, 350)}`);
  return 'needs_review';
}

async function processResource(resource, engineVersion) {
  const attempt = (Number(resource.scan_attempts) || 0) + 1;
  const now = new Date().toISOString();
  const { data: lockData, error: lockError } = await updateResource(resource.id, {
    scan_status: 'scanning', scan_attempts: attempt,
    scan_engine: `ClamAV ${engineVersion}`,
    scan_summary: `Проверка выполняется. Попытка ${attempt}/${MAX_ATTEMPTS}.`, scanned_at: now
  }).eq('scan_status', resource.scan_status).select('id').maybeSingle();
  if (lockError) throw lockError;
  if (!lockData) {
    console.log(`Пропуск ${resource.id}: другой запуск уже забрал файл в проверку.`);
    return 'skipped';
  }

  let tempDir;
  try {
    if (!resource.file_path || resource.file_path.startsWith('deleted/')) {
      return await setNeedsReview(resource, engineVersion, 'У записи отсутствует исходный файл. Требуется ручная проверка.');
    }
    if (Number(resource.size_bytes) > MAX_DOWNLOAD_BYTES) {
      return await setNeedsReview(resource, engineVersion, `Основной файл превышает лимит автоматической проверки (${MAX_DOWNLOAD_BYTES} байт).`);
    }

    tempDir = await mkdtemp(path.join(tmpdir(), 'ruwsquad-scan-'));
    const paths = [
      { storagePath: resource.file_path, name: safeFilename(resource.filename, 'resource.bin'), limit: MAX_DOWNLOAD_BYTES, label: 'основной файл', verifyHash: true },
      ...(resource.cover_path ? [{ storagePath: resource.cover_path, name: `cover-${safeFilename(path.basename(resource.cover_path), 'cover.img')}`, limit: MAX_ASSET_BYTES, label: 'обложка' }] : []),
      ...((Array.isArray(resource.gallery_paths) ? resource.gallery_paths : []).map((storagePath, index) => ({
        storagePath, name: `gallery-${index + 1}-${safeFilename(path.basename(storagePath), 'image.img')}`,
        limit: MAX_ASSET_BYTES, label: `скриншот ${index + 1}`
      })))
    ];
    const unique = [...new Map(paths.filter(item => typeof item.storagePath === 'string' && item.storagePath && !item.storagePath.startsWith('deleted/'))
      .map(item => [item.storagePath, item])).values()];
    if (!unique.length) return await setNeedsReview(resource, engineVersion, 'Нет файлов для проверки.');

    let totalBytes = 0;
    for (let index = 0; index < unique.length; index++) {
      const item = unique[index];
      const destination = path.join(tempDir, `${String(index).padStart(2, '0')}-${item.name}`);
      const { bytes, buffer } = await downloadToFile(item.storagePath, destination, item.limit, item.label);
      totalBytes += bytes;
      if (totalBytes > MAX_TOTAL_SCAN_BYTES) {
        return await setNeedsReview(resource, engineVersion, `Общий размер файлов для проверки превышает лимит ${MAX_TOTAL_SCAN_BYTES} байт.`);
      }
      if (item.verifyHash && resource.sha256) {
        const actualHash = createHash('sha256').update(buffer).digest('hex');
        if (actualHash.toLowerCase() !== String(resource.sha256).toLowerCase()) {
          return await setNeedsReview(resource, engineVersion, 'SHA-256 основного файла не совпадает с сохранённым хешем. Требуется ручная проверка.');
        }
      }
    }

    const result = runClamScan(tempDir);
    const patch = {
      scan_status: result.status,
      scan_engine: `ClamAV ${engineVersion}`,
      scan_summary: shortMessage(`${result.summary} Проверено файлов: ${unique.length}.`),
      scanned_at: new Date().toISOString()
    };
    if (result.status === 'infected') {
      patch.status = 'rejected';
      patch.moderation_note = `Автоматически отклонён: ClamAV обнаружил вредоносную сигнатуру. ${shortMessage(result.summary, 450)}`;
    }
    // Only write the result if this exact scanning lease is still active.
    // A DB trigger resets scan_status to queued when any scanned file path/hash changes.
    const { data: savedResult, error: updateError } = await updateResource(resource.id, patch)
      .eq('scan_status', 'scanning').select('id').maybeSingle();
    if (updateError) throw updateError;
    if (!savedResult) {
      console.log(`${resource.id}: ресурс изменился во время проверки; результат старой версии отброшен, новая версия остаётся в очереди.`);
      return 'skipped';
    }
    console.log(`${resource.id} [${resource.status}] -> ${result.status}; files=${unique.length}; attempt=${attempt}; ${resource.filename}`);
    return result.status;
  } catch (error) {
    const summary = shortMessage(error?.message || error, 900);
    const finalStatus = error?.code === 'FILE_TOO_LARGE' || attempt >= MAX_ATTEMPTS ? 'needs_review' : 'error';
    const message = finalStatus === 'needs_review'
      ? `Автоматические попытки проверки исчерпаны или нарушен лимит: ${summary}. Требуется ручная проверка.`
      : `Проверка не завершена; будет повторена автоматически: ${summary}`;
    const { data: savedError, error: saveError } = await updateResource(resource.id, {
      scan_status: finalStatus, scan_engine: `ClamAV ${engineVersion}`,
      scan_summary: message, scanned_at: new Date().toISOString()
    }).eq('scan_status', 'scanning').select('id').maybeSingle();
    if (saveError) {
      console.error('Не удалось сохранить результат ошибки сканирования:', saveError.message);
      throw saveError;
    }
    if (!savedError) {
      console.log(`${resource.id}: исходный файл изменился во время проверки; ошибка старой версии не применена.`);
      return 'skipped';
    }
    console.error(`Scan failed for ${resource.id} (attempt ${attempt}/${MAX_ATTEMPTS}): ${summary}`);
    return finalStatus;
  } finally {
    if (tempDir) await rm(tempDir, { recursive: true, force: true });
  }
}

async function main() {
  const versionResult = spawnSync('clamscan', ['--version'], { encoding: 'utf8', timeout: 10_000 });
  if (versionResult.status !== 0) throw new Error('ClamAV не установлен на runner.');
  const engineVersion = shortMessage(versionResult.stdout || 'ClamAV', 100);

  // Recover abandoned scans. The moderator can requeue these explicitly.
  const staleBefore = new Date(Date.now() - 45 * 60 * 1000).toISOString();
  const { error: recoveryError } = await supabase.from('resources').update({
    scan_status: 'needs_review',
    scan_summary: 'Предыдущий запуск ClamAV прервался или превысил время ожидания. Требуется повторная проверка модератором.',
    scanned_at: new Date().toISOString()
  }).eq('scan_status', 'scanning').or(`scanned_at.is.null,scanned_at.lt.${staleBefore}`).is('files_deleted_at', null);
  if (recoveryError) throw recoveryError;

  const { data: resources, error } = await supabase.from('resources')
    .select('id,owner_id,status,title,filename,file_path,cover_path,gallery_paths,size_bytes,sha256,scan_status,scan_attempts,files_deleted_at')
    .in('status', ['pending', 'published'])
    .in('scan_status', ['queued', 'error'])
    .lt('scan_attempts', MAX_ATTEMPTS)
    .is('files_deleted_at', null)
    .order('created_at', { ascending: true })
    .limit(BATCH_SIZE);
  if (error) throw error;

  if (!resources?.length) {
    console.log('Очередь RuWSquad пуста: нет файлов, ожидающих сканирования.');
    return;
  }

  console.log(`ClamAV ${engineVersion}; файлов в партии: ${resources.length}; максимальный размер файла: ${MAX_DOWNLOAD_BYTES} bytes.`);
  const totals = { clean: 0, infected: 0, needs_review: 0, error: 0, skipped: 0 };
  for (const resource of resources) {
    console.log(`Проверяется: ${shortMessage(resource.title, 120)} (${shortMessage(resource.filename, 120)})`);
    const status = await processResource(resource, engineVersion);
    if (Object.hasOwn(totals, status)) totals[status]++;
  }
  console.log(`ИТОГ ПАРТИИ: clean=${totals.clean}; infected=${totals.infected}; needs_review=${totals.needs_review}; error=${totals.error}; skipped=${totals.skipped}.`);
}

main().catch(error => {
  console.error('RuWSquad ClamAV workflow failed:', error);
  process.exitCode = 1;
});
