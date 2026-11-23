import { createClient } from '@supabase/supabase-js';
import { createHash } from 'node:crypto';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const SUPABASE_URL = process.env.SUPABASE_URL;
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const BUCKET = process.env.SUPABASE_STORAGE_BUCKET || 'ruwsquad-files';
const BATCH_SIZE = Math.max(1, Math.min(25, Number(process.env.SCAN_BATCH_SIZE) || 12));
const MAX_DOWNLOAD_BYTES = Math.max(1, Number(process.env.MAX_DOWNLOAD_BYTES) || 52_428_800);

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

function runClamScan(filePath) {
  const args = [
    '--infected',
    '--stdout',
    '--alert-encrypted=yes',
    '--alert-exceeds-max=yes',
    '--max-filesize=100M',
    '--max-scansize=300M',
    '--max-files=10000',
    '--max-recursion=15',
    '--max-scantime=180000',
    '--scan-archive=yes',
    filePath
  ];
  const result = spawnSync('clamscan', args, {
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 8 * 1024 * 1024
  });
  const output = `${result.stdout || ''}\n${result.stderr || ''}`.trim();
  if (result.error) throw result.error;
  if (result.status === 2 || result.status === null) {
    throw new Error(`ClamAV завершился с ошибкой (${result.status ?? 'timeout'}): ${shortMessage(output, 900)}`);
  }

  const detections = output.split(/\r?\n/).filter(line => /FOUND\s*$/.test(line));
  if (detections.length) {
    const limitOrEncrypted = detections.some(line => /Heuristics\.(Limits\.Exceeded|Encrypted)/i.test(line));
    if (limitOrEncrypted) {
      return { status: 'needs_review', summary: `ClamAV остановил полный анализ: зашифрованный архив или превышен безопасный лимит. ${shortMessage(detections.join(' | '), 800)}` };
    }
    return { status: 'infected', summary: `Обнаружена сигнатура ClamAV: ${shortMessage(detections.join(' | '), 800)}` };
  }
  if (result.status === 0) {
    return { status: 'clean', summary: 'ClamAV завершил проверку: сигнатур вредоносного ПО не обнаружено. Это не является абсолютной гарантией безопасности.' };
  }
  throw new Error(`ClamAV вернул неизвестный код ${result.status}: ${shortMessage(output, 900)}`);
}

async function processResource(resource, engineVersion) {
  const now = new Date().toISOString();
  const { data: lockData, error: lockError } = await updateResource(resource.id, {
    scan_status: 'scanning',
    scan_engine: `ClamAV ${engineVersion}`,
    scan_summary: 'Файл получен сканером и проверяется.',
    scanned_at: now
  }).eq('scan_status', resource.scan_status).select('id').maybeSingle();
  if (lockError) throw lockError;
  if (!lockData) {
    console.log(`Пропуск ${resource.id}: другой запуск уже забрал файл в проверку.`);
    return;
  }

  let tempDir;
  try {
    if (!resource.file_path || resource.file_path.startsWith('deleted/')) {
      await updateResource(resource.id, {
        scan_status: 'error', scan_engine: `ClamAV ${engineVersion}`,
        scan_summary: 'У записи отсутствует путь к исходному файлу.', scanned_at: now
      });
      return;
    }

    if (Number(resource.size_bytes) > MAX_DOWNLOAD_BYTES) {
      await updateResource(resource.id, {
        scan_status: 'needs_review', scan_engine: `ClamAV ${engineVersion}`,
        scan_summary: `Файл превышает разрешённый размер для автоматической проверки (${MAX_DOWNLOAD_BYTES} байт).`, scanned_at: now
      });
      return;
    }

    const { data: blob, error: downloadError } = await supabase.storage.from(BUCKET).download(resource.file_path);
    if (downloadError) throw new Error(`Не удалось скачать файл из приватного Storage: ${downloadError.message}`);
    if (!blob) throw new Error('Storage вернул пустой файл.');
    const buffer = Buffer.from(await blob.arrayBuffer());
    if (!buffer.length) throw new Error('Загруженный файл пуст.');
    if (buffer.length > MAX_DOWNLOAD_BYTES) {
      await updateResource(resource.id, {
        scan_status: 'needs_review', scan_engine: `ClamAV ${engineVersion}`,
        scan_summary: 'Фактический размер файла больше допустимого лимита сканера.', scanned_at: now
      });
      return;
    }

    const actualHash = createHash('sha256').update(buffer).digest('hex');
    if (resource.sha256 && actualHash.toLowerCase() !== String(resource.sha256).toLowerCase()) {
      await updateResource(resource.id, {
        scan_status: 'needs_review', scan_engine: `ClamAV ${engineVersion}`,
        scan_summary: 'SHA-256 файла не совпадает с хешем, записанным при загрузке. Требуется ручная проверка.', scanned_at: now
      });
      return;
    }

    tempDir = await mkdtemp(path.join(tmpdir(), 'ruwsquad-scan-'));
    const safeBase = path.basename(resource.filename || 'resource.bin').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 90) || 'resource.bin';
    const localPath = path.join(tempDir, `${resource.id}-${safeBase}`);
    await writeFile(localPath, buffer, { flag: 'wx', mode: 0o600 });

    const result = runClamScan(localPath);
    const patch = {
      scan_status: result.status,
      scan_engine: `ClamAV ${engineVersion}`,
      scan_summary: shortMessage(result.summary),
      scanned_at: new Date().toISOString()
    };
    if (result.status === 'infected') {
      patch.status = 'rejected';
      patch.moderation_note = 'Ресурс автоматически отклонён: ClamAV обнаружил вредоносную сигнатуру. ' + shortMessage(result.summary, 500);
    }
    const { error: updateError } = await updateResource(resource.id, patch);
    if (updateError) throw updateError;
    console.log(`${resource.id} [${resource.status}] -> ${result.status}: ${resource.filename}`);
  } catch (error) {
    const summary = shortMessage(error?.message || error, 1000);
    const { error: saveError } = await updateResource(resource.id, {
      scan_status: 'error', scan_engine: `ClamAV ${engineVersion}`,
      scan_summary: `Проверка не завершена: ${summary}`, scanned_at: new Date().toISOString()
    });
    if (saveError) console.error('Не удалось сохранить ошибку сканирования:', saveError.message);
    console.error(`Scan failed for ${resource.id}: ${summary}`);
  } finally {
    if (tempDir) await rm(tempDir, { recursive: true, force: true });
  }
}

async function main() {
  const versionResult = spawnSync('clamscan', ['--version'], { encoding: 'utf8', timeout: 10_000 });
  if (versionResult.status !== 0) throw new Error('ClamAV не установлен на runner.');
  const engineVersion = shortMessage(versionResult.stdout || 'ClamAV', 100);

  // Recover rows left in `scanning` by a cancelled/expired runner. Active scans
  // refresh scanned_at when claiming a row; a 45-minute lease is safely longer
  // than one file's scan timeout and shorter than the hourly schedule.
  const staleBefore = new Date(Date.now() - 45 * 60 * 1000).toISOString();
  const { error: recoveryError } = await supabase
    .from('resources')
    .update({
      scan_status: 'error',
      scan_summary: 'Предыдущий запуск ClamAV прервался до завершения. Нужен повторный запуск.',
      scanned_at: new Date().toISOString()
    })
    .eq('scan_status', 'scanning')
    .or(`scanned_at.is.null,scanned_at.lt.${staleBefore}`)
    .is('files_deleted_at', null);
  if (recoveryError) throw recoveryError;

  const { data: resources, error } = await supabase
    .from('resources')
    .select('id,status,title,filename,file_path,size_bytes,sha256,scan_status,files_deleted_at')
    .in('status', ['pending', 'published'])
    .in('scan_status', ['queued', 'error'])
    .is('files_deleted_at', null)
    .order('created_at', { ascending: true })
    .limit(BATCH_SIZE);
  if (error) throw error;

  if (!resources?.length) {
    console.log('Очередь RuWSquad пуста: нет файлов, ожидающих сканирования.');
    return;
  }

  console.log(`ClamAV ${engineVersion}; файлов в этой партии: ${resources.length}`);
  for (const resource of resources) {
    console.log(`Проверяется: ${resource.title} (${resource.filename})`);
    await processResource(resource, engineVersion);
  }
}

main().catch(error => {
  console.error('RuWSquad ClamAV workflow failed:', error);
  process.exitCode = 1;
});
