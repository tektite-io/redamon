export function timestampSlug(): string {
  return new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-')
}

export function downloadBlob(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

export function flattenCellValue(raw: unknown): string {
  if (raw == null) return ''
  if (Array.isArray(raw)) {
    return raw
      .map(v => (typeof v === 'object' && v !== null ? safeStringify(v) : String(v)))
      .join(', ')
  }
  if (typeof raw === 'object') return safeStringify(raw)
  return String(raw)
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

export function escapeMarkdownCell(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ')
}

const CSV_BINARY_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g

function escapeCsvCell(value: unknown): string {
  const flat = flattenCellValue(value).replace(CSV_BINARY_CHARS, '')
  if (/[",\r\n]/.test(flat)) return `"${flat.replace(/"/g, '""')}"`
  return flat
}

/**
 * Build a CSV string for the given headers + rows.
 *
 * - RFC 4180 quoting: cells containing comma / quote / CR / LF are quoted,
 *   internal quotes are doubled.
 * - Streams row-by-row into an array then joins once -- avoids the O(n²)
 *   string concatenation that crashes browsers on huge exports.
 * - Adds a UTF-8 BOM so Excel auto-detects encoding.
 * - CRLF line endings (Excel-friendly).
 */
export function toCsv(headers: string[], rows: Array<Record<string, unknown>>): string {
  const lines: string[] = [headers.map(h => escapeCsvCell(h)).join(',')]
  for (const row of rows) {
    lines.push(headers.map(h => escapeCsvCell(row[h])).join(','))
  }
  return '\uFEFF' + lines.join('\r\n') + '\r\n'
}

export const CSV_MIME = 'text/csv;charset=utf-8'
