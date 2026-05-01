import {
  timestampSlug,
  downloadBlob,
  flattenCellValue,
  escapeMarkdownCell,
  toCsv,
  CSV_MIME,
} from '../../utils/exportHelpers'

export interface RedZoneExportColumn {
  key: string
  header: string
}

export interface RedZoneExportConfig {
  rows: object[]
  sheetName: string
  fileSlug: string
  columns: RedZoneExportColumn[]
}

function buildRowDict(rows: object[], columns: RedZoneExportColumn[]): Record<string, unknown>[] {
  return rows.map(row => {
    const out: Record<string, unknown> = {}
    for (const col of columns) {
      out[col.header] = (row as Record<string, unknown>)[col.key]
    }
    return out
  })
}

export function exportRedZoneCsv<T extends object>(
  rows: T[],
  _sheetName: string,
  columns: RedZoneExportColumn[],
  fileSlug: string,
) {
  const headers = columns.map(c => c.header)
  const data = buildRowDict(rows, columns)
  const csv = toCsv(headers, data)
  downloadBlob(csv, `${fileSlug}-${timestampSlug()}.csv`, CSV_MIME)
}

export function exportRedZoneJson<T extends object>(
  rows: T[],
  _sheetName: string,
  columns: RedZoneExportColumn[],
  fileSlug: string,
) {
  const data = buildRowDict(rows, columns).map(row => {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(row)) out[k] = v ?? null
    return out
  })
  downloadBlob(
    JSON.stringify(data, null, 2),
    `${fileSlug}-${timestampSlug()}.json`,
    'application/json;charset=utf-8',
  )
}

export function exportRedZoneMarkdown<T extends object>(
  rows: T[],
  sheetName: string,
  columns: RedZoneExportColumn[],
  fileSlug: string,
) {
  const headers = columns.map(c => c.header)
  const headerLine = `| ${headers.join(' | ')} |`
  const sepLine = `| ${headers.map(() => '---').join(' | ')} |`
  const dataLines = rows.map(row =>
    `| ${columns
      .map(col => escapeMarkdownCell(flattenCellValue((row as Record<string, unknown>)[col.key])))
      .join(' | ')} |`,
  )

  const md = `# ${sheetName}\n\nGenerated: ${new Date().toISOString()}\nRows: ${rows.length}\n\n${headerLine}\n${sepLine}\n${dataLines.join('\n')}\n`
  downloadBlob(md, `${fileSlug}-${timestampSlug()}.md`, 'text/markdown;charset=utf-8')
}

export function runRedZoneExport(
  format: 'csv' | 'json' | 'md',
  config: RedZoneExportConfig,
) {
  if (format === 'csv') return exportRedZoneCsv(config.rows, config.sheetName, config.columns, config.fileSlug)
  if (format === 'json') return exportRedZoneJson(config.rows, config.sheetName, config.columns, config.fileSlug)
  return exportRedZoneMarkdown(config.rows, config.sheetName, config.columns, config.fileSlug)
}
