import type { TableRow } from '../hooks/useTableData'
import {
  timestampSlug,
  downloadBlob,
  flattenCellValue,
  escapeMarkdownCell,
  toCsv,
  CSV_MIME,
} from './exportHelpers'

interface NodeExportRow {
  Type: string
  Name: string
  ID: string
  'Connections In': number
  'Connections Out': number
  'Connections In Detail': string
  'Connections Out Detail': string
  'Level 2': number
  'Level 2 Detail': string
  'Level 3': number
  'Level 3 Detail': string
  [extra: string]: unknown
}

const FIXED_HEADERS: (keyof NodeExportRow)[] = [
  'Type',
  'Name',
  'ID',
  'Connections In',
  'Connections Out',
  'Connections In Detail',
  'Connections Out Detail',
  'Level 2',
  'Level 2 Detail',
  'Level 3',
  'Level 3 Detail',
]

function buildExportRows(rows: TableRow[]): NodeExportRow[] {
  return rows.map(row => {
    const base: NodeExportRow = {
      Type: row.node.type,
      Name: row.node.name,
      ID: row.node.id,
      'Connections In': row.connectionsIn.length,
      'Connections Out': row.connectionsOut.length,
      'Connections In Detail': row.connectionsIn
        .map(c => `${c.nodeType}: ${c.nodeName} (${c.relationType})`)
        .join('; '),
      'Connections Out Detail': row.connectionsOut
        .map(c => `${c.nodeType}: ${c.nodeName} (${c.relationType})`)
        .join('; '),
      'Level 2': row.getLevel2().length,
      'Level 2 Detail': row.getLevel2()
        .map(c => `${c.nodeType}: ${c.nodeName}`)
        .join('; '),
      'Level 3': row.getLevel3().length,
      'Level 3 Detail': row.getLevel3()
        .map(c => `${c.nodeType}: ${c.nodeName}`)
        .join('; '),
    }

    for (const [key, value] of Object.entries(row.node.properties)) {
      if (key === 'project_id' || key === 'user_id') continue
      base[key] = value
    }

    return base
  })
}

function collectHeaders(rows: NodeExportRow[]): string[] {
  const dynamic = new Set<string>()
  for (const r of rows) {
    for (const k of Object.keys(r)) {
      if (!FIXED_HEADERS.includes(k as keyof NodeExportRow)) dynamic.add(k)
    }
  }
  return [...(FIXED_HEADERS as string[]), ...Array.from(dynamic).sort()]
}

export function exportToCsv(rows: TableRow[], filename?: string) {
  const built = buildExportRows(rows)
  const headers = collectHeaders(built)
  const csv = toCsv(headers, built as unknown as Array<Record<string, unknown>>)
  const slug = filename || 'redamon-data'
  downloadBlob(csv, `${slug}-${timestampSlug()}.csv`, CSV_MIME)
}

export function exportToJson(rows: TableRow[], filename?: string) {
  const built = buildExportRows(rows)
  const slug = filename || 'redamon-data'
  downloadBlob(
    JSON.stringify(built, null, 2),
    `${slug}-${timestampSlug()}.json`,
    'application/json;charset=utf-8',
  )
}

export function exportToMarkdown(rows: TableRow[], filename?: string) {
  const built = buildExportRows(rows)
  const slug = filename || 'redamon-data'

  const headerSet = new Set<string>()
  built.forEach(row => Object.keys(row).forEach(k => headerSet.add(k)))
  const headers = Array.from(headerSet)

  const headerLine = `| ${headers.join(' | ')} |`
  const sepLine = `| ${headers.map(() => '---').join(' | ')} |`
  const dataLines = built.map(row =>
    `| ${headers.map(h => escapeMarkdownCell(flattenCellValue(row[h]))).join(' | ')} |`,
  )

  const md = `# Nodes Export\n\nGenerated: ${new Date().toISOString()}\nRows: ${built.length}\n\n${headerLine}\n${sepLine}\n${dataLines.join('\n')}\n`
  downloadBlob(md, `${slug}-${timestampSlug()}.md`, 'text/markdown;charset=utf-8')
}
