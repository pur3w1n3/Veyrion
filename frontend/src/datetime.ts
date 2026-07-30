/**
 * Display-layer datetime helpers. API wire format stays ISO-8601 UTC;
 * UI converts to the browser's local timezone for readable labels.
 */

const pad2 = (value: number): string => String(value).padStart(2, '0')

const parseInstant = (value: string): Date | undefined => {
  const trimmed = value.trim()
  if (!trimmed) return undefined
  const parsed = Date.parse(trimmed)
  if (Number.isNaN(parsed)) return undefined
  return new Date(parsed)
}

/**
 * Format an API timestamp for UI display.
 * - ZH (default): `yyyy年MM月dd日 HH:mm:ss` in local time
 * - EN: `yyyy-MM-dd HH:mm:ss` in local time
 * Invalid or empty input is returned unchanged (or empty string).
 */
export function formatDisplayDateTime(
  value: string | undefined | null,
  options: { english?: boolean } = {}
): string {
  if (value == null) return ''
  const instant = parseInstant(value)
  if (!instant) return value

  const year = instant.getFullYear()
  const month = pad2(instant.getMonth() + 1)
  const day = pad2(instant.getDate())
  const hour = pad2(instant.getHours())
  const minute = pad2(instant.getMinutes())
  const second = pad2(instant.getSeconds())

  if (options.english) {
    return `${year}-${month}-${day} ${hour}:${minute}:${second}`
  }
  return `${year}年${month}月${day}日 ${hour}:${minute}:${second}`
}
