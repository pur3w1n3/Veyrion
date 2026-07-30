/**
 * 展示层 datetime helper。API wire 格式保持 ISO-8601 UTC；
 * UI 转换为浏览器本地时区以便阅读。
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
 * 将 API 时间戳格式化为 UI 展示。
 * - ZH（默认）：本地时间 `yyyy年MM月dd日 HH:mm:ss`
 * - EN：本地时间 `yyyy-MM-dd HH:mm:ss`
 * 无效或空输入原样返回（或空字符串）。
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
