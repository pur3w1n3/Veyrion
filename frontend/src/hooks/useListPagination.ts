import { useEffect, useMemo, useState } from 'react'

export const LIST_PAGE_SIZE_OPTIONS = [20, 50] as const
export const DEFAULT_LIST_PAGE_SIZE = 20

export type ListPaginationState<T> = {
  page: number
  pageSize: number
  setPageSize: (size: number) => void
  total: number
  totalPages: number
  rangeStart: number
  rangeEnd: number
  pageItems: T[]
  setPage: (page: number | ((current: number) => number)) => void
  goPrev: () => void
  goNext: () => void
  canPrev: boolean
  canNext: boolean
}

/**
 * Client-side list pagination shared by PathRun and results sub-views.
 * Resets to page 1 when `pageSize` or any `resetKeys` change.
 */
export function useListPagination<T>(
  items: readonly T[],
  ...resetKeys: ReadonlyArray<string | number | boolean | null | undefined>
): ListPaginationState<T> {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState<number>(DEFAULT_LIST_PAGE_SIZE)
  const resetSignature = resetKeys.map((key) => String(key ?? '')).join('\u0000')

  useEffect(() => {
    setPage(1)
  }, [pageSize, resetSignature])

  const total = items.length
  const totalPages = Math.max(1, Math.ceil(total / pageSize) || 1)
  const safePage = Math.min(Math.max(1, page), totalPages)
  const rangeStart = total === 0 ? 0 : (safePage - 1) * pageSize + 1
  const rangeEnd = Math.min(safePage * pageSize, total)

  useEffect(() => {
    if (page !== safePage) setPage(safePage)
  }, [page, safePage])

  const pageItems = useMemo(() => {
    const start = (safePage - 1) * pageSize
    return items.slice(start, start + pageSize) as T[]
  }, [items, safePage, pageSize])

  return {
    page: safePage,
    pageSize,
    setPageSize,
    total,
    totalPages,
    rangeStart,
    rangeEnd,
    pageItems,
    setPage,
    goPrev: () => setPage((current) => Math.max(1, current - 1)),
    goNext: () => setPage((current) => Math.min(totalPages, current + 1)),
    canPrev: safePage > 1,
    canNext: safePage < totalPages
  }
}
