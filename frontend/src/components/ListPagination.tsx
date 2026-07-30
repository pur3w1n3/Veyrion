import { LIST_PAGE_SIZE_OPTIONS } from '../hooks/useListPagination'

export function ListPagination({
  english,
  ariaLabel,
  page,
  totalPages,
  pageSize,
  onPageSizeChange,
  rangeStart,
  rangeEnd,
  total,
  onPrev,
  onNext,
  canPrev,
  canNext
}: {
  english: boolean
  ariaLabel: string
  page: number
  totalPages: number
  pageSize: number
  onPageSizeChange: (size: number) => void
  rangeStart: number
  rangeEnd: number
  total: number
  onPrev: () => void
  onNext: () => void
  canPrev: boolean
  canNext: boolean
}) {
  if (total === 0) return null

  return (
    <div className="list-pagination" role="navigation" aria-label={ariaLabel}>
      <p className="list-pagination__range">
        {english
          ? `${rangeStart}–${rangeEnd} of ${total}`
          : `第 ${rangeStart}–${rangeEnd} 条 / 共 ${total} 条`}
      </p>
      <label className="field list-pagination__size">
        <span>{english ? 'Per page' : '每页'}</span>
        <select
          value={pageSize}
          onChange={(event) => onPageSizeChange(Number(event.target.value))}
        >
          {LIST_PAGE_SIZE_OPTIONS.map((size) => (
            <option key={size} value={size}>{size}</option>
          ))}
        </select>
      </label>
      <div className="button-row list-pagination__nav">
        <button
          type="button"
          className="secondary-button"
          disabled={!canPrev}
          onClick={onPrev}
        >
          {english ? 'Previous' : '上一页'}
        </button>
        <span className="list-pagination__page">
          {english ? `Page ${page} / ${totalPages}` : `第 ${page} / ${totalPages} 页`}
        </span>
        <button
          type="button"
          className="secondary-button"
          disabled={!canNext}
          onClick={onNext}
        >
          {english ? 'Next' : '下一页'}
        </button>
      </div>
    </div>
  )
}
