import type { AnalysisPackDto, ExperimentPlanDto, ProbeBudgetDto, SqlExperimentCardDto } from '../../api'
import { Notice, StatusPill } from '../Common'

export function ExperimentReplayView({
  english,
  sqlCards,
  experimentPlans,
  analysisPacks,
  probeBudget,
  cardReplayLoading,
  cardReplayError,
  cardReplayNotice,
  onReplayCard
}: {
  english: boolean
  sqlCards: SqlExperimentCardDto[]
  experimentPlans: ExperimentPlanDto[]
  analysisPacks: AnalysisPackDto[]
  probeBudget?: ProbeBudgetDto
  cardReplayLoading?: string
  cardReplayError?: string
  cardReplayNotice?: string
  onReplayCard: (cardId: string) => void
}) {
  return (
    <div className="results-view results-view--experiments">
      <div className="results-view__head">
        <div>
          <p className="eyebrow">{english ? 'EXPERIMENTS' : '实验与重放'}</p>
          <h2>{english ? 'Plans and replay' : '计划与重放'}</h2>
        </div>
        <span>{sqlCards.length + experimentPlans.length}</span>
      </div>

      <p className="form-help">
        {english
          ? 'Replay actions enqueue server-owned attempts; they never upgrade to VERIFIED.'
          : '重放动作由服务端排队；不会直接升格 VERIFIED。'}
      </p>

      {cardReplayError && <Notice kind="error">{cardReplayError}</Notice>}
      {cardReplayNotice && <Notice kind="info">{cardReplayNotice}</Notice>}

      <div className="results-table-list">
        {sqlCards.map((card) => (
          <div className="results-row" key={card.cardId}>
            <div className="results-row__body">
              <strong>{card.entrypointRef} · {card.track}</strong>
              <small className="veyrion-long-text">{english ? 'Before' : '前'}：{card.sqlBefore}</small>
              <small className="veyrion-long-text">{english ? 'After' : '后'}：{card.sqlAfter}</small>
              <small>{card.dependencyMode} · {card.verificationStatus}</small>
            </div>
            <div className="button-row">
              <StatusPill status={card.verificationStatus} />
              <button
                type="button"
                className="secondary-button"
                disabled={!card.replayable || !!cardReplayLoading || card.verificationStatus === 'VERIFIED'}
                onClick={() => onReplayCard(card.cardId)}
              >
                {cardReplayLoading === card.cardId ? (english ? 'Replaying…' : '重放中…') : (english ? 'Replay' : '重放')}
              </button>
            </div>
          </div>
        ))}
        {sqlCards.length === 0 && (
          <p className="empty-state">{english ? 'No D3 cards yet.' : '尚无 D3 实验卡。'}</p>
        )}
      </div>

      {(probeBudget || experimentPlans.length > 0 || analysisPacks.length > 0) && (
        <div className="section-gap form-help">
          {probeBudget && (
            <p>{english
              ? `Probe budget: ${probeBudget.plannedProbes}/${probeBudget.maxProbes}, unreached ${probeBudget.unreachedEntries}.`
              : `探针预算：${probeBudget.plannedProbes}/${probeBudget.maxProbes}，未达 ${probeBudget.unreachedEntries}。`}
            </p>
          )}
          {experimentPlans.length > 0 && (
            <p>{english ? `Accepted plans: ${experimentPlans.length}` : `已接受计划：${experimentPlans.length}`}</p>
          )}
          {analysisPacks.length > 0 && (
            <p>{english ? `Packs: ${analysisPacks.map((pack) => pack.packId).join(', ')}` : `语义包：${analysisPacks.map((pack) => pack.packId).join('、')}`}</p>
          )}
        </div>
      )}

      {experimentPlans.some((plan) => plan.fuzzStrategyJson || plan.fuzzStrategy) && (
        <div className="results-table-list section-gap">
          {experimentPlans.filter((plan) => plan.fuzzStrategyJson || plan.fuzzStrategy).map((plan) => (
            <div className="results-row" key={plan.planId}>
              <strong>{plan.planId}</strong>
              <small className="veyrion-long-text">{plan.method} {plan.entrypointRef} · {(plan.fuzzStrategyJson || plan.fuzzStrategy || '').slice(0, 200)}</small>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
