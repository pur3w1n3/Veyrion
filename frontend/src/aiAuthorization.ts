let confirmedForPageSession = false

export function confirmAiAuthorization(): boolean {
  if (confirmedForPageSession) return true
  const confirmed = window.confirm('确认本次页面会话中的 AI Job 可使用当前项目已持久化、受限且可能发送至远端 Provider 的脱敏事实？')
  if (confirmed) confirmedForPageSession = true
  return confirmed
}
