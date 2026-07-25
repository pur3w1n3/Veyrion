let confirmedForPageSession = false

export function confirmAiAuthorization(): boolean {
  if (confirmedForPageSession) return true
  const confirmed = window.confirm(
    '确认启动整条审计流水线？系统将使用当前项目已保存、受限制的脱敏事实，依次调用五个模型角色，并在断网容器中做动态观察；这些数据可能发送到你配置的远端模型服务。'
  )
  if (confirmed) confirmedForPageSession = true
  return confirmed
}
