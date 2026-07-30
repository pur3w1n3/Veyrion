import type { ProjectDto } from './types'
import { asText, optionalText, statusOf, evidenceRefsOf, isRecord, schemaVersion, unwrap } from './helpers'
import { parseArtifact } from './artifacts'

export const parseProject = (value: unknown): ProjectDto => {
  const body = unwrap(value, 'project')
  if (!isRecord(body)) throw new Error('invalid project response')
  return {
    schemaVersion: schemaVersion(isRecord(value) ? value.schemaVersion : undefined, 'project.schemaVersion'),
    projectId: asText(body.projectId ?? body.id, 'project.projectId'),
    name: asText(body.name, 'project.name'),
    createdAt: asText(body.createdAt, 'project.createdAt'),
    verificationStatus: body.verificationStatus === undefined ? undefined : statusOf(body.verificationStatus, 'project.verificationStatus'),
    dependencyMode: optionalText(body.dependencyMode),
    evidenceRefs: evidenceRefsOf(body.evidenceRefs, 'project.evidenceRefs'),
    artifacts: body.artifacts === undefined
      ? undefined
      : Array.isArray(body.artifacts) ? body.artifacts.map(parseArtifact) : (() => { throw new Error('invalid project.artifacts') })()
  }
}

