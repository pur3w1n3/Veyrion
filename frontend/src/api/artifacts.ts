import type { ArtifactDto } from './types'
import { asText, optionalText, statusOf, evidenceRefsOf, isRecord, schemaVersion, asSafeInteger, asBoolean, unwrap } from './helpers'

export const parseArtifact = (value: unknown): ArtifactDto => {
  const body = unwrap(value, 'artifact')
  if (!isRecord(body)) throw new Error('invalid artifact response')
  const status = statusOf(body.verificationStatus ?? body.status, 'artifact.verificationStatus')
  const artifactId = asText(body.artifactId ?? body.id, 'artifact.artifactId')
  const originalFileName = optionalText(body.originalFileName) ?? optionalText(body.fileName)
  const displayName = optionalText(body.displayName) ?? originalFileName ?? artifactId
  return {
    schemaVersion: schemaVersion(isRecord(value) ? value.schemaVersion : undefined, 'artifact.schemaVersion'),
    artifactId,
    type: asText(body.type ?? body.artifactType, 'artifact.type').toUpperCase(),
    artifactType: asText(body.type ?? body.artifactType, 'artifact.type').toUpperCase(),
    artifactDigest: asText(body.artifactDigest ?? body.sha256, 'artifact.artifactDigest'),
    sizeBytes: asSafeInteger(body.sizeBytes, 'artifact.sizeBytes', 0),
    staticOnly: asBoolean(body.staticOnly, 'artifact.staticOnly'),
    verificationStatus: status,
    dependencyMode: optionalText(body.dependencyMode),
    evidenceRefs: evidenceRefsOf(body.evidenceRefs, 'artifact.evidenceRefs'),
    projectId: optionalText(body.projectId),
    registeredAt: optionalText(body.registeredAt),
    originalFileName,
    fileName: originalFileName,
    displayName
  }
}

