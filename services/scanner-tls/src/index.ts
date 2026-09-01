import type { ScannerObservationInput } from "@aasp/schemas";
import type { ScopedHttpClient } from "@aasp/scope-engine";

export async function analyzeTls(
  client: ScopedHttpClient,
  targetUrl: string,
  timeoutMs: number,
): Promise<ScannerObservationInput[]> {
  const parsed = new URL(targetUrl);
  if (parsed.protocol !== "https:") return [];
  const response = await client.request(parsed.origin, {
    method: "HEAD",
    timeoutMs,
    maxResponseBytes: 16_384,
    followRedirects: false,
  });
  if (!response.tls) throw new Error("HTTPS response did not expose TLS session metadata.");
  const certificate = response.tls.peerCertificate;
  const expiresAt = Date.parse(certificate.validTo);
  const daysUntilExpiry = Number.isFinite(expiresAt)
    ? Math.floor((expiresAt - Date.now()) / 86_400_000)
    : null;
  const rawSeverity = daysUntilExpiry !== null && daysUntilExpiry < 0 ? "HIGH" : "INFO";
  return [
    {
      scanner: "aasp-tls",
      scannerVersion: "0.1.0",
      observationType: "TLS_CONFIGURATION_OBSERVATION",
      asset: parsed.origin,
      endpoint: "/",
      method: "HEAD",
      rawSeverity,
      evidence: [
        {
          source: "aasp-tls",
          asset: response.finalUrl,
          requestMetadata: { method: "HEAD", requestedUrl: targetUrl },
          responseMetadata: { statusCode: response.statusCode, tls: response.tls },
          excerpt: JSON.stringify({
            protocol: response.tls.protocol,
            cipher: response.tls.cipher,
            authorized: response.tls.authorized,
            subject: certificate.subject,
            issuer: certificate.issuer,
            validFrom: certificate.validFrom,
            validTo: certificate.validTo,
            subjectAltName: certificate.subjectAltName,
            fingerprint256: certificate.fingerprint256,
          }),
        },
      ],
      metadata: {
        protocol: response.tls.protocol,
        cipher: response.tls.cipher,
        certificateAuthorized: response.tls.authorized,
        authorizationError: response.tls.authorizationError,
        daysUntilExpiry,
      },
    },
  ];
}
