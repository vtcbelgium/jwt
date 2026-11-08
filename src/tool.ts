/**
 * JWT Decoder & Expiry Inspector - Pure TypeScript Domain Module
 * Decodes JWT tokens, inspects claims, calculates expiration status.
 * Zero dependencies, standard Web APIs only.
 */

/**
 * Standardized result contract for all OTHRYS tools.
 */
export interface ToolResult {
  success: boolean;
  data: string;
  error?: string;
  warnings?: string[];
}

/**
 * Decoded JWT component structure.
 */
export interface DecodedJWT {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
  rawParts: [string, string, string];
}

/**
 * Timestamp analysis result.
 */
export interface TimestampAnalysis {
  claim: string;
  epoch: number;
  iso: string;
  human: string;
  status: 'expired' | 'valid' | 'future' | 'unknown';
  relative: string;
}

/**
 * Algorithm metadata.
 */
export interface AlgorithmInfo {
  name: string;
  description: string;
  category: 'symmetric' | 'asymmetric' | 'none' | 'unknown';
  recommended: boolean;
}

/**
 * Known JWT algorithms with metadata.
 */
const ALGORITHM_REGISTRY: Record<string, AlgorithmInfo> = {
  'HS256': { name: 'HS256', description: 'HMAC using SHA-256', category: 'symmetric', recommended: true },
  'HS384': { name: 'HS384', description: 'HMAC using SHA-384', category: 'symmetric', recommended: true },
  'HS512': { name: 'HS512', description: 'HMAC using SHA-512', category: 'symmetric', recommended: true },
  'RS256': { name: 'RS256', description: 'RSASSA-PKCS1-v1_5 using SHA-256', category: 'asymmetric', recommended: true },
  'RS384': { name: 'RS384', description: 'RSASSA-PKCS1-v1_5 using SHA-384', category: 'asymmetric', recommended: true },
  'RS512': { name: 'RS512', description: 'RSASSA-PKCS1-v1_5 using SHA-512', category: 'asymmetric', recommended: true },
  'ES256': { name: 'ES256', description: 'ECDSA using P-256 and SHA-256', category: 'asymmetric', recommended: true },
  'ES384': { name: 'ES384', description: 'ECDSA using P-384 and SHA-384', category: 'asymmetric', recommended: true },
  'ES512': { name: 'ES512', description: 'ECDSA using P-521 and SHA-512', category: 'asymmetric', recommended: true },
  'PS256': { name: 'PS256', description: 'RSASSA-PSS using SHA-256 and MGF1 with SHA-256', category: 'asymmetric', recommended: true },
  'PS384': { name: 'PS384', description: 'RSASSA-PSS using SHA-384 and MGF1 with SHA-384', category: 'asymmetric', recommended: true },
  'PS512': { name: 'PS512', description: 'RSASSA-PSS using SHA-512 and MGF1 with SHA-512', category: 'asymmetric', recommended: true },
  'EdDSA': { name: 'EdDSA', description: 'Edwards-curve Digital Signature Algorithm', category: 'asymmetric', recommended: true },
  'none': { name: 'none', description: 'No signature (INSECURE)', category: 'none', recommended: false },
};

/**
 * Standard JWT registered claims (RFC 7519).
 */
const REGISTERED_CLAIMS = new Set([
  'iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'
]);

/**
 * Decodes a base64url-encoded string to UTF-8 string.
 * Uses standard atob with padding correction and TextDecoder for safety.
 */
export function base64UrlDecode(input: string): string {
  // Restore padding
  let padded = input.replace(/-/g, '+').replace(/_/g, '/');
  const padLength = (4 - (padded.length % 4)) % 4;
  padded += '='.repeat(padLength);
  
  try {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return new TextDecoder('utf-8').decode(bytes);
  } catch (e) {
    throw new Error(`Invalid base64url encoding: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/**
 * Parses a JWT token string into its components.
 * Returns null if the token structure is invalid.
 */
export function parseJWT(token: string): DecodedJWT | null {
  const parts = token.split('.');
  if (parts.length !== 3) {
    return null;
  }
  const [headerB64, payloadB64, signature] = parts;
  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(base64UrlDecode(headerB64));
    payload = JSON.parse(base64UrlDecode(payloadB64));
  } catch {
    return null;
  }
  return {
    header,
    payload,
    signature,
    rawParts: [headerB64, payloadB64, signature]
  };
}

/**
 * Analyzes a timestamp claim (exp, iat, nbf) against a reference time.
 */
export function analyzeTimestamp(epoch: number, reference: number = Date.now() / 1000): TimestampAnalysis {
  const date = new Date(epoch * 1000);
  const iso = date.toISOString();
  const human = date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' });
  
  let status: TimestampAnalysis['status'] = 'unknown';
  let relative = '';
  
  const diff = epoch - reference;
  if (diff < 0) {
    status = 'expired';
    const absDiff = Math.abs(diff);
    if (absDiff < 60) relative = `${Math.round(absDiff)} seconds ago`;
    else if (absDiff < 3600) relative = `${Math.round(absDiff / 60)} minutes ago`;
    else if (absDiff < 86400) relative = `${Math.round(absDiff / 3600)} hours ago`;
    else relative = `${Math.round(absDiff / 86400)} days ago`;
  } else if (diff === 0) {
    status = 'valid';
    relative = 'right now';
  } else {
    status = 'future';
    if (diff < 60) relative = `in ${Math.round(diff)} seconds`;
    else if (diff < 3600) relative = `in ${Math.round(diff / 60)} minutes`;
    else if (diff < 86400) relative = `in ${Math.round(diff / 3600)} hours`;
    else relative = `in ${Math.round(diff / 86400)} days`;
  }
  
  return { claim: '', epoch, iso, human, status, relative };
}

/**
 * Retrieves algorithm metadata from the registry.
 */
export function getAlgorithmInfo(alg: string): AlgorithmInfo {
  const normalized = alg.toUpperCase();
  return ALGORITHM_REGISTRY[normalized] || {
    name: alg,
    description: 'Unknown or custom algorithm',
    category: 'unknown',
    recommended: false
  };
}

/**
 * Formats a claim value for display.
 */
export function formatClaimValue(key: string, value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'number' && (key === 'exp' || key === 'iat' || key === 'nbf')) {
    const analysis = analyzeTimestamp(value);
    return `${value} (${analysis.iso} / ${analysis.human}) [${analysis.status.toUpperCase()}: ${analysis.relative}]`;
  }
  if (typeof value === 'object') {
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return String(value);
    }
  }
  return String(value);
}

/**
 * Main orchestrator: processes a JWT token string and returns a formatted analysis.
 */
export function processInput(input: string): ToolResult {
  const token = input.trim();
  if (!token) {
    return { success: false, data: '', error: 'No token provided' };
  }
  
  const decoded = parseJWT(token);
  if (!decoded) {
    return { success: false, data: '', error: 'Invalid JWT format: must contain three base64url-encoded parts separated by dots' };
  }
  
  const warnings: string[] = [];
  const lines: string[] = [];
  
  // Header
  lines.push('=== HEADER ===');
  for (const [key, value] of Object.entries(decoded.header)) {
    lines.push(`${key}: ${formatClaimValue(key, value)}`);
  }
  
  // Algorithm check
  const alg = decoded.header.alg as string | undefined;
  if (alg) {
    const algInfo = getAlgorithmInfo(alg);
    lines.push(`\nAlgorithm: ${algInfo.name} (${algInfo.category})`);
    lines.push(`Description: ${algInfo.description}`);
    lines.push(`Recommended: ${algInfo.recommended ? 'Yes' : 'No'}`);
    if (!algInfo.recommended) {
      warnings.push(`Algorithm '${alg}' is not recommended for production use`);
    }
    if (algInfo.category === 'none') {
      warnings.push('CRITICAL: Token uses "none" algorithm - no signature verification!');
    }
  } else {
    warnings.push('Missing "alg" claim in header');
  }
  
  // Payload
  lines.push('\n=== PAYLOAD ===');
  const now = Date.now() / 1000;
  for (const [key, value] of Object.entries(decoded.payload)) {
    const isRegistered = REGISTERED_CLAIMS.has(key);
    const prefix = isRegistered ? '● ' : '  ';
    lines.push(`${prefix}${key}: ${formatClaimValue(key, value)}`);
    
    // Timestamp-specific warnings
    if ((key === 'exp' || key === 'nbf') && typeof value === 'number') {
      const analysis = analyzeTimestamp(value, now);
      if (analysis.status === 'expired') {
        warnings.push(`Token ${key === 'exp' ? 'expired' : 'not yet valid'} (${key}: ${analysis.relative})`);
      }
    }
  }
  
  // Signature
  lines.push('\n=== SIGNATURE ===');
  lines.push(`Length: ${decoded.signature.length} chars (base64url)`);
  lines.push(`Raw: ${decoded.signature}`);
  
  // Summary
  lines.push('\n=== SUMMARY ===');
  lines.push(`Token parts: 3 (valid structure)`);
  lines.push(`Registered claims present: ${[...REGISTERED_CLAIMS].filter(c => c in decoded.payload).join(', ') || 'none'}`);
  
  const output = lines.join('\n');
  return {
    success: true,
    data: output,
    warnings: warnings.length > 0 ? warnings : undefined
  };
}

