import { describe, it, expect } from 'vitest';
import {
  processInput,
  parseJWT,
  base64UrlDecode,
  analyzeTimestamp,
  getAlgorithmInfo,
  formatClaimValue,
  ToolResult,
  DecodedJWT,
  TimestampAnalysis,
  AlgorithmInfo
} from '../src/tool.ts';

// Helper to create a valid JWT-like token (not cryptographically valid, but structurally correct)
function createTestJWT(header: Record<string, unknown>, payload: Record<string, unknown>): string {
  const encode = (obj: Record<string, unknown>) => {
    const json = JSON.stringify(obj);
    const bytes = new TextEncoder().encode(json);
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  };
  return `${encode(header)}.${encode(payload)}.signature`;
}

describe('JWT Decoder & Expiry Inspector', () => {
  describe('base64UrlDecode', () => {
    it('decodes standard base64url strings', () => {
      // "hello world" -> "aGVsbG8gd29ybGQ"
      expect(base64UrlDecode('aGVsbG8gd29ybGQ')).toBe('hello world');
    });

    it('handles padding correctly', () => {
      // "a" -> "YQ" (needs padding)
      expect(base64UrlDecode('YQ')).toBe('a');
      // "ab" -> "YWI" (needs padding)
      expect(base64UrlDecode('YWI')).toBe('ab');
    });

    it('converts URL-safe alphabet', () => {
      // "+" -> "-", "/" -> "_"
      const original = '++//';
      const encoded = btoa(original).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      expect(base64UrlDecode(encoded)).toBe(original);
    });

    it('throws on invalid input', () => {
      expect(() => base64UrlDecode('!!!')).toThrow();
    });
  });

  describe('parseJWT', () => {
    it('parses a valid JWT', () => {
      const token = createTestJWT({ alg: 'HS256', typ: 'JWT' }, { sub: '123', name: 'John' });
      const result = parseJWT(token);
      expect(result).not.toBeNull();
      expect(result!.header.alg).toBe('HS256');
      expect(result!.payload.sub).toBe('123');
      expect(result!.signature).toBe('signature');
    });

    it('returns null for malformed token (wrong part count)', () => {
      expect(parseJWT('header.payload')).toBeNull();
      expect(parseJWT('header.payload.signature.extra')).toBeNull();
    });

    it('returns null for invalid base64url in header', () => {
      expect(parseJWT('!!! .payload.signature')).toBeNull();
    });

    it('returns null for invalid JSON in payload', () => {
      const header = btoa(JSON.stringify({ alg: 'none' })).replace(/=/g, '');
      const payload = btoa('not json').replace(/=/g, '');
      expect(parseJWT(`${header}.${payload}.sig`)).toBeNull();
    });
  });

  describe('analyzeTimestamp', () => {
    const now = 1700000000; // Fixed reference time

    it('marks past timestamps as expired', () => {
      const res = analyzeTimestamp(now - 3600, now);
      expect(res.status).toBe('expired');
      expect(res.relative).toContain('hour');
    });

    it('marks future timestamps as future', () => {
      const res = analyzeTimestamp(now + 7200, now);
      expect(res.status).toBe('future');
      expect(res.relative).toContain('hour');
    });

    it('marks current timestamp as valid', () => {
      const res = analyzeTimestamp(now, now);
      expect(res.status).toBe('valid');
      expect(res.relative).toBe('right now');
    });

    it('formats ISO and human dates correctly', () => {
      const res = analyzeTimestamp(0, now); // Unix epoch
      expect(res.iso).toBe('1970-01-01T00:00:00.000Z');
      expect(res.human).toContain('1970');
    });
  });

  describe('getAlgorithmInfo', () => {
    it('returns known algorithm metadata', () => {
      const info = getAlgorithmInfo('RS256');
      expect(info.name).toBe('RS256');
      expect(info.category).toBe('asymmetric');
      expect(info.recommended).toBe(true);
    });

    it('returns unknown for unregistered algorithm', () => {
      const info = getAlgorithmInfo('CUSTOM_ALG');
      expect(info.name).toBe('CUSTOM_ALG');
      expect(info.category).toBe('unknown');
      expect(info.recommended).toBe(false);
    });

    it('handles case insensitivity', () => {
      expect(getAlgorithmInfo('hs256').name).toBe('HS256');
      expect(getAlgorithmInfo('Hs256').category).toBe('symmetric');
    });
  });

  describe('formatClaimValue', () => {
    it('formats timestamp claims with analysis', () => {
      const now = Date.now() / 1000;
      const formatted = formatClaimValue('exp', now + 3600);
      expect(formatted).toContain(String(now + 3600));
      expect(formatted).toContain('FUTURE');
    });

    it('stringifies objects', () => {
      const obj = { nested: { value: 42 } };
      expect(formatClaimValue('custom', obj)).toContain('nested');
    });

    it('handles primitives', () => {
      expect(formatClaimValue('str', 'hello')).toBe('hello');
      expect(formatClaimValue('num', 42)).toBe('42');
      expect(formatClaimValue('bool', true)).toBe('true');
      expect(formatClaimValue('null', null)).toBe('null');
    });
  });

  describe('processInput (integration)', () => {
    it('returns error for empty input', () => {
      const res = processInput('   ');
      expect(res.success).toBe(false);
      expect(res.error).toContain('No token provided');
    });

    it('returns error for invalid JWT structure', () => {
      const res = processInput('not.a.jwt');
      expect(res.success).toBe(false);
      expect(res.error).toContain('Invalid JWT format');
    });

    it('successfully decodes and analyzes a valid token', () => {
      const future = Math.floor(Date.now() / 1000) + 3600;
      const token = createTestJWT({ alg: 'HS256' }, { sub: 'user1', exp: future, iat: future - 7200 });
      const res = processInput(token);
      expect(res.success).toBe(true);
      expect(res.data).toContain('HEADER');
      expect(res.data).toContain('PAYLOAD');
      expect(res.data).toContain('SIGNATURE');
      expect(res.data).toContain('HS256');
      expect(res.data).toContain('user1');
      expect(res.warnings).toBeUndefined(); // no warnings for valid future exp
    });

    it('generates warnings for expired token', () => {
      const past = Math.floor(Date.now() / 1000) - 3600;
      const token = createTestJWT({ alg: 'HS256' }, { exp: past });
      const res = processInput(token);
      expect(res.success).toBe(true);
      expect(res.warnings).toBeDefined();
      expect(res.warnings!.some(w => w.includes('expired'))).toBe(true);
    });

    it('warns about none algorithm', () => {
      const token = createTestJWT({ alg: 'none' }, {});
      const res = processInput(token);
      expect(res.success).toBe(true);
      expect(res.warnings).toBeDefined();
      expect(res.warnings!.some(w => w.includes('none'))).toBe(true);
    });
  });
});

