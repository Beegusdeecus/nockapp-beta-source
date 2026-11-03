/** Normalize wallet replies only; public protocol quantities stay canonical. */
export function walletQuantity(v: unknown, field: string): string {
  // MetaMask's external-extension channel has returned JSON numbers (nonce:1).
  // Unsafe numbers have already lost precision and must never be rounded.
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && !Object.is(v, -0))
    return '0x'+BigInt(v).toString(16);
  if (typeof v !== 'string' || !/^0x[0-9a-fA-F]{1,64}$/.test(v))
    throw new Error(`MetaMask returned an invalid ${field}. No transaction was requested.`);
  return '0x'+BigInt(v).toString(16);
}
