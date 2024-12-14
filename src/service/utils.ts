export function hexToUint8Array(h: any) {
    return Uint8Array.from(Buffer.from(h.slice(2), "hex"));
  }