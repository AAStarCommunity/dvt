export function hexToUint8Array(h: any) {
    return Uint8Array.from(Buffer.from(h.slice(2), "hex"));
  }
  function uint8ArrayToHex(array: Uint8Array): string {
    return (
      "0x" +
      Array.from(array)
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("")
    );
  }
  