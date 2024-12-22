import { Fp2 } from "@noble/curves/abstract/tower";
import { hexToNumber } from "@noble/curves/abstract/utils";
import type { ProjPointType } from "@noble/curves/abstract/weierstrass";
import { bn254 } from "@noble/curves/bn254"

interface SigPoint {
  px: string,
  py: string,
  pz: string
}

interface PublicPoint {
  px: {
      c0: string,
      c1: string
  },
  py: {
      c0: string,
      c1: string
  }
}

export function hexToUint8Array(h: any) {
  return Uint8Array.from(Buffer.from(h.slice(2), "hex"));
}

export const parseSigPoint = (formatSigPoint: string): ProjPointType<bigint> => {
  const data = JSON.parse(formatSigPoint) as SigPoint
  return bn254.G1.ProjectivePoint.fromAffine({
    x: hexToNumber(data.px),
    y: hexToNumber(data.py)
  })
}

export const parsePublicPoint = (formatSigPoint: string): ProjPointType<Fp2> => {
  const data = JSON.parse(formatSigPoint) as PublicPoint

  const { Fp2 } = bn254.fields;
  const x = Fp2.fromBigTuple([hexToNumber(data.px.c0), hexToNumber(data.px.c1)]);
  const y = Fp2.fromBigTuple([hexToNumber(data.py.c0), hexToNumber(data.py.c1)]);

  return bn254.G2.ProjectivePoint.fromAffine({
    x, y
  })
}