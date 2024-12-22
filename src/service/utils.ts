import { Fp2 } from "@noble/curves/abstract/tower";
import { concatBytes, hexToNumber, numberToBytesBE } from "@noble/curves/abstract/utils";
import type { ProjPointType } from "@noble/curves/abstract/weierstrass";
import { bn254 } from "@noble/curves/bn254"
import { solG1 } from "@thehubbleproject/bls/dist/mcl";

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

export interface AggregationPayload {
  sigs: {
    sig: string[],
    pub: string[]
  }[]
}

export const getBigIntPoint = (point: ProjPointType<bigint>) => {
  return concatBytes(
      numberToBytesBE(point.x, 32),
      numberToBytesBE(point.y, 32),
  )
}

export const getFp2Point = (point: ProjPointType<Fp2>) => {
  return concatBytes(
      numberToBytesBE(point.x.c1, 32),
      numberToBytesBE(point.x.c0, 32),
      numberToBytesBE(point.y.c1, 32),
      numberToBytesBE(point.y.c0, 32),
  )
}

export function hexToUint8Array(h: any) {
  return Uint8Array.from(Buffer.from(h.slice(2), "hex"));
}

export const parseSigPoint = (sigPoint: SigPoint): ProjPointType<bigint> => {
  return bn254.G1.ProjectivePoint.fromAffine({
    x: hexToNumber(sigPoint.px),
    y: hexToNumber(sigPoint.py)
  })
}

export const parsePublicPoint = (publicPoint: PublicPoint): ProjPointType<Fp2> => {
  const { Fp2 } = bn254.fields;
  const x = Fp2.fromBigTuple([hexToNumber(publicPoint.px.c0), hexToNumber(publicPoint.px.c1)]);
  const y = Fp2.fromBigTuple([hexToNumber(publicPoint.py.c0), hexToNumber(publicPoint.py.c1)]);

  return bn254.G2.ProjectivePoint.fromAffine({
    x, y
  })
}

export const convertSOlG1ProjectPointType = (solG1: solG1): ProjPointType<bigint> => {
  const v = {
    px: solG1[0],
    py: solG1[1],
    pz: '01'
  }

  return parseSigPoint(v);
}

export const convertSolG1ToSigPoint = (solG1Points: solG1[]): SigPoint[] => {
  return solG1Points.map(([px, py]) => ({
    px,
    py,
    pz: '01'
  }));
}

export const extractSignaturesFromPayload = (payload: any[]): solG1[] => {
  return payload.map(sig => sig.sig as solG1);
}

export const extractPublicPointsFromPayload = (payload: any[]): PublicPoint[] => {
  return payload.map(sig => {
    const pub = sig.pub;
    if (pub.length !== 4) {
      throw new Error('Invalid public point format: expected 4 strings');
    }
    
    return {
      px: {
        c0: pub[0],
        c1: pub[1]
      },
      py: {
        c0: pub[2],
        c1: pub[3]
      }
    };
  });
}

export const convertPublicPointToG2Point = (publicPoint: PublicPoint): ProjPointType<Fp2> => {
  const { Fp2 } = bn254.fields;
  const x = Fp2.fromBigTuple([
    hexToNumber(publicPoint.px.c0), 
    hexToNumber(publicPoint.px.c1)
  ]);
  const y = Fp2.fromBigTuple([
    hexToNumber(publicPoint.py.c0), 
    hexToNumber(publicPoint.py.c1)
  ]);

  return bn254.G2.ProjectivePoint.fromAffine({ x, y });
}

export const convertPayloadToG2Points = (payload: any[]): ProjPointType<Fp2>[] => {
  const publicPoints = extractPublicPointsFromPayload(payload);
  return publicPoints.map(convertPublicPointToG2Point);
}