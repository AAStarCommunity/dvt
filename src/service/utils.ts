import { mod } from "@noble/curves/abstract/modular";
import { Fp2 } from "@noble/curves/abstract/tower";
import { concatBytes, hexToNumber, numberToBytesBE } from "@noble/curves/abstract/utils";
import type { ProjPointType } from "@noble/curves/abstract/weierstrass";
import { bn254 } from "@noble/curves/bn254"
const { Fp12 } = bn254.fields;

export const getHm = (opHash: bigint) => {
  const ORDER = BigInt('21888242871839275222246405745257275088696311157297823662689037894645226208583');
  const hMNonce = mod(opHash, ORDER);
  const Hm = bn254.G1.ProjectivePoint.fromPrivateKey(hMNonce);
  return Hm;
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

export const verifySignature = (
  aggSignature: ProjPointType<bigint>,
  publicPoints: ProjPointType<Fp2>[],
  Hm: ProjPointType<bigint>
) => {
  let pairs: any[] = [];
  pairs.push({ g1: aggSignature, g2: bn254.G2.ProjectivePoint.BASE });
  for (let i = 0; i < publicPoints.length; i++) {
      pairs.push({ g1: Hm, g2: publicPoints[i].negate() });
  }
  const f = bn254.pairingBatch(pairs);
  return Fp12.eql(f, Fp12.ONE);
}