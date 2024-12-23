import { ethers } from "ethers";
import { concatBytes } from "@noble/curves/abstract/utils";
import { bn254 } from '@kevincharm/noble-bn254-drand'
import type { ProjPointType } from "@noble/curves/abstract/weierstrass";
import type { Fp2 } from "@noble/curves/abstract/tower";
import { getBigIntPoint, getFp2Point } from './utils';

export const getSignaturePoint = (privateKey: Uint8Array, Hm: ProjPointType<bigint>) => {
  const publicPoint = bn254.G2.ProjectivePoint.fromPrivateKey(privateKey);
  const sigPoint = Hm.multiply(bn254.G1.normPrivateKeyToScalar(privateKey));
  return { sigPoint, publicPoint };
}

export const createSignature = (
  eoaSignature: string,
  blsSignature: Uint8Array
): string => {
  const abiCoder = new ethers.AbiCoder();
  const encodedSignatures = abiCoder.encode(
    ['bytes', 'bytes'],
    [eoaSignature, blsSignature]
  );

  return ethers.concat([
    new Uint8Array([3]),
    encodedSignatures
  ]);
}

export const getAggSignature = (signatures: ProjPointType<bigint>[]) => {
  const aggSignature = signatures.reduce((sum, s) => sum.add(s), bn254.G1.ProjectivePoint.ZERO);
  return aggSignature;
}

export const blsSignature = (
  aggSignature: ProjPointType<bigint>,
  publicPoints: ProjPointType<Fp2>[],
  Hm: ProjPointType<bigint>
) => {
  let calldata = concatBytes(getBigIntPoint(aggSignature), getFp2Point(bn254.G2.ProjectivePoint.BASE));
  for (let i = 0; i < publicPoints.length; i++) {
      calldata = concatBytes(calldata, getBigIntPoint(Hm), getFp2Point(publicPoints[i].negate()));
  }
  return calldata
}