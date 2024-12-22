import { BlsSignerFactory } from "@thehubbleproject/bls/dist/signer";
import { getConfig } from '../config';
import crypto from "crypto";
import { g1ToHex, hashToPoint, solG1 } from "@thehubbleproject/bls/dist/mcl";
import { ethers } from "ethers";
import { concatBytes, numberToBytesBE } from "@noble/curves/abstract/utils";
import { bn254 } from '@kevincharm/noble-bn254-drand'
import type { ProjPointType } from "@noble/curves/abstract/weierstrass";
import type { Fp2 } from "@noble/curves/abstract/tower";

const config = getConfig();
const signerDomain = new Uint8Array([config.domain]);

export async function blsSign(message: string): Promise<any> {
  const factory = await BlsSignerFactory.new();
  const secretKey = '0x' + crypto.createHash('sha256')
    .update(config.dvtSecret)
    .digest('hex');
  const signer = factory.getSigner(signerDomain, secretKey);
  const signature = signer.sign(message);
  const msgPoints = g1ToHex(hashToPoint(message, signerDomain));
  const pubkey = signer.pubkey;
  console.log({ pubkey, signature, msgPoints })
  return { pubkey, signature, msgPoints };
}

export function createSignature(
  eoaSignature: string,
  blsSignature: solG1
): string {
  const abiCoder = new ethers.AbiCoder();
  const encodedSignatures = abiCoder.encode(
    ['bytes', '(bytes32,bytes32)'],
    [eoaSignature, blsSignature]
  );

  return ethers.concat([
    new Uint8Array([3]),
    encodedSignatures
  ]);
}


const getBigIntPoint = (point: ProjPointType<bigint>) => {
  return concatBytes(
      numberToBytesBE(point.x, 32),
      numberToBytesBE(point.y, 32),
  )
}

const getFp2Point = (point: ProjPointType<Fp2>) => {
  return concatBytes(
      numberToBytesBE(point.x.c1, 32),
      numberToBytesBE(point.x.c0, 32),
      numberToBytesBE(point.y.c1, 32),
      numberToBytesBE(point.y.c0, 32),
  )
}

export const getAggSignatureCalldata = (
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