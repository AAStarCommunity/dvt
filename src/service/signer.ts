import { BlsSignerFactory } from "@thehubbleproject/bls/dist/signer";
import { getConfig } from '../config';
import crypto from "crypto";
import { g1ToHex, hashToPoint, solG1 } from "@thehubbleproject/bls/dist/mcl";
import { ethers } from "ethers";

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