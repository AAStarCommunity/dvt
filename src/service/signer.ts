import { BlsSignerFactory } from "@thehubbleproject/bls/dist/signer";
import { formatBytes32String } from "ethers/lib/utils";
import { getConfig } from '../config';
import crypto from "crypto";
import { g1ToHex, hashToPoint } from "@thehubbleproject/bls/dist/mcl";
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