import { BlsSignerFactory } from "@thehubbleproject/bls/dist/signer";
import { formatBytes32String } from "ethers/lib/utils";
import { getConfig } from '../config';
const config = getConfig();

export async function blsSign(message: string): Promise<any> {
  const factory = await BlsSignerFactory.new();
  const msg = formatBytes32String(message);
  const signer = factory.getSigner(new Uint8Array([config.domain]), config.dvtSecret);
  const signature = signer.sign(msg);
  const pubkey = signer.pubkey;
  console.log({ pubkey, signature, signer })
  return { pubkey, signature, signer };
}
