import { solG1, solG2 } from "@thehubbleproject/bls/dist/mcl";
import { aggregate, BlsSignerFactory } from "@thehubbleproject/bls/dist/signer";
import { formatBytes32String } from "ethers/lib/utils";
import { hexToUint8Array } from "./utils";

export async function blsSign(domain: string, message: string): Promise<any> {
  const DOMAIN = hexToUint8Array(domain);
  const factory = await BlsSignerFactory.new();
  const msg = formatBytes32String(message);
  const signer = factory.getSigner(DOMAIN);
  const signature = signer.sign(msg);
  const pubkey = signer.pubkey;
  console.log({ pubkey, signature, signer })
  return { pubkey, signature, signer };
}
