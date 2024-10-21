import { solG1 } from "@thehubbleproject/bls/dist/mcl";
import { aggregate } from "@thehubbleproject/bls/dist/signer";

export function aggregator(sigs:solG1[]) : solG1{
    return aggregate(sigs);
}