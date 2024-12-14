import express from "express";
import { blsSign } from "./service/signer";
import { solG1, solG2 } from "@thehubbleproject/bls/dist/mcl";
import { mcl } from "@thehubbleproject/bls";
import { aggregate, BlsSignerFactory } from "@thehubbleproject/bls/dist/signer";
import { formatBytes32String, sha256 } from "ethers/lib/utils";
import crypto from "crypto";
import { AuthenticationResponseJSON } from "@simplewebauthn/types";
import { getConfig } from './config';

const mcl_1 = require("@thehubbleproject/bls/dist/mcl");

const STATUS_CODES_ACCEPTED = 202;
const STATUS_CODES_NOT_ACCEPTED = 406;
const STATUS_CODES_INTERNAL_SERVER_ERROR = 500;

const app = express();
let factory: BlsSignerFactory;
const config = getConfig();
const port = config.port;
const dvtDomain = new Uint8Array([config.domain])
const dvtSecret = '0x' + crypto.createHash('sha256')
  .update(config.dvtSecret)
  .digest('hex');

app.use(express.json());

const hashMessage = (message: string): string => {
  return formatBytes32String(crypto.createHash('sha256')
    .update(message)
    .digest('hex')
    .substring(0, 30));
};

app.post("/sign", async (req, res, next) => {
  try {
    const { message, passkeyPubkey, passkey }: { message: string; passkeyPubkey: string; passkey: AuthenticationResponseJSON } = req.body;

    if (!message || !passkeyPubkey || passkey === undefined) {
      res.status(400).send({ error: "Invalid input" });
      return;
    }

    console.log({message})

    // TODO: verify passkey by @simplewebauthn

    const s = await blsSign(hashMessage(message));

    res.send(JSON.stringify({ sig: s.signature, pubkeys: s.pubkey, msg: s.msgPoints }));
  } catch (e) {
    next(e);
  }
});

app.post("/aggr", async (req, res, next) => {
  try {
    const { sigs }: { sigs: string[2][] } = req.body;
    console.log({ sigs });
    const aggrs: solG1[] = [];
    for (let i = 0; i < sigs.length; i++) {
      let x = sigs[i][0];
      let y = sigs[i][1];
      if (!x || !y) {
        res.status(400).send({ error: "Invalid input" });
        return;
      }
      if (!x.startsWith("0x")) {
        x = "0x" + x;
      }
      if (y.startsWith("0x")) {
        y = y.slice(2);
      }
      if (x.length !== 66 || y.length !== 64) {
        res.status(400).send({ error: "Invalid input" });
        return;
      }
      aggrs.push(mcl.loadG1(x + y));
    }
    res.send(JSON.stringify({ sig: aggregate(aggrs) }));
  } catch (e) {
    next(e);
  }
});

app.post("/aggr/verify/offchain", async (req, res, next) => {
  try {
    const {
      message,
      pubkeys,
      aggrSig,
    }: {
      message: string;   // raw message
      pubkeys: string[4][];
      aggrSig: string[2];
    } = req.body;

    const messages: string[] = [];
    const hm = hashMessage(message);
    for (let i=0; i<pubkeys.length; i++) {
      messages.push(hm);
    }
    const g1 = mcl.loadG1(aggrSig[0] + aggrSig[1].slice(2));
    const g2: solG2[] = [];
    for (let i = 0; i < pubkeys.length; i++) {
      const x = pubkeys[i][0];
      const y = pubkeys[i][1].slice(2);
      const z = pubkeys[i][2].slice(2);
      const w = pubkeys[i][3].slice(2);
      g2.push(mcl.loadG2(x + y + z + w));
    }
    const signer = factory.getSigner(dvtDomain, dvtSecret);
    const status = signer.verifyMultiple(g1, g2, messages)
      ? STATUS_CODES_ACCEPTED
      : STATUS_CODES_NOT_ACCEPTED;

    console.log({ domain: dvtDomain, msgs: messages, pubkeys, aggrSig });
    res.status(status).send({ "signature verification": status == STATUS_CODES_ACCEPTED });
  } catch (e) {
    next(e);
  }
});

app.use((err: any, req: any, res: any, next: any) => {
  console.error(err.stack);
  res
    .status(STATUS_CODES_INTERNAL_SERVER_ERROR)
    .send({ error: "interal server error: " + err.stack });
});

app.listen(port, async () => {
  factory = await BlsSignerFactory.new();
  console.log(`Server is running at http://localhost:${port}`);
});
