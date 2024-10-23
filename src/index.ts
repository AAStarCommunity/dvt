import express from "express";
import { blsSign } from "./service/signer";
import { aggregator } from "./service/aggregator";
import { solG1, solG2 } from "@thehubbleproject/bls/dist/mcl";
import { mcl } from "@thehubbleproject/bls";
import { BlsSignerFactory } from "@thehubbleproject/bls/dist/signer";
import { formatBytes32String } from "ethers/lib/utils";
import crypto from "crypto";
import { hexToUint8Array } from "./service/utils";

const STATUS_CODES_ACCEPTED = 202;
const STATUS_CODES_NOT_ACCEPTED = 406;
const STATUS_CODES_INTERNAL_SERVER_ERROR = 500;

const app = express();
let factory: BlsSignerFactory;
const port = process.env.PORT || 80;

app.use(express.json());
app.post("/sign", async (req, res, next) => {
  try {
    const { domain, message }: { domain: string; message: string } = req.body;

    if (!domain || !message) {
      res.status(400).send({ error: "Invalid input" });
      return;
    }

    const hashedDomain = crypto
      .createHash("sha256")
      .update(domain)
      .digest("hex");

    const s = await blsSign(hashedDomain, message);

    res.send(JSON.stringify({ sig: s.signature, pubkeys: s.pubkey }));
  } catch (e) {
    next(e);
  }
});

app.post("/aggr", async (req, res, next) => {
  try {
    const { sigs }: { sigs: string[2][] } = req.body;
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
    res.send(JSON.stringify({ sig: aggregator(aggrs) }));
  } catch (e) {
    next(e);
  }
});

app.post("/aggr/verify", async (req, res, next) => {
  try {
    const {
      domain,
      messages,
      pubkeys,
      aggrSig,
    }: {
      domain: string;
      messages: string[];
      pubkeys: string[4][];
      aggrSig: string[2];
    } = req.body;

    const msgs = [];
    for (const raw of messages) {
      const message = formatBytes32String(raw);
      msgs.push(message);
    }

    const hashedDomain = crypto
      .createHash("sha256")
      .update(domain)
      .digest("hex");

    const signer = factory.getSigner(hexToUint8Array(hashedDomain));
    console.log({ domain, msgs, pubkeys, aggrSig });
    const g1 = mcl.loadG1(aggrSig[0] + aggrSig[1].slice(2));
    const g2: solG2[] = [];
    for (let i = 0; i < pubkeys.length; i++) {
      const x = pubkeys[i][0];
      const y = pubkeys[i][1].slice(2);
      const z = pubkeys[i][2].slice(2);
      const w = pubkeys[i][3].slice(2);
      g2.push(mcl.loadG2(x + y + z + w));
    }
    res
      .status(
        signer.verifyMultiple(g1, g2, msgs)
          ? STATUS_CODES_ACCEPTED
          : STATUS_CODES_NOT_ACCEPTED
      )
      .send();
  } catch (e) {
    next(e);
  }
});

app.use((err:any, req:any, res:any, next:any) => {
  console.error(err.stack);
  res.status(STATUS_CODES_INTERNAL_SERVER_ERROR).send({ error: "interal server error: " + err.stack });
});


app.listen(port, async () => {
  factory = await BlsSignerFactory.new();
  console.log(`Server is running at http://localhost:${port}`);
});
