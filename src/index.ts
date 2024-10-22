import express from "express";
import { blsSign } from "./service/signer";

const app = express();
const port = process.env.PORT || 80;

import { aggregator } from "./service/aggregator";
import { solG1 } from "@thehubbleproject/bls/dist/mcl";
import { mcl } from "@thehubbleproject/bls";
import { BlsSignerFactory } from "@thehubbleproject/bls/dist/signer";
app.use(express.json());
app.post("/sign", async (req, res) => {
  const { domain, message }: { domain: string; message: string } = req.body;

  if (!domain || !message) {
    res.status(400).send({ error: "Invalid input" });
    return;
  }
  const s = await blsSign(domain, message);

  res.send(JSON.stringify({ sig: s.signature, pubkeys: s.pubkey }));
});

app.post("/aggr", async (req, res) => {
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
});

app.listen(port, async () => {
  await BlsSignerFactory.new();
  console.log(`Server is running at http://localhost:${port}`);
});
