import express from "express";
import { blsSign } from "./service/signer";

const app = express();
const port = process.env.PORT || 8080;

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

  const v = aggregator([s.signature]);

  const g1 = mcl.loadG1(
    "0x2f71e7f05b887dd947424b3fe1885a32c7733a180b4bbf0eb0040a644bdfea262f197beb9a8accb964c90dc387323bf0b9c5631b23f8bcb777e692361e5d331f"
  );
  console.log(aggregator([g1]));
  res.send(JSON.stringify({ sig: s.signature, pubkeys: s.pubkey, v }));
});

app.post("/aggr", async (req, res) => {
  const g1 = mcl.loadG1(
    "0x2f71e7f05b887dd947424b3fe1885a32c7733a180b4bbf0eb0040a644bdfea262f197beb9a8accb964c90dc387323bf0b9c5631b23f8bcb777e692361e5d331f"
  );
  res.send(JSON.stringify({ sig: aggregator([g1]) }));
});

app.listen(port, async () => {
    await BlsSignerFactory.new();
    console.log(`Server is running at http://localhost:${port}`);
});
