import express from "express";
import { getAggSignature, blsSignature, getHm, getSignaturePoint, createSignature } from "./service";
import { AuthenticationResponseJSON } from "@simplewebauthn/types";
import { getConfig } from './config';
import { bytesToHex, hexToBytes } from "@noble/curves/abstract/utils";
import { bn254 } from "@kevincharm/noble-bn254-drand";

const STATUS_CODES_ACCEPTED = 202;
const STATUS_CODES_NOT_ACCEPTED = 406;
const STATUS_CODES_INTERNAL_SERVER_ERROR = 500;

const app = express();
const config = getConfig();
const port = config.port;

app.use(express.json());

app.post("/sign", async (req, res, next) => {
  try {
    const { message, passkeyPubkey, passkey }: { message: string; passkeyPubkey: string; passkey: AuthenticationResponseJSON } = req.body;

    if (!message || !passkeyPubkey || passkey === undefined) {
      res.status(400).send({ error: "Invalid input" });
      return;
    }

    console.log({ message })

    // TODO: verify passkey by @simplewebauthn

    const messageBigInt = BigInt(`0x${message.replace(/^0x/, '')}`);
    const hm = getHm(messageBigInt);
    const privateKey = hexToBytes(config.dvtSecret);
    const { sigPoint, publicPoint } = getSignaturePoint(privateKey, hm);
    res.send(JSON.stringify({
      sig: {
        px: sigPoint.x.toString(),
        py: sigPoint.y.toString(),
      },
      pub: {
        px: {
          c0: publicPoint.px.c0.toString(),
          c1: publicPoint.px.c1.toString(),
        },
        py: {
          c0: publicPoint.py.c0.toString(),
          c1: publicPoint.py.c1.toString(),
        }
      }
    }));
  } catch (e) {
    next(e);
  }
});

app.get("/gen", async (req, res, next) => {
  const pks: string[] = [];
  const pubs: string[][] = []
  for (let i = 0; i < 5; i++) {
    const privateKey = bn254.utils.randomPrivateKey();
    const publicPoint = bn254.G2.ProjectivePoint.fromPrivateKey(privateKey);

    const pk = bytesToHex(privateKey);
    pks.push(pk);
    console.log({ pk });
    pubs.push([
      publicPoint.x.c0.toString(),
      publicPoint.x.c1.toString(),
    ])
  }

  res.send(JSON.stringify({ pks, pubs }));
})

app.post("/aggr", async (req, res, next) => {
  try {
    const { sigs, eoa, msg }: {
      sigs: Array<{
        sig: { px: string, py: string },
        pub: {
          px: { c0: string, c1: string },
          py: { c0: string, c1: string }
        }
      }>,
      eoa: string,
      msg: string
    } = req.body;

    const messageBigInt = BigInt(`0x${msg.replace(/^0x/, '')}`);
    const hm = getHm(messageBigInt);

    const { Fp2 } = bn254.fields;
    const pts = sigs.map(sig => ({
      sigPoint: bn254.G1.ProjectivePoint.fromAffine({
        x: BigInt(sig.sig.px),
        y: BigInt(sig.sig.py)
      }),
      publicPoint: bn254.G2.ProjectivePoint.fromAffine({
        x: Fp2.fromBigTuple([BigInt(sig.pub.px.c0), BigInt(sig.pub.px.c1)]),
        y: Fp2.fromBigTuple([BigInt(sig.pub.py.c0), BigInt(sig.pub.py.c1)])
      })
    }));

    const aggSignature = getAggSignature(pts.map(pt => pt.sigPoint));
    const blsSig = blsSignature(aggSignature, pts.map(pt => pt.publicPoint), hm);
    const sig = createSignature(eoa, blsSig);
    res.send(JSON.stringify({ sig }));
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
  console.log(`Server is running at http://localhost:${port}`);
});
