import { ethers } from "ethers";
import * as dotenv from "dotenv";
import * as fs from "fs";

import abi from './signature.verification.abi.json';

if (fs.existsSync('.env.local')) {
    dotenv.config({ path: '.env.local' });
  } else {
    dotenv.config();
  }

const rpc = process.env.RPC;
const provider = new ethers.providers.JsonRpcProvider(rpc);

const privateKey = process.env.KEY || "";
const wallet = new ethers.Wallet(privateKey, provider);

const contractAddress = process.env.ADD || "";

const contract = new ethers.Contract(contractAddress, abi, wallet);

export async function verifyAggrSigs(signature: string[2], pubkeys: string[4][], messages: any[]): Promise<boolean> {
    const result = await contract.validateAggregatorSignature(signature, pubkeys, messages);
    return result;
}


export async function callContractFunction() {
    try {
      // 调用合约的一个函数
      const result = await contract.getMessage();
      console.log("合约调用结果:", result);
    } catch (error) {
      console.error("合约调用失败:", error);
    }
  }