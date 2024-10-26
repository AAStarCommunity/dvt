import { ethers } from "ethers";
import * as dotenv from "dotenv";
import * as fs from "fs";

import abi from './signature.verification.abi.json';

const abi2 = [
    {
        "inputs": [
            {
                "internalType": "string",
                "name": "_message",
                "type": "string"
            }
        ],
        "stateMutability": "nonpayable",
        "type": "constructor"
    },
    {
        "inputs": [],
        "name": "getMessage",
        "outputs": [
            {
                "internalType": "string",
                "name": "",
                "type": "string"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "message",
        "outputs": [
            {
                "internalType": "string",
                "name": "",
                "type": "string"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "string",
                "name": "_message",
                "type": "string"
            }
        ],
        "name": "setMessage",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "uint256[2]",
                "name": "signature",
                "type": "uint256[2]"
            },
            {
                "internalType": "uint256[4][]",
                "name": "pubkeys",
                "type": "uint256[4][]"
            },
            {
                "internalType": "uint256[2][]",
                "name": "messages",
                "type": "uint256[2][]"
            }
        ],
        "name": "validateAggregatorSignature",
        "outputs": [
            {
                "internalType": "bool",
                "name": "",
                "type": "bool"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
];

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

const contract = new ethers.Contract(contractAddress, abi2, wallet);

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