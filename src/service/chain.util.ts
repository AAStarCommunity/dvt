import { ethers } from "ethers";

const provider = new ethers.providers.JsonRpcProvider("http://localhost:8545");

const privateKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const wallet = new ethers.Wallet(privateKey, provider);

const contractAddress = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";
const contractABI = [
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

const contract = new ethers.Contract(contractAddress, contractABI, wallet);

export async function verifyAggrSigs(signature: string[2], pubkeys: string[4][], messages: any[]): Promise<boolean> {
    const result = await contract.validateAggregatorSignature(signature, pubkeys, messages);
    return result;
}