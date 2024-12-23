import { describe, it } from '@jest/globals';
import {encodeBytes32String} from "ethers"

describe('Signer Service', () => {
    describe('blsSign', () => {

        const DOMAIN = new Uint8Array([0])

        it('should be the same public key when domain and secret are the same', async () => {
            
        });

        it('should the same domain but different secret verify each other   ', async () => {
            
        });
    });
});