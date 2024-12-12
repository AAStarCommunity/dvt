import { describe, it } from '@jest/globals';
import { BlsSignerFactory } from '@thehubbleproject/bls/dist/signer';
import { formatBytes32String, keccak256 } from "ethers/lib/utils";

describe('Signer Service', () => {
    describe('blsSign', () => {

        const DOMAIN = new Uint8Array([0])

        it('should be the same public key when domain and secret are the same', async () => {
            const factory = await BlsSignerFactory.new();
            const signer = factory.getSigner(DOMAIN, "0xabcd");

            const x0 = signer.pubkey[0];
            const x1 = signer.pubkey[1];
            const y0 = signer.pubkey[2];
            const y1 = signer.pubkey[3];

            const signer2 = (await BlsSignerFactory.new()).getSigner(DOMAIN, "0xabcd");

            const x02 = signer2.pubkey[0];
            const x12 = signer2.pubkey[1];
            const y02 = signer2.pubkey[2];
            const y12 = signer2.pubkey[3];

            expect(x0).toEqual(x02);
            expect(x1).toEqual(x12);
            expect(y0).toEqual(y02);
            expect(y1).toEqual(y12);
        });

        it('should the same domain but different secret verify each other   ', async () => {
            const factory = await BlsSignerFactory.new();
            const signer = factory.getSigner(DOMAIN, "0xabcd");
            const signer2 = (await BlsSignerFactory.new()).getSigner(DOMAIN, "0xabcd");

            const message = formatBytes32String("0x1234")
            const signature = signer.sign(message);
            const result = signer2.verify(signature, signer.pubkey, message);

            expect(result).toEqual(true);
        });
    });
});