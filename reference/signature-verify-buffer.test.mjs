import assert from 'node:assert/strict';
import {createHash,createPublicKey} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {types as utilTypes} from 'node:util';
import {subtreeInput,verifyCosignature} from './extension.mjs';

const vector=JSON.parse(readFileSync(new URL('../vectors/signature-verify-buffer.json',import.meta.url)));
const key=createPublicKey({key:Buffer.from(vector.selectedSpkiHex,'hex'),type:'spki',format:'der'});
const context={...vector.context,root:Buffer.from(vector.context.root,'hex')};
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');

test('direct verifier vector fixes admitted SPKI, signed input and signature bytes',()=>{
  const spki=Buffer.from(vector.selectedSpkiHex,'hex');
  assert.equal(digest(spki),vector.selectedSpkiSha256);
  assert.equal(subtreeInput(context).toString('hex'),vector.signedInputHex);
  assert.equal(digest(subtreeInput(context)),vector.signedInputSha256);
  assert.equal(vector.inputs.valid.bytes,4627);
  for(const item of Object.values(vector.inputs)){
    assert.equal(Buffer.from(item.hex,'hex').length,item.bytes);
    assert.equal(digest(Buffer.from(item.hex,'hex')),item.sha256);
  }
});

for(const item of vector.cases){
  test(item.id,()=>{
    let signature=Buffer.from(vector.inputs[item.input].hex,'hex');
    switch(item.decoration){
      case 'none': break;
      case 'length-16': Object.defineProperty(signature,'length',{value:16}); break;
      case 'length-4627': Object.defineProperty(signature,'length',{value:4627}); break;
      case 'length-throws': Object.defineProperty(signature,'length',{get(){throw new Error('SHADOW_LENGTH_READ');}}); break;
      case 'byte-length-throws': Object.defineProperty(signature,'byteLength',{get(){throw new Error('SHADOW_BYTE_LENGTH_READ');}}); break;
      case 'uint16-buffer-prototype': {
        const bytes=signature;
        signature=new Uint16Array(bytes.buffer.slice(bytes.byteOffset,bytes.byteOffset+bytes.byteLength));
        Object.setPrototypeOf(signature,Buffer.prototype);
        Object.defineProperty(signature,'length',{value:4627});
        assert.equal(Buffer.isBuffer(signature),true);
        assert.equal(utilTypes.isUint8Array(signature),false);
        break;
      }
      case 'proxy': signature=new Proxy(signature,{}); break;
      case 'revoked-proxy': {
        const wrapped=Proxy.revocable(signature,{});wrapped.revoke();signature=wrapped.proxy;break;
      }
      default: throw new Error(item.decoration);
    }
    assert.equal(verifyCosignature(context,signature,key),item.verified);
  });
}
