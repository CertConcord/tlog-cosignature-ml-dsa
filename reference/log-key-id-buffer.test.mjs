import assert from 'node:assert/strict';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {types as utilTypes} from 'node:util';
import {assertCheckpointLogSignature} from './transport.mjs';

const vector=JSON.parse(readFileSync(new URL('../vectors/log-key-id-buffer.json',import.meta.url)));
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');

test('log structural gate vector fixes full checkpoint and ID bytes',()=>{
  assert.equal(Buffer.byteLength(vector.checkpointWire),vector.checkpointWireUtf8Bytes);
  assert.equal(digest(Buffer.from(vector.checkpointWire)),vector.checkpointWireSha256);
  const cut=vector.checkpointWire.indexOf('\n\n');
  assert.equal(Buffer.from(vector.checkpointWire.slice(0,cut+1)).toString('hex'),vector.checkpointBodyHex);
  assert.equal(digest(Buffer.from(vector.checkpointBodyHex,'hex')),vector.checkpointBodySha256);
  assert.equal(digest(Buffer.from(vector.logSpkiHex,'hex')),vector.logSpkiSha256);
  const payload=Buffer.from(vector.logSignaturePayloadHex,'hex');
  assert.equal(payload.length,68);
  assert.equal(payload.subarray(0,4).toString('hex'),vector.inputs.valid.hex);
  assert.equal(digest(payload),vector.logSignaturePayloadSha256);
  const key=createPublicKey({key:Buffer.from(vector.logSpkiHex,'hex'),type:'spki',format:'der'});
  assert.equal(verify(null,Buffer.from(vector.checkpointBodyHex,'hex'),key,payload.subarray(4)),true);
  for(const item of Object.values(vector.inputs)){
    assert.equal(Buffer.from(item.hex,'hex').length,item.bytes);
    assert.equal(digest(Buffer.from(item.hex,'hex')),item.sha256);
  }
});

for(const item of vector.cases){
  test(item.id,()=>{
    let keyID=Buffer.from(vector.inputs[item.input].hex,'hex');
    switch(item.decoration){
      case 'none': break;
      case 'length-2': Object.defineProperty(keyID,'length',{value:2}); break;
      case 'length-4': Object.defineProperty(keyID,'length',{value:4}); break;
      case 'length-throws': Object.defineProperty(keyID,'length',{get(){throw new Error('SHADOW_LOG_KEY_LENGTH_READ');}}); break;
      case 'byte-length-throws': Object.defineProperty(keyID,'byteLength',{get(){throw new Error('SHADOW_LOG_KEY_BYTE_LENGTH_READ');}}); break;
      case 'uint16-buffer-prototype': {
        const bytes=keyID;
        keyID=new Uint16Array(bytes.buffer.slice(bytes.byteOffset,bytes.byteOffset+bytes.byteLength));
        Object.setPrototypeOf(keyID,Buffer.prototype);
        Object.defineProperty(keyID,'length',{value:4});
        assert.equal(Buffer.isBuffer(keyID),true);
        assert.equal(utilTypes.isUint8Array(keyID),false);
        break;
      }
      case 'proxy': keyID=new Proxy(keyID,{}); break;
      case 'revoked-proxy': {
        const wrapped=Proxy.revocable(keyID,{});wrapped.revoke();keyID=wrapped.proxy;break;
      }
      default: throw new Error(item.decoration);
    }
    const evaluate=()=>assertCheckpointLogSignature(vector.checkpointWire,{name:vector.logName,keyID});
    if(item.expected==='VALID'){
      const cp=evaluate();
      assert.equal(cp.origin,vector.logName);
      assert.equal(Buffer.from(cp.body).toString('hex'),vector.checkpointBodyHex);
    } else assert.throws(evaluate,{code:item.expected});
  });
}
