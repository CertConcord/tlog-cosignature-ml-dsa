import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createPublicKey,generateKeyPairSync} from 'node:crypto';
import {mlDsa87KeyID,subtreeInput,verifyCosignature} from './extension.mjs';
const v=JSON.parse(readFileSync(new URL('../vectors/prefix.json',import.meta.url)));
const key=createPublicKey({key:Buffer.from(v.spki,'hex'),type:'spki',format:'der'});
const context={...v.context,root:Buffer.from(v.context.root,'hex')};
const signature=Buffer.from(v.signature,'hex');
test('published exact bytes and signature verify with the admitted key',()=>{
  assert.equal(subtreeInput(context).toString('hex'),v.input);
  assert.equal(mlDsa87KeyID(context.name,key).toString('hex'),v.keyHint);
  assert(verifyCosignature(context,signature,key));
});
test('each authenticated subtree field rejects substitution',()=>{
  for(const patch of [{name:'other'},{origin:'other'},{end:5},{timestamp:101},{root:Buffer.alloc(32)}])
    assert.equal(verifyCosignature({...context,...patch},signature,key),false);
  const corrupted=Buffer.from(signature);corrupted[0]^=1;
  assert.equal(verifyCosignature(context,corrupted,key),false);
  assert.throws(()=>subtreeInput({...context,start:1}),{code:'SUBTREE_CONTEXT'});
  const other=generateKeyPairSync('ml-dsa-44').publicKey;
  assert.throws(()=>verifyCosignature(context,signature,other),{code:'NOTE_KEY_SCHEME'});
});
