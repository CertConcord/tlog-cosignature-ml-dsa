import {createHash,createPublicKey,KeyObject,verify} from 'node:crypto';
import {types as utilTypes} from 'node:util';
const requireValue = (condition,code) => {if(!condition){const e=new Error(code);e.code=code;throw e;}};
const exactInteger = n => {requireValue(typeof n==='bigint'||(typeof n==='number'&&Number.isSafeInteger(n)),'SUBTREE_INTEGER');return BigInt(n);};
const u64 = n => {n=exactInteger(n);requireValue(n>=0n&&n<=0xffffffffffffffffn,'SUBTREE_INTEGER');const b=Buffer.alloc(8);b.writeBigUInt64BE(n);return b;};
const text = s => {requireValue(typeof s==='string'&&/^[\x21-\x2a\x2c-\x7e]{1,255}$/.test(s),'SUBTREE_NAME');const b=Buffer.from(s);return Buffer.concat([Buffer.from([b.length]),b]);};
export function mlDsa87KeyID(name,key) {
  text(name);
  const publicKey=key.type==='public'?key:createPublicKey(key);
  requireValue(publicKey.asymmetricKeyType==='ml-dsa-87','NOTE_KEY_SCHEME');
  return createHash('sha256').update(Buffer.concat([
    Buffer.from('certconcord/tlog-ml-dsa-87/v1\n'),Buffer.from(name+'\n'),
    publicKey.export({type:'spki',format:'der'}),
  ])).digest().subarray(0,4);
}
// The caller admits the candidates and selects this experimental profile first.
// A four-byte hint cannot establish trust or resolve a collision by itself.
export function selectMlDsa87Key(name,keyHint,candidates) {
  text(name);
  requireValue(Buffer.isBuffer(keyHint)&&keyHint.length===4,'NOTE_KEY_ID');
  requireValue(Array.isArray(candidates)&&!utilTypes.isProxy(candidates),'NOTE_KEY_CANDIDATES');
  const admittedHint=Buffer.from(keyHint);
  const count=candidates.length;
  requireValue(count<=64,'NOTE_KEY_CANDIDATES');
  const entries=[];
  for(let i=0;i<count;i++) {
    const slot=Object.getOwnPropertyDescriptor(candidates,i);
    requireValue(slot&&Object.hasOwn(slot,'value'),'NOTE_KEY_CANDIDATES');
    entries.push(slot.value);
  }
  const records=[];
  let accessorRecords=0;
  for(const candidate of entries) {
    requireValue(candidate&&typeof candidate==='object'&&!utilTypes.isProxy(candidate),'NOTE_KEY_CANDIDATES');
    const nameField=Object.getOwnPropertyDescriptor(candidate,'name');
    const keyField=Object.getOwnPropertyDescriptor(candidate,'publicKey');
    requireValue(nameField&&keyField,'NOTE_KEY_CANDIDATES');
    const accessor=!Object.hasOwn(nameField,'value')||!Object.hasOwn(keyField,'value');
    if(accessor)accessorRecords++;
    records.push({candidate,nameField,keyField,accessor});
  }
  requireValue(accessorRecords<=1,'NOTE_KEY_CANDIDATES');
  const fieldValue=(candidate,field) => {
    if(Object.hasOwn(field,'value'))return field.value;
    return field.get===undefined?undefined:Reflect.apply(field.get,candidate,[]);
  };
  let selected;
  for(const {candidate,nameField,keyField,accessor} of records) {
    const candidateName=fieldValue(candidate,nameField);
    requireValue(typeof candidateName==='string','NOTE_KEY_CANDIDATES');
    if(candidateName!==name)continue;
    const currentKeyField=accessor?Object.getOwnPropertyDescriptor(candidate,'publicKey'):keyField;
    requireValue(currentKeyField,'NOTE_KEY_CANDIDATES');
    const publicKey=fieldValue(candidate,currentKeyField);
    requireValue(publicKey instanceof KeyObject&&publicKey.type==='public','NOTE_KEY_CANDIDATES');
    if(publicKey.asymmetricKeyType!=='ml-dsa-87')continue;
    if(!mlDsa87KeyID(name,publicKey).equals(admittedHint))continue;
    requireValue(selected===undefined,'NOTE_KEY_AMBIGUOUS');
    selected=publicKey;
  }
  requireValue(selected!==undefined,'NOTE_KEY_UNKNOWN');
  return selected;
}
export function subtreeInput({name,origin,start=0n,end,root,timestamp=0}) {
  start=exactInteger(start);end=exactInteger(end);timestamp=exactInteger(timestamp);
  requireValue(start>=0n&&end>=start&&end<=0xffffffffffffffffn&&(!timestamp||start===0n),'SUBTREE_CONTEXT');
  let width=1n;while(width<end-start)width<<=1n;
  requireValue(start%width===0n&&Buffer.isBuffer(root)&&root.length===32,'SUBTREE_CONTEXT');
  return Buffer.concat([Buffer.from('subtree/v1\n\0'),text(name),u64(timestamp),text(origin),u64(start),u64(end),root]);
}
export function verifyCosignature(context,signature,key) {
  requireValue(key.asymmetricKeyType==='ml-dsa-87','NOTE_KEY_SCHEME');
  return Buffer.isBuffer(signature)&&signature.length===4627&&verify(null,subtreeInput(context),key,signature);
}
