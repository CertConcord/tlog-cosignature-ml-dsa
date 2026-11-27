import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync} from 'node:fs';

const sourcePath=process.argv[2]??new URL('../vectors/transport.json',import.meta.url);
const outputPath=process.argv[3]??new URL('../vectors/log-key-id-buffer.json',import.meta.url);
const source=JSON.parse(readFileSync(sourcePath));
const selected=source.cases.find(item=>item.id==='log-checkpoint');
if(!selected||selected.operation!=='log'||selected.expected!=='VALID')throw new Error('missing fixed log checkpoint');
const wire=selected.wire;
const split=wire.indexOf('\n\n');
if(split<0)throw new Error('checkpoint separator');
const body=wire.slice(0,split+1);
const digest=data=>createHash('sha256').update(data).digest('hex');
const keyID=Buffer.from(source.log.keyHint,'hex');
if(keyID.length!==4)throw new Error('expected four-byte log key hint');
const logLine=wire.split('\n').find(line=>line.startsWith('— '+source.log.name+' '));
if(!logLine)throw new Error('missing log signature line');
const logPayload=Buffer.from(logLine.slice(('— '+source.log.name+' ').length),'base64');
if(!logPayload.subarray(0,4).equals(keyID)||logPayload.length!==68)throw new Error('unexpected log payload');
const values={valid:keyID,short:keyID.subarray(0,2),long:Buffer.concat([keyID,Buffer.from('5a5a','hex')]),
  wrong:Buffer.from('5a5a5a5a','hex'),disguised:Buffer.from('5a5a5a5a','hex')};
const inputs=Object.fromEntries(Object.entries(values).map(([name,bytes])=>[name,{hex:bytes.toString('hex'),bytes:bytes.length,sha256:digest(bytes)}]));
const cases=[
  ['log-key-id-plain','valid','none','VALID'],
  ['log-key-id-shadow-length-2','valid','length-2','VALID'],
  ['log-key-id-shadow-length-throws','valid','length-throws','VALID'],
  ['log-key-id-shadow-byte-length-throws','valid','byte-length-throws','VALID'],
  ['log-key-id-native-short-spoof','short','length-4','CHECKPOINT_LOG_KEY'],
  ['log-key-id-native-long-spoof','long','length-4','CHECKPOINT_LOG_KEY'],
  ['log-key-id-uint16-buffer-prototype','disguised','uint16-buffer-prototype','CHECKPOINT_LOG_KEY'],
  ['log-key-id-proxy','valid','proxy','CHECKPOINT_LOG_KEY'],
  ['log-key-id-revoked-proxy','valid','revoked-proxy','CHECKPOINT_LOG_KEY'],
  ['log-key-id-wrong-four-bytes','wrong','none','CHECKPOINT_LOG_SIGNATURE_REQUIRED'],
].map(([id,input,decoration,expected])=>({id,input,decoration,expected}));
const vector={schemaVersion:1,profile:'C2SP-20261007-MLDSA87-v2',sourceCase:'vectors/transport.json#log-checkpoint',
  logName:source.log.name,logSpkiHex:source.log.spki,logSpkiSha256:digest(Buffer.from(source.log.spki,'hex')),
  logSignaturePayloadHex:logPayload.toString('hex'),logSignaturePayloadSha256:digest(logPayload),
  checkpointWire:wire,checkpointWireUtf8Bytes:Buffer.byteLength(wire),checkpointWireSha256:digest(Buffer.from(wire)),
  checkpointBodyHex:Buffer.from(body).toString('hex'),checkpointBodySha256:digest(Buffer.from(body)),inputs,cases};
writeFileSync(outputPath,JSON.stringify(vector,null,2)+'\n');
console.log(`Log key ID bytes: ${cases.length} cases, ${Buffer.byteLength(wire)} checkpoint bytes`);
