import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync} from 'node:fs';

const prefixPath=process.argv[2]??new URL('../vectors/prefix.json',import.meta.url);
const outputPath=process.argv[3]??new URL('../vectors/signature-verify-buffer.json',import.meta.url);
const prefix=JSON.parse(readFileSync(prefixPath));
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const signature=Buffer.from(prefix.signature,'hex');
if(signature.length!==4627)throw new Error('expected frozen ML-DSA-87 signature');
const corrupted=Buffer.from(signature);corrupted[0]^=1;
const values={valid:signature,corrupted,short:Buffer.alloc(16,0x5a),long:Buffer.alloc(4630,0x5a),disguised:Buffer.alloc(4628,0x5a)};
const inputs=Object.fromEntries(Object.entries(values).map(([name,bytes])=>[name,{hex:bytes.toString('hex'),bytes:bytes.length,sha256:digest(bytes)}]));
const cases=[
  ['verify-signature-plain','valid','none',true],
  ['verify-signature-shadow-length-16','valid','length-16',true],
  ['verify-signature-shadow-length-throws','valid','length-throws',true],
  ['verify-signature-shadow-byte-length-throws','valid','byte-length-throws',true],
  ['verify-signature-corrupted','corrupted','none',false],
  ['verify-signature-native-short-spoof','short','length-4627',false],
  ['verify-signature-native-long-spoof','long','length-4627',false],
  ['verify-signature-uint16-buffer-prototype','disguised','uint16-buffer-prototype',false],
  ['verify-signature-proxy','valid','proxy',false],
  ['verify-signature-revoked-proxy','valid','revoked-proxy',false],
].map(([id,input,decoration,verified])=>({id,input,decoration,expected:verified?'VALID':'VERIFY_FALSE',verified}));
const vector={schemaVersion:1,profile:'CERTCONCORD-MLDSA87-SUBTREE-v1',sourceCase:'vectors/prefix.json',context:prefix.context,
  selectedSpkiHex:prefix.spki,selectedSpkiSha256:digest(Buffer.from(prefix.spki,'hex')),
  signedInputHex:prefix.input,signedInputSha256:digest(Buffer.from(prefix.input,'hex')),
  inputs,cases};
writeFileSync(outputPath,JSON.stringify(vector,null,2)+'\n');
console.log(`Signature verification bytes: ${cases.length} cases, ${Object.keys(inputs).length} input byte strings`);
