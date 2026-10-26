import {newOracle,type createOracle} from '../rabin/oracle';import {attack,chooseNegative} from '../attack/cca';import {verifyFactor} from '../verify/verify';import {unit} from '../gm/gm';
let oracle:ReturnType<typeof createOracle>|null=null;let lastCipher:bigint[]=[];
self.onmessage=({data})=>{const {id,name,args}=data;try{if(name==='keygen'){oracle=newOracle(Number(args.bits));lastCipher=[];self.postMessage({id,result:oracle.publicKey});return;}if(!oracle)throw Error('Generate a session key first.');const {N,z}=oracle.publicKey;let result:unknown;
 if(name==='gm'){const bits=String(args.bits);const c=oracle.encrypt(bits),again=oracle.encrypt(bits),flipped=c.map(v=>v*z%N);lastCipher=c;result={c,again,decrypted:oracle.decrypt(c),flipped,flippedPlain:oracle.decrypt(flipped),xor:oracle.decrypt(c.map((v,i)=>v*again[i]%N))};}
 else if(name==='roots'){const c=BigInt(args.c);result=oracle.rootEvidence(c);}
 else if(name==='rabin'){const m=BigInt(args.m),rule=args.rule,k=Number(args.k);const enc=rule==='canonical'?{m,c:oracle.canonicalEncrypt(m)}:oracle.redundancyEncrypt(m,k);result={...enc,roots:oracle.rootEvidence(enc.c),returned:oracle.query(enc.c,rule,k)};}
 else if(name==='onebit')result=oracle.oneBit(Number(args.bit));
 else if(name==='pick')result=chooseNegative(N);
 else if(name==='bginfo')result=oracle.bgInfo();
 else if(name==='bgdecrypt')result=oracle.bgDecrypt({blocks:(args.blocks as string[]),finalState:BigInt(args.finalState as string),bitLength:Number(args.bitLength)});
 else if(name==='bgprevious')result=oracle.bgPrevious(BigInt(args.x as string));
 else if(name==='bgtamperstates')result=oracle.bgTamperStates(BigInt(args.x as string));
 else if(name==='attack'){const r=attack(N,BigInt(args.x),c=>oracle!.query(c,args.rule,Number(args.k)));result={...r,recoveredPlain:r.factor&&verifyFactor(N,r.factor)?oracle.recoveredDecrypt(lastCipher,r.factor):null};}
 else if(name==='batch'){const count=Number(args.count);if(count<1||count>500)throw Error('Batch size 1–500');const rows=[];for(let i=0;i<count;i++)rows.push(attack(N,unit(N),c=>oracle!.query(c,args.rule,Number(args.k))));result=rows;}
 else throw Error('Unknown operation');self.postMessage({id,result});
 }catch(e){self.postMessage({id,error:e instanceof Error?e.message:String(e)});}};
