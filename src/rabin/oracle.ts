import {gcd,below} from '../nt/bigint';import {jacobi} from '../nt/jacobi';import {probablePrime} from '../nt/primes';import {fourRoots} from '../nt/sqrt';import {unit,encryptGM,decryptGM} from '../gm/gm';import {canonicalRoot,redundancyRoot,encodeRedundancy,validateUnit} from './rabin';
import {blockSizes,decryptBG,makeBlumKey,previousState,type BGCiphertext,type BlumKey} from '../bbs/bbs';
export function createOracle(p:bigint,q:bigint){
 if(p===q)throw Error('Blum primes must be distinct.');if(p%4n!==3n||q%4n!==3n)throw Error('Both Blum primes must be 3 modulo 4.');if(!probablePrime(p,40).prime||!probablePrime(q,40).prime)throw Error('Factors failed primality testing.');
 const N=p*q;let z:bigint;do{z=unit(N);}while(jacobi(z,p)!==-1||jacobi(z,q)!==-1);
 let bg:(BlumKey&{sevenMod8:boolean})|null=null;const bgKey=()=>bg??=makeBlumKey(p,q);
 // p and q are held only by these trusted key-holder closures, never sent to the attacker.
 return {publicKey:{N,z,bits:N.toString(2).length},query:(c:bigint,rule:'canonical'|'redundancy',k=32)=>rule==='canonical'?canonicalRoot(c,p,q):redundancyRoot(c,p,q,k),
 encrypt:(bits:string)=>encryptGM(bits,N,z),decrypt:(c:bigint[])=>decryptGM(c,p,q),
 rootEvidence:(c:bigint)=>fourRoots(c,p,q).map(r=>({root:r,jp:jacobi(r,p),jq:jacobi(r,q)})),
 // A-D-13. The Blum–Goldwasser key is built on first use: createOracle has already
 // proved p and q prime, and rebuilding it eagerly would repeat that work at keygen.
 // Only the key-holder side lives here. Encryption and the public forward walk need
 // nothing but N and run on the main thread, which is what makes that boundary real.
 bgDecrypt:(cipher:BGCiphertext)=>decryptBG(cipher,bgKey()),
 bgPrevious:(x:bigint)=>previousState(x,p,q),
 bgInfo:()=>({...blockSizes(N),sevenMod8:bgKey().sevenMod8}),
 bgTamperStates:(x:bigint)=>{let rejected:bigint|null=null,accepted:bigint|null=null;for(let delta=1n;delta<=4096n&&(rejected===null||accepted===null);delta++){const y=(x+delta)%N;if(y===x)continue;const qr=gcd(y,N)===1n&&jacobi(y,p)===1&&jacobi(y,q)===1;if(qr)accepted??=y;else rejected??=y;}if(rejected===null||accepted===null)throw Error('Could not find both final-state teaching controls within the bounded search.');return {rejected,accepted};},

 canonicalEncrypt:(m:bigint)=>{validateUnit(m,N);if(jacobi(m,p)!==1||jacobi(m,q)!==1)throw Error('Canonical messages must lie in QR_N.');return m*m%N;},
 redundancyEncrypt:(payload:bigint,k:number)=>{const m=encodeRedundancy(payload,k,N);return {m,c:m*m%N};},
 oneBit:(bit:number)=>{if(bit!==0&&bit!==1)throw Error('Bit must be 0 or 1');const r=unit(N),x=r*r%N,c=x*x%N,masked=Number(x&1n)^bit,root=canonicalRoot(c,p,q);return {c,masked,decrypted:masked^Number(root&1n)};},
 recoveredDecrypt:(cipher:bigint[],factor:bigint)=>{if(factor<=1n||factor>=N||N%factor)throw Error('Invalid recovered factor');return decryptGM(cipher,factor,N/factor);}
 };
}
export function makeBlumPrime(bits:number):bigint{if(bits<8||bits>1024)throw Error('Prime size outside range');for(;;){const p=(3n<<BigInt(bits-2))|below(1n<<BigInt(bits-2))|3n;if(probablePrime(p,40).prime)return p;}}
export function newOracle(bits=2048){if(bits!==2048&&bits!==16)throw Error('Supported modulus sizes: 2048,16');if(bits===16)return createOracle(19n,23n);const p=makeBlumPrime(bits/2);let q:bigint;do{q=makeBlumPrime(bits/2);}while(q===p||gcd(q,p)!==1n);return createOracle(p,q);}
// The BBS / Blum–Goldwasser exhibit (A-D-13) reuses exactly this Blum generation.
