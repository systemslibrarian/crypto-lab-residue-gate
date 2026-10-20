import {gcd} from '../nt/bigint';import {jacobi} from '../nt/jacobi';import {fourRoots} from '../nt/sqrt';
export function validateUnit(c:bigint,N:bigint):void{if(c<=0n||c>=N)throw Error('Use a value strictly between 0 and N.');if(gcd(c,N)!==1n)throw Error('Not a unit: gcd already reveals a factor of N.');}
export function canonicalRoot(c:bigint,p:bigint,q:bigint):bigint{validateUnit(c,p*q);const roots=fourRoots(c,p,q).filter(r=>jacobi(r,p)===1&&jacobi(r,q)===1);if(roots.length!==1)throw Error('No unique QR root; the ciphertext is not a square.');return roots[0];}
export function encodeRedundancy(payload:bigint,k:number,N:bigint):bigint{if(k<1||k>64)throw Error('Redundancy width must be 1–64 bits');const m=(payload<<BigInt(k))|(payload&((1n<<BigInt(k))-1n));validateUnit(m,N);return m;}
export function hasRedundancy(m:bigint,k:number):boolean{const mask=(1n<<BigInt(k))-1n;return (m&mask)===((m>>BigInt(k))&mask);}
export function redundancyRoot(c:bigint,p:bigint,q:bigint,k:number):bigint{validateUnit(c,p*q);const roots=fourRoots(c,p,q).filter(r=>hasRedundancy(r,k));if(roots.length===0)throw Error('Refused — no root carries the redundancy');if(roots.length!==1)throw Error('Refused — multiple roots carry the redundancy');return roots[0];}
// [extension] point: Rabin–Williams signatures and proven CCA padding are separate schemes.
