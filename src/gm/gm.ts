import {gcd,below} from '../nt/bigint';import {jacobi} from '../nt/jacobi';
export function unit(N:bigint):bigint{for(;;){const r=1n+below(N-1n);if(gcd(r,N)===1n)return r;}}
export function encryptGM(bits:string,N:bigint,z:bigint):bigint[]{if(!/^[01]*$/.test(bits))throw Error('GM accepts only a bit string, possibly empty.');if(N<3n||z<=0n||z>=N||jacobi(z,N)!==1)throw Error('Invalid GM public key');return [...bits].map(b=>{const r=unit(N);return r*r%N*(b==='1'?z:1n)%N;});}
export function decryptGM(cipher:bigint[],p:bigint,q:bigint):string{const N=p*q;return cipher.map(c=>{if(c<=0n||c>=N||gcd(c,N)!==1n)throw Error('GM ciphertext must be a unit');const symbol=jacobi(c,p);return symbol===1?'0':'1';}).join('');}
