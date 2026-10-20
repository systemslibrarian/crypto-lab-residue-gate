import {gcd} from '../nt/bigint';import {jacobi} from '../nt/jacobi';import {verifyFactor,verifyRoot} from '../verify/verify';
export type Query=(c:bigint)=>bigint;
// Receives only the public modulus and oracle return. No private-key import.
export function attack(N:bigint,x:bigint,query:Query){if(x<=0n||x>=N||gcd(x,N)!==1n)throw Error('Choose x in Z*_N.');const c=x*x%N;try{const m=query(c);if(!verifyRoot(N,c,m))throw Error('Oracle returned an invalid root');const f=gcd(m-x,N);return {x,c,m,jacobi:jacobi(x,N),factor:verifyFactor(N,f)?f:null,refusal:null};}catch(e){return {x,c,m:null,jacobi:jacobi(x,N),factor:null,refusal:e instanceof Error?e.message:String(e)};}}
export function chooseNegative(N:bigint):bigint{for(let x=2n;x<N-1n;x++)if(jacobi(x,N)===-1&&gcd(x,N)===1n)return x;throw Error('No Jacobi-negative unit found.');}
