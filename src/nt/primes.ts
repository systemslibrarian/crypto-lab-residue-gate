import {gcd,pow,randomBase,type Fill,systemRandom} from './bigint';
export interface Trace {n:bigint;a:bigint;s:number;d:bigint;chain:bigint[];composite:boolean;reason:string;factor:bigint|null;}
export function millerRabin(n:bigint,a:bigint):Trace{
 const out:Trace={n,a,s:0,d:n-1n,chain:[],composite:false,reason:'',factor:null};
 if(n<2n){out.composite=true;out.reason='Neither prime nor composite: n < 2';return out;}
 if(n===2n||n===3n){out.reason='Small proven prime';return out;}
 if(n%2n===0n){out.composite=true;out.reason='Even composite';out.factor=2n;return out;}
 if(a<1n||a>=n)throw Error('Base must be in [1, n−1].');
 while(out.d%2n===0n){out.d/=2n;out.s++;}
 const f=gcd(a,n);if(f>1n){out.composite=true;out.factor=f;out.reason='GCD witness';return out;}
 let x=pow(a,out.d,n);out.chain.push(x);
 if(x===1n){out.reason='No witness: chain starts at 1';return out;}
 if(x===n-1n){out.reason='No witness: chain starts at −1';return out;}
 for(let r=1;r<out.s;r++){
  const previous=x;x=x*x%n;out.chain.push(x);
  if(x===n-1n){out.reason='No witness: chain reaches −1';return out;}
  if(x===1n){const factor=gcd(previous-1n,n);out.composite=true;out.factor=factor>1n&&factor<n?factor:null;out.reason='Nontrivial square root of 1';return out;}
 }
 // A failed Fermat endpoint can prove compositeness without yielding a factor.
 out.composite=true;out.reason='Chain exhausted without 1 initially or −1';return out;
}
export function probablePrime(n:bigint,rounds:number,fill:Fill=systemRandom):{prime:boolean;bases:bigint[];witness:bigint|null}{
 if(!Number.isInteger(rounds)||rounds<1||rounds>128)throw Error('Rounds must be 1–128.');
 if(n<5n)return {prime:n===2n||n===3n,bases:[],witness:null};if(n%2n===0n)return {prime:false,bases:[],witness:2n};
 const bases:bigint[]=[];for(let i=0;i<rounds;i++){const a=randomBase(n,fill);bases.push(a);if(millerRabin(n,a).composite)return {prime:false,bases,witness:a};}return {prime:true,bases,witness:null};
}
// [extension] point: Lucas / Baillie–PSW, separate from this strong probable-prime test.
