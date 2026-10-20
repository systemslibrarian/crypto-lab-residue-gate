export function mod(a:bigint,n:bigint):bigint{return ((a%n)+n)%n;}
export function gcd(a:bigint,b:bigint):bigint{a=a<0n?-a:a;b=b<0n?-b:b;while(b){[a,b]=[b,a%b];}return a;}
export function pow(a:bigint,e:bigint,n:bigint):bigint{if(n<1n||e<0n)throw Error('Positive modulus and non-negative exponent required.');let r=1n%n;a=mod(a,n);while(e){if(e&1n)r=r*a%n;a=a*a%n;e>>=1n;}return r;}
export function isqrt(n:bigint):bigint{if(n<0n)throw Error('Negative square root');if(n<2n)return n;let x=1n<<BigInt(Math.ceil(n.toString(2).length/2));for(;;){const y=(x+n/x)/2n;if(y>=x)return x;x=y;}}
export function perfectPower(n:bigint):{base:bigint;exponent:number}|null {if(n<4n)return null;for(let k=2;k<=n.toString(2).length;k++){let lo=2n,hi=1n<<BigInt(Math.ceil(n.toString(2).length/k));while(lo<=hi){const b=(lo+hi)/2n,v=b**BigInt(k);if(v===n)return {base:b,exponent:k};if(v<n)lo=b+1n;else hi=b-1n;}}return null;}
export type Fill = (bytes:Uint8Array<ArrayBuffer>)=>void;
export const systemRandom:Fill=bytes=>{crypto.getRandomValues(bytes);};
export function below(n:bigint,fill:Fill=systemRandom):bigint{if(n<1n)throw Error('Empty random range');const bits=n.toString(2).length,bytes=new Uint8Array(Math.ceil(bits/8)),mask=(1<<(bits%8||8))-1;for(;;){fill(bytes);bytes[0]&=mask;let x=0n;for(const b of bytes)x=(x<<8n)|BigInt(b);if(x<n)return x;}}
export function randomBase(n:bigint,fill:Fill=systemRandom):bigint{if(n<5n)throw Error('Random base needs n >= 5');return 2n+below(n-3n,fill);}
