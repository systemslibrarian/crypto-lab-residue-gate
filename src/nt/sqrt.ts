import {pow,mod} from './bigint';import {legendre} from './legendre';
export function inverse(a:bigint,n:bigint):bigint{let r=n,s=mod(a,n),u=0n,v=1n;while(s){const q=r/s;[r,s]=[s,r-q*s];[u,v]=[v,u-q*v];}if(r!==1n)throw Error('No inverse');return mod(u,n);}
export function crt(a:bigint,p:bigint,b:bigint,q:bigint):bigint{return mod(a+p*mod((b-a)*inverse(p,q),q),p*q);}
export function sqrtPrime(a:bigint,p:bigint){a=mod(a,p);const trace:{x:bigint;t:bigint;m:number}[]=[];if(a===0n)return {root:0n,trace,method:'zero'};if(legendre(a,p)!==1)throw Error('Not a square modulo p.');if(p%4n===3n){const root=pow(a,(p+1n)/4n,p);return {root,trace:[{x:root,t:1n,m:0}],method:'p ≡ 3 mod 4 shortcut'};}
 // Tonelli–Shanks: halve the remaining power-of-two order; HAC Algorithm 3.34.
 let d=p-1n,s=0;while(d%2n===0n){d/=2n;s++;}let z=2n;while(legendre(z,p)!==-1)z++;let c=pow(z,d,p),x=pow(a,(d+1n)/2n,p),t=pow(a,d,p),m=s;trace.push({x,t,m});
 while(t!==1n){let i=1,u=t*t%p;while(u!==1n&&i<m){u=u*u%p;i++;}if(i>=m)throw Error('Square-root invariant failed');const b=pow(c,1n<<BigInt(m-i-1),p);x=x*b%p;t=t*b%p*b%p;c=b*b%p;m=i;trace.push({x,t,m});}if(x*x%p!==a)throw Error('Square-back failed');return {root:x,trace,method:'Tonelli–Shanks order-halving'};
}
export function fourRoots(c:bigint,p:bigint,q:bigint):bigint[]{const a=sqrtPrime(c,p).root,b=sqrtPrime(c,q).root,N=p*q;return [...new Set([crt(a,p,b,q),crt(a,p,mod(-b,q),q),crt(mod(-a,p),p,b,q),crt(mod(-a,p),p,mod(-b,q),q)])].sort((a,b)=>a<b?-1:1).map(x=>{if(x*x%N!==c)throw Error('Root verification failed');return x;});}
