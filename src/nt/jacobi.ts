// HAC Algorithm 2.149. The denominator alone is sufficient; no key or factor import.
export function jacobi(a:bigint,n:bigint):number{
 if(n<=1n||n%2n===0n)throw Error('Jacobi requires an odd denominator greater than 1.');a=((a%n)+n)%n;let sign=1;
 while(a!==0n){while(a%2n===0n){a/=2n;const r=n%8n;if(r===3n||r===5n)sign=-sign;}[a,n]=[n,a];if(a%4n===3n&&n%4n===3n)sign=-sign;a%=n;}
 return n===1n?sign:0;
}
// [extension] point: Cocks IBE uses this public symbol computation.
