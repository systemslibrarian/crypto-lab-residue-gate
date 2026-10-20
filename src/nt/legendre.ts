import {pow,mod} from './bigint';
export function legendre(a:bigint,p:bigint):number{if(p<3n||p%2n===0n)throw Error('Odd prime required');a=mod(a,p);if(a===0n)return 0;const v=pow(a,(p-1n)/2n,p);if(v===1n)return 1;if(v===p-1n)return -1;throw Error('Euler criterion failed: denominator is not prime.');}
