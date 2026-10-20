// Independent final checks. This module imports no scheme, oracle, attack or nt implementation.
export function verifyFactor(N:bigint,p:bigint):boolean{return p>1n&&p<N&&N%p===0n&&p*(N/p)===N;}
export function verifyRoot(N:bigint,c:bigint,r:bigint):boolean{return r>0n&&r<N&&r*r%N===c;}
