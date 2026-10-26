import {test,expect,type Page} from '@playwright/test';import {boot} from './gate';
async function toy(page:Page){await boot(page);await page.locator('#key-size').selectOption('16');await page.getByRole('button',{name:'Generate session key',exact:true}).click();await expect(page.locator('[data-key-N]')).toHaveAttribute('data-key-N','437');}
const gcd=(a:bigint,b:bigint):bigint=>b?gcd(b,a%b):a<0n?-a:a;
test('canonical oracle returns a verified different root and factor',async({page})=>{await toy(page);await page.getByRole('tab',{name:/Break the oracle/}).click();await page.locator('#oracle-rule').selectOption('canonical');await page.getByRole('button',{name:'Send x² to the oracle'}).click();const row=page.locator('[data-factor]');await expect(row).toBeAttached();const N=BigInt((await row.getAttribute('data-N'))!),x=BigInt((await row.getAttribute('data-x'))!),m=BigInt((await row.getAttribute('data-m'))!),f=BigInt((await row.getAttribute('data-factor'))!);expect(m*m%N).toBe(x*x%N);await expect(page.locator('#attack-out .metric strong').nth(1)).toHaveText('-1');expect(gcd(m-x,N)).toBe(f);expect(f*(N/f)).toBe(N);await expect(page.locator('[data-verdict=cca-negative]')).toContainText('One-wayness equivalent to factoring does not provide chosen-ciphertext security.');await page.locator('#x').fill('3');await expect(row).toHaveCount(0);await expect(page.locator('#attack-out')).toContainText('Retired: inputs changed');});
test('redundancy refuses the verified fixture without claiming CCA security',async({page})=>{await toy(page);await page.getByRole('tab',{name:/Break the oracle/}).click();await expect(page.locator('#oracle-rule')).toHaveValue('redundancy');await page.getByRole('button',{name:'Send x² to the oracle'}).click();await expect(page.locator('[data-verdict=cca-outcome]')).toContainText('no root carries the redundancy');await expect(page.locator('#panel')).toContainText('not every possible attack');});
test('GM decrypts valid ciphertexts and the flipped bits',async({page})=>{await toy(page);await page.getByRole('tab',{name:/Encrypt bits/}).click();await page.getByRole('button',{name:'Encrypt twice, then flip'}).click();await expect(page.locator('[data-gm-plain]')).toHaveText('1010');const rows=page.locator('#gm-out tbody tr');await expect(rows).toHaveCount(4);expect(await rows.locator('td:last-child').allTextContents()).toEqual(['0','1','0','1']);await expect(page.locator('[data-verdict=gm-negative]')).toContainText('does not stop anyone flipping it');});
test('Rabin roots and returned redundant message square back',async({page})=>{await toy(page);await page.getByRole('tab',{name:/Four roots/}).click();await page.getByRole('button',{name:'Encrypt and decrypt',exact:true}).click();await expect(page.locator('[data-verdict=rabin]')).toBeVisible();const rows=await page.locator('#rabin-out tbody tr').allTextContents();expect(rows).toHaveLength(4);for(const row of await page.locator('#rabin-out tbody tr').all()){const cells=await row.locator('td').allTextContents();expect(BigInt(cells[0])**2n%437n).toBe(BigInt(cells[1]));}});
test('game tally equals its recorded answers',async({page})=>{await boot(page);await page.getByRole('tab',{name:/Jacobi’s blind spot/}).click();await page.getByRole('button',{name:'Guess square',exact:true}).click();const cells=await page.locator('#guess-out tbody tr td').allTextContents();expect(cells.length).toBe(4);const right=cells[3]==='yes'?1:0;await expect(page.locator('#guess-out .metric strong')).toHaveText(right+' / 1');await page.getByRole('button',{name:'Guess square',exact:true}).click();await expect(page.locator('#guess-out tbody tr')).toHaveCount(1);});
test('roots verify before display and input rejection is explicit',async({page})=>{await boot(page);await expect(page.locator('[data-verdict=roots]')).toContainText('ROOTS VERIFIED');await page.locator('#a').fill('2');await page.getByRole('button',{name:'Find roots',exact:true}).click();await expect(page.locator('#prime-out')).toContainText('Not a square');await page.locator('#a').fill('bad');await page.getByRole('button',{name:'Find roots',exact:true}).click();await expect(page.locator('#prime-out')).toContainText('Input refused');});

// ---------------------------------------------------------------------------
// A-D-13. Every assertion below recomputes the displayed value from the PUBLIC
// inputs (N from the key badge, the seed and the message typed into the page)
// with arithmetic written here, never by calling the app's own helpers.
// ---------------------------------------------------------------------------
const refSquare=(x:bigint,n:bigint):bigint=>x*x%n;
function refChain(seed:bigint,n:bigint,count:number):bigint[]{const out:bigint[]=[];let x=refSquare(seed,n);for(let i=0;i<count;i++){x=refSquare(x,n);out.push(x);}return out;}
function refLow(x:bigint,h:number):string{let s='';for(let b=h-1;b>=0;b--)s+=String((x>>BigInt(b))&1n);return s;}
function refXor(a:string,b:string):string{return [...a].map((c,i)=>String(Number(c)^Number(b[i]))).join('');}
async function stream(page:Page,bits='1001110000010000',seed='5'){await toy(page);await page.getByRole('tab',{name:/Rewind the stream/}).click();await page.locator('#bg-seed-mode').selectOption('manual');await page.locator('#bg-bits').fill(bits);await page.locator('#bg-seed').fill(seed);await page.getByRole('button',{name:'Encrypt',exact:true}).click();await expect(page.locator('[data-bg-final]')).toBeAttached();}
async function teachingRows(page:Page){return Promise.all((await page.getByRole('region',{name:'Sender state-chain calculation'}).locator('tbody tr').all()).map(async r=>r.locator('td').allTextContents()));}

test('BBS stream encrypt matches an independent chain and block extraction',async({page})=>{
 const message='1001110000010000';await stream(page,message,'5');
 const N=BigInt((await page.locator('[data-key-N]').getAttribute('data-key-N'))!);expect(N).toBe(437n);
 const h=3;const rows=await teachingRows(page);
 const chain=refChain(5n,N,rows.length);
 expect(rows.length).toBe(Math.ceil(message.length/h));
 let plain='';
 for(let i=0;i<rows.length;i++){
  expect(BigInt(rows[i][1])).toBe(chain[i]);                       // state x_i
  expect(rows[i][2]).toBe(refLow(chain[i],h));                     // keystream p_i
  const piece=message.slice(i*h,(i+1)*h);
  expect(rows[i][3]).toBe(refXor(piece,refLow(chain[i],h).slice(0,piece.length)));
  plain+=refXor(rows[i][3],refLow(chain[i],h).slice(0,rows[i][3].length));
 }
 expect(plain).toBe(message);
 // The transmitted state is one squaring past the last emitting state.
 const final=BigInt((await page.locator('[data-bg-final]').getAttribute('data-bg-final'))!);
 expect(final).toBe(refSquare(chain[chain.length-1],N));
 // A short final block is kept, not padded away.
 expect(rows[rows.length-1][3].length).toBe(message.length-h*(rows.length-1));
});

test('the factors rewind the transmitted state back to the seed state',async({page})=>{
 const message='1001110000010000';await stream(page,message,'5');
 const N=BigInt((await page.locator('[data-key-N]').getAttribute('data-key-N'))!);
 await page.getByRole('button',{name:'Decrypt with the factors'}).click();
 await expect(page.locator('[data-verdict=bg-decrypt]')).toContainText('DECRYPTED — the rewind landed on x₀');
 const out=page.locator('#bg-out');
 await expect(out).toContainText(message);
 await expect(out).toContainText('Matches the message sent');
 // The recovered seed state must be r² mod N, recomputed here.
 const metrics=await out.locator('.metric').allTextContents();
 expect(metrics.some(m=>m.includes(String(refSquare(5n,N))))).toBe(true);
});

test('state disclosure exposes its current block and every later wire block',async({page})=>{
 const message='1001110000010000';await stream(page,message,'5');
 const N=BigInt((await page.locator('[data-key-N]').getAttribute('data-key-N'))!);const h=3;
 await page.getByRole('button',{name:'Disclose x₂'}).click();
 const verdictBox=page.locator('[data-verdict=bg-disclosed]');
 await expect(verdictBox).toContainText('CURRENT AND SUBSEQUENT OUTPUT IS EXPOSED');
 const disclosure=page.locator('[data-bg-disclosed]');
 const disclosed=BigInt((await disclosure.getAttribute('data-bg-disclosed'))!);
 const first=Number(await disclosure.getAttribute('data-bg-disclosure-first'));
 expect(first).toBe(2);
 const rows=await page.getByRole('region',{name:'Transmitted ciphertext blocks'}).locator('tbody tr td:last-child').allTextContents();
 const blocks=rows.slice(first-1);
 const keys:string[]=[];let x=disclosed;
 for(let i=0;i<blocks.length;i++){keys.push(refLow(x,h));x=refSquare(x,N);}
 const recovered=blocks.map((b,i)=>refXor(b,keys[i].slice(0,b.length))).join('');
 expect(recovered).toBe(message.slice(h));
 expect(await disclosure.getAttribute('data-bg-disclosure-recovered')).toBe(recovered);
 await expect(disclosure).toHaveAttribute('data-bg-cycle',/28 forward squarings/);
 await expect(verdictBox).toContainText('not an information-theoretic promise');
});

test('flipping one ciphertext bit flips one plaintext bit and is not detected',async({page})=>{
 const message='1001110000010000';await stream(page,message,'5');
 await page.getByRole('button',{name:'Apply one-bit mutation'}).click();
 await page.getByRole('button',{name:'Apply one-bit mutation'}).click(); // idempotent scenario, not a toggle
 await expect(page.locator('[data-verdict=bg-tampered]')).toContainText('no authentication');
 await page.getByRole('button',{name:'Decrypt with the factors'}).click();
 await expect(page.locator('[data-verdict=bg-decrypt]')).toContainText('DECRYPTED TO A CHANGED MESSAGE');
 const flipped=String(1-Number(message[0]))+message.slice(1);
 await expect(page.locator('#bg-out')).toContainText(flipped);
 // Exactly one bit differs, and nothing rejected the ciphertext.
 expect([...flipped].filter((c,i)=>c!==message[i]).length).toBe(1);
 await expect(page.locator('[data-verdict=bg-decrypt]')).toContainText('nothing to reject with');
});

test('final-state validity rejection and accepted valid-residue tampering stay distinct',async({page})=>{
 await stream(page,'1001110000010000','5');
 await page.getByRole('button',{name:'Use a non-QR final state'}).click();
 await expect(page.locator('[data-bg-final]')).toHaveAttribute('data-bg-final','37');
 await page.getByRole('button',{name:'Decrypt with the factors'}).click();
 await expect(page.locator('[data-verdict=bg-validity-refusal]')).toContainText('not sender authentication');
 await page.getByRole('button',{name:'Use an altered valid-QR final state'}).click();
 await expect(page.locator('[data-bg-final]')).toHaveAttribute('data-bg-final','39');
 await page.getByRole('button',{name:'Decrypt with the factors'}).click();
 await expect(page.locator('[data-verdict=bg-decrypt]')).toContainText('DECRYPTED TO A CHANGED MESSAGE');
 await expect(page.locator('[data-verdict=bg-decrypt]')).toContainText('did not authenticate a sender');
});

test('an invalid seed is refused by name and retires the stream result',async({page})=>{
 await stream(page,'1001110000010000','5');
 await page.locator('#bg-seed').fill('19');          // 19 divides 437
 await expect(page.locator('#bg-out')).toContainText('Retired: inputs changed');
 await page.getByRole('button',{name:'Encrypt',exact:true}).click();
 await expect(page.locator('#bg-out')).toContainText('gcd(r, n) = 19');
 await page.locator('#bg-seed').fill('0');
 await page.getByRole('button',{name:'Encrypt',exact:true}).click();
 await expect(page.locator('#bg-out')).toContainText('0 < r < n');
});

test('the stream exhibit states exact assumptions, roles, work and scope',async({page})=>{
 await toy(page);await page.getByRole('tab',{name:/Rewind the stream/}).click();
 const panel=page.locator('#panel');
 await expect(panel).toContainText('HAC Algorithm 8.56');
 await expect(panel).toContainText('emits nothing');
 await expect(panel).toContainText('BBS 1986 §4');
 await expect(panel).toContainText('p,q ≡ 3 (mod 4)');
 await expect(panel).toContainText('p,q ≡ 7 (mod 8)');
 await expect(panel).toContainText('fresh uniform');
 await expect(panel).toContainText('does not transmit r');
 await expect(panel).toContainText('not BBS credential signing');
 await expect(panel).toContainText('unauthenticated and malleable');
 await expect(panel).toContainText('not evidence of pseudorandomness');
 await stream(page,'1001110000010000','5');
 await expect(page.getByRole('heading',{name:'Sender teaching view — private state is not transmitted'})).toBeVisible();
 await page.getByRole('button',{name:'Decrypt with the factors'}).click();
 await expect(page.locator('[data-verdict=bg-decrypt]')).toContainText('four modular exponentiations');
 await expect(page.locator('#bg-out')).toContainText('does not recover or need this particular pre-square root r');
});

test('fresh coins are the default while manual coins are an explicit override',async({page})=>{
 await toy(page);await page.getByRole('tab',{name:/Rewind the stream/}).click();
 await expect(page.locator('#bg-seed-mode')).toHaveValue('fresh');
 await expect(page.locator('#bg-seed')).toBeDisabled();
 await page.getByRole('button',{name:'Encrypt',exact:true}).click();
 const seedNode=page.locator('[data-bg-seed]');
 await expect(seedNode).toHaveAttribute('data-bg-seed-mode','fresh');
 const seed=BigInt((await seedNode.getAttribute('data-bg-seed'))!);
 expect(seed).toBeGreaterThan(0n);expect(seed).toBeLessThan(437n);expect(gcd(seed,437n)).toBe(1n);
});

test('same-seed control derives the two-time-pad XOR relation from both ciphertexts',async({page})=>{
 await stream(page,'1001110000010000','5');
 await page.getByRole('button',{name:'Show same-seed leak'}).click();
 const row=page.locator('[data-bg-reuse-cxor]');
 const c=await row.getAttribute('data-bg-reuse-cxor'),m=await row.getAttribute('data-bg-reuse-pxor');
 expect(c).toBe(m);expect(c).toBe('1111111111111111');
 await expect(page.locator('[data-verdict=bg-reuse]')).toContainText('Fresh randomness is part of probabilistic encryption');
});

test('the live BBS and HAC bit sequences have the documented one-state offset',async({page})=>{
 await stream(page,'1001110000010000','5');
 const N=437n,x0=25n,rows=await page.getByRole('region',{name:'BBS indexing comparison'}).locator('tbody tr').all();
 expect(rows).toHaveLength(2);
 const text=await Promise.all(rows.map(r=>r.locator('td').allTextContents()));
 let x=x0,bbs='';for(let i=0;i<8;i++){bbs+=String(x&1n);x=refSquare(x,N);}
 x=x0;let hac='';for(let i=0;i<8;i++){x=refSquare(x,N);hac+=String(x&1n);}
 expect(text[0]).toEqual(['BBS 1986 §4','x₀',bbs]);
 expect(text[1]).toEqual(['HAC 5.40','x₁',hac]);
 expect(bbs.slice(1)).toBe(hac.slice(0,7));
});

test('input and session retirement erase the stored stream scenario',async({page})=>{
 for(const action of ['Decrypt with the factors','Show same-seed leak','Disclose x₂','Apply one-bit mutation','Use a non-QR final state','Use an altered valid-QR final state']){
  await stream(page,'1001110000010000','5');
  await page.locator('#bg-bits').fill('1001110000010001');
  await expect(page.locator('#bg-out')).toContainText('Retired: inputs changed');
  await page.getByRole('button',{name:action,exact:true}).click();
  await expect(page.locator('[data-bg-final]')).toHaveCount(0);
  await expect(page.locator('#bg-out')).toContainText('Encrypt a message first');
 }
 await stream(page,'1001110000010000','5');
 await page.getByRole('button',{name:'Generate session key',exact:true}).click();
 await expect(page.locator('[data-key-N]')).toBeVisible();
 await page.getByRole('button',{name:'Decrypt with the factors'}).click();
 await expect(page.locator('[data-bg-final]')).toHaveCount(0);
 await expect(page.locator('#bg-out')).toContainText(/session key changed|Encrypt a message first/);
});
