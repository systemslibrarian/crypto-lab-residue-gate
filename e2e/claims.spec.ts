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
async function stream(page:Page,bits='1001110000010000',seed='5'){await toy(page);await page.getByRole('tab',{name:/Rewind the stream/}).click();await page.locator('#bg-bits').fill(bits);await page.locator('#bg-seed').fill(seed);await page.getByRole('button',{name:'Encrypt',exact:true}).click();await expect(page.locator('[data-bg-final]')).toBeAttached();}
async function teachingRows(page:Page){return Promise.all((await page.locator('#bg-out .table-wrap').last().locator('tbody tr').all()).map(async r=>r.locator('td').allTextContents()));}

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

test('state disclosure gives future output only and says so',async({page})=>{
 const message='1001110000010000';await stream(page,message,'5');
 const N=BigInt((await page.locator('[data-key-N]').getAttribute('data-key-N'))!);const h=3;
 await page.getByRole('button',{name:'Disclose a state'}).click();
 const verdictBox=page.locator('[data-verdict=bg-disclosed]');
 await expect(verdictBox).toContainText('FUTURE OUTPUT IS GONE — THE PAST IS NOT');
 // Recompute what a public forward walk from x_2 actually yields.
 const chain=refChain(5n,N,Math.ceil(message.length/h));
 const futureKeys=chain.slice(2).map(x=>refLow(x,h));
 const expected=message.slice(2*h);
 const recovered=futureKeys.map((k,i)=>{const piece=expected.slice(i*h,(i+1)*h);return refXor(piece,k.slice(0,piece.length));}).map((c,i)=>refXor(c,futureKeys[i].slice(0,c.length))).join('');
 expect(recovered).toBe(expected);
 await expect(page.locator('#bg-out')).toContainText(expected);
 // The claim is bounded: earlier bits are NOT recovered this way.
 await expect(page.locator('#bg-out')).toContainText('Earlier bits recovered this way');
 await expect(verdictBox).toContainText('the factors are necessary and sufficient to run it backward');
});

test('flipping one ciphertext bit flips one plaintext bit and is not detected',async({page})=>{
 const message='1001110000010000';await stream(page,message,'5');
 await page.getByRole('button',{name:'Flip one ciphertext bit'}).click();
 await expect(page.locator('[data-verdict=bg-tampered]')).toContainText('no authentication');
 await page.getByRole('button',{name:'Decrypt with the factors'}).click();
 await expect(page.locator('[data-verdict=bg-decrypt]')).toContainText('DECRYPTED TO SOMETHING ELSE');
 const flipped=String(1-Number(message[0]))+message.slice(1);
 await expect(page.locator('#bg-out')).toContainText(flipped);
 // Exactly one bit differs, and nothing rejected the ciphertext.
 expect([...flipped].filter((c,i)=>c!==message[i]).length).toBe(1);
 await expect(page.locator('[data-verdict=bg-decrypt]')).toContainText('nothing to reject with');
});

test('tampering the transmitted final state is shown, never dressed up as detection',async({page})=>{
 await stream(page,'1001110000010000','5');
 await page.getByRole('button',{name:'Tamper the final state'}).click();
 await expect(page.locator('[data-verdict=bg-tampered]')).toContainText('neither is a detection');
 await page.getByRole('button',{name:'Decrypt with the factors'}).click();
 const body=await page.locator('#bg-out').textContent();
 // Either the rewind refuses (not a residue) or it lands elsewhere and prints garbage.
 expect(/not a quadratic residue|DECRYPTED TO SOMETHING ELSE|Input refused/.test(body??'')).toBe(true);
 expect(body??'').not.toContain('DECRYPTED — the rewind landed on x₀');
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

test('the stream exhibit states the indexing it runs and refuses the BBS signature confusion',async({page})=>{
 await toy(page);await page.getByRole('tab',{name:/Rewind the stream/}).click();
 const panel=page.locator('#panel');
 await expect(panel).toContainText('HAC Algorithm 8.56');
 await expect(panel).toContainText('emits nothing');
 await expect(panel).toContainText('BBS 1986 §4 instead emits');
 await expect(panel).toContainText('not BBS credential signing');
 await expect(panel).toContainText('unauthenticated and malleable');
 await expect(panel).toContainText('not evidence of pseudorandomness');
});
