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
async function teachingRows(page:Page){return Promise.all((await page.getByRole('region',{name:'Sender original state-chain calculation'}).locator('tbody tr').all()).map(async r=>r.locator('td').allTextContents()));}

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
 await expect(verdictBox).toContainText('PUBLIC CYCLE EXPOSES THE EARLIER STREAM TOO');
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
 let cycleLength=0,predecessor=disclosed;x=disclosed;
 do{predecessor=x;x=refSquare(x,N);cycleLength++;expect(cycleLength).toBeLessThanOrEqual(4096);}while(x!==disclosed);
 expect(cycleLength).toBe(30);expect(predecessor).toBe(188n);
 const firstPlain=refXor(rows[0],refLow(predecessor,h).slice(0,rows[0].length));
 expect(firstPlain+recovered).toBe(message);
 expect(await disclosure.getAttribute('data-bg-disclosure-all')).toBe(message);
 await expect(disclosure).toHaveAttribute('data-bg-cycle-length',String(cycleLength));
 await expect(disclosure).toHaveAttribute('data-bg-cycle-predecessor',String(predecessor));
 await expect(disclosure).toHaveAttribute('data-bg-cycle',/30 forward squarings/);
 await expect(disclosure).toContainText('Earlier wire bits recovered from the public cycle predecessor');
 await expect(verdictBox).toContainText('fresh uniformly sampled start at cryptographic sizes');
});

test('manual fixed-point and two-cycle seeds expose the earlier stream without a false classification',async({page})=>{
 for(const seed of ['1','436']){
  const message='1001110000010000';await stream(page,message,seed);
  await page.getByRole('button',{name:'Disclose x₂'}).click();
  const disclosure=page.locator('[data-bg-disclosed]');
  await expect(disclosure).toHaveAttribute('data-bg-disclosed','1');
  await expect(disclosure).toHaveAttribute('data-bg-cycle-length','1');
  await expect(disclosure).toHaveAttribute('data-bg-cycle-predecessor','1');
  await expect(disclosure).toHaveAttribute('data-bg-disclosure-all',message);
  await expect(page.locator('[data-verdict=bg-disclosed]')).toContainText('public fixed point');
  await expect(page.locator('[data-verdict=bg-disclosed]')).not.toContainText('not recovered by this bounded check');
 }
 const message='1001110000010000';await stream(page,message,'45');
 await page.getByRole('button',{name:'Disclose x₂'}).click();
 const twoCycle=page.locator('[data-bg-disclosed]');
 await expect(twoCycle).toHaveAttribute('data-bg-disclosed','277');
 await expect(twoCycle).toHaveAttribute('data-bg-cycle-length','2');
 await expect(twoCycle).toHaveAttribute('data-bg-cycle-predecessor','254');
 await expect(twoCycle).toHaveAttribute('data-bg-disclosure-all',message);
 await expect(page.locator('[data-verdict=bg-disclosed]')).toContainText('public two-state cycle');
 await expect(page.locator('[data-verdict=bg-disclosed]')).not.toContainText('public fixed point');
});

test('flipping one ciphertext bit flips one plaintext bit and is not detected',async({page})=>{
 const message='1001110000010000';await stream(page,message,'5');
 await page.getByRole('button',{name:'Apply one-bit mutation'}).click();
 await page.getByRole('button',{name:'Apply one-bit mutation'}).click(); // idempotent scenario, not a toggle
 await expect(page.locator('[data-verdict=bg-tampered]')).toContainText('no authentication');
 const senderFirst=(await page.getByRole('region',{name:'Sender original state-chain calculation'}).locator('tbody tr').first().locator('td').last().textContent())!;
 const wireFirst=(await page.getByRole('region',{name:'Transmitted ciphertext blocks'}).locator('tbody tr').first().locator('td').last().textContent())!;
 expect(senderFirst).not.toBe(wireFirst);
 await expect(page.locator('[data-bg-blocks-match-original]')).toHaveAttribute('data-bg-blocks-match-original','no');
 await expect(page.locator('[data-bg-blocks-match-original]')).toContainText('sender table preserves the original ciphertext');
 await page.getByRole('button',{name:'Decrypt with the factors'}).click();
 await expect(page.locator('[data-verdict=bg-decrypt]')).toContainText('DECRYPTED TO A CHANGED MESSAGE');
 const flipped=String(1-Number(message[0]))+message.slice(1);
 await expect(page.locator('#bg-out')).toContainText(flipped);
 // Exactly one bit differs, and nothing rejected the ciphertext.
 expect([...flipped].filter((c,i)=>c!==message[i]).length).toBe(1);
 await expect(page.locator('[data-verdict=bg-decrypt]')).toContainText('did not authenticate a sender');
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

test('older asynchronous stream actions cannot overwrite newer ciphertext actions',async({page})=>{
 await stream(page,'1001110000010000','5');
 const out=page.locator('#bg-out');

 // A decrypt begun for the original wire value must not be rendered after a
 // later synchronous bit mutation changes the current ciphertext.
 await page.evaluate(()=>{
  (document.querySelector('#bg-decrypt') as HTMLButtonElement).click();
  (document.querySelector('#bg-flip') as HTMLButtonElement).click();
 });
 await expect(out).toHaveAttribute('data-bg-stale-decrypt-discarded',/\d+/);
 await expect(page.locator('[data-verdict=bg-tampered]')).toContainText('Bit 1 of block 1');
 await expect(page.locator('[data-verdict=bg-decrypt]')).toHaveCount(0);

 // A pending final-state selection is also older than a later bit mutation.
 // Its worker response may not replace the newer wire value or scenario.
 await page.getByRole('button',{name:'Encrypt',exact:true}).click();
 await page.evaluate(()=>{
  (document.querySelector('#bg-tamper-invalid') as HTMLButtonElement).click();
  (document.querySelector('#bg-flip') as HTMLButtonElement).click();
 });
 await expect(out).toHaveAttribute('data-bg-stale-final-state-discarded',/\d+/);
 const final=await page.locator('[data-bg-final]').getAttribute('data-bg-final');
 const original=await page.locator('[data-bg-final]').getAttribute('data-bg-original-final');
 expect(final).toBe(original);
 await expect(page.locator('[data-verdict=bg-tampered]')).toContainText('Bit 1 of block 1');
 await expect(page.locator('[data-verdict=bg-tampered]')).not.toContainText('outside QR');

 // If selection and decrypt are clicked back-to-back, decrypt owns the later
 // action and remains attached to the original valid ciphertext it submitted.
 await page.getByRole('button',{name:'Encrypt',exact:true}).click();
 await page.evaluate(()=>{
  (document.querySelector('#bg-tamper-invalid') as HTMLButtonElement).click();
  (document.querySelector('#bg-decrypt') as HTMLButtonElement).click();
 });
 await expect(out).toHaveAttribute('data-bg-stale-final-state-discarded',/\d+/);
 await expect(page.locator('[data-verdict=bg-decrypt]')).toContainText('DECRYPTED — the rewind landed on x₀');
 await expect(page.locator('[data-verdict=bg-validity-refusal]')).toHaveCount(0);
});

test('input retirement discards an in-flight non-QR rejection',async({page})=>{
 await stream(page,'1001110000010000','5');
 await page.getByRole('button',{name:'Use a non-QR final state'}).click();
 await expect(page.locator('[data-bg-final]')).toHaveAttribute('data-bg-final','37');
 const out=page.locator('#bg-out');
 await page.evaluate(()=>{
  (document.querySelector('#bg-decrypt') as HTMLButtonElement).click();
  const input=document.querySelector('#bg-bits') as HTMLInputElement;
  input.value='1001110000010001';
  input.dispatchEvent(new Event('input',{bubbles:true}));
 });
 await expect(out).toHaveAttribute('data-bg-stale-decrypt-discarded',/\d+/);
 await expect(out).toContainText('Retired: inputs changed');
 await expect(page.locator('[data-verdict=bg-validity-refusal]')).toHaveCount(0);
});

test('key regeneration discards an in-flight decrypt rejection',async({page})=>{
 await stream(page,'1001110000010000','5');
 const out=page.locator('#bg-out');
 await page.evaluate(()=>{
  (document.querySelector('#bg-decrypt') as HTMLButtonElement).click();
  (document.querySelector('#keygen') as HTMLButtonElement).click();
 });
 await expect(out).toHaveAttribute('data-bg-stale-decrypt-discarded',/\d+/);
 await expect(out).toContainText('Retired: key changed');
 await expect(out).not.toContainText('Cancelled');
 await expect(page.locator('[data-verdict=bg-decrypt]')).toHaveCount(0);
});

test('key regeneration discards an in-flight final-state selection',async({page})=>{
 await stream(page,'1001110000010000','5');
 const out=page.locator('#bg-out');
 await page.evaluate(()=>{
  (document.querySelector('#bg-tamper-invalid') as HTMLButtonElement).click();
  (document.querySelector('#keygen') as HTMLButtonElement).click();
 });
 await expect(out).toHaveAttribute('data-bg-stale-final-state-discarded',/\d+/);
 await expect(out).toContainText('Retired: key changed');
 await expect(out).not.toContainText('Cancelled');
 await expect(page.locator('[data-verdict=bg-tampered]')).toHaveCount(0);
});

test('an unexpected worker error is not presented as a validity refusal',async({page})=>{
 await stream(page,'1001110000010000','5');
 await page.getByRole('button',{name:'Use a non-QR final state'}).click();
 await expect(page.locator('[data-bg-final]')).toHaveAttribute('data-bg-final','37');
 await page.evaluate(()=>{
  const original=Worker.prototype.postMessage;
  const replacement=function(this:Worker,message:unknown):void{
   if(typeof message==='object'&&message!==null&&(message as {name?:unknown}).name==='bgdecrypt'){
    const id=(message as {id:number}).id;
    setTimeout(()=>this.dispatchEvent(new MessageEvent('message',{data:{id,error:'synthetic worker computation failure'}})),0);
    return;
   }
   original.call(this,message);
  };
  Worker.prototype.postMessage=replacement as typeof Worker.prototype.postMessage;
  try{(document.querySelector('#bg-decrypt') as HTMLButtonElement).click();}
  finally{Worker.prototype.postMessage=original;}
 });
 await expect(page.locator('#bg-out')).toContainText('synthetic worker computation failure');
 await expect(page.locator('[data-verdict=bg-validity-refusal]')).toHaveCount(0);
 await expect(page.locator('#bg-out .verdict')).toContainText('Input refused');
 await page.evaluate(()=>{
  const original=Worker.prototype.postMessage;
  const replacement=function(this:Worker,message:unknown):void{
   if(typeof message==='object'&&message!==null&&(message as {name?:unknown}).name==='bgdecrypt')throw Error('synthetic worker transport failure');
   original.call(this,message);
  };
  Worker.prototype.postMessage=replacement as typeof Worker.prototype.postMessage;
  try{(document.querySelector('#bg-decrypt') as HTMLButtonElement).click();}
  finally{Worker.prototype.postMessage=original;}
 });
 await expect(page.locator('#bg-out')).toContainText('synthetic worker transport failure');
 await expect(page.locator('[data-verdict=bg-validity-refusal]')).toHaveCount(0);
 await expect(page.locator('#bg-out .verdict')).toContainText('Operation failed');
 await expect(page.locator('#bg-out .verdict')).not.toContainText('Input refused');
 await expect(page.locator('[data-key-N]')).toHaveCount(0);
 await expect(page.locator('#key-state')).toContainText('Session failed after an unexpected worker error');
 await page.getByRole('button',{name:'Encrypt',exact:true}).click();
 await expect(page.locator('#bg-out')).toContainText('Generate a session key');
 await page.getByRole('button',{name:'Generate session key',exact:true}).click();
 await expect(page.locator('[data-key-N]')).toHaveAttribute('data-key-N','437');
 await page.getByRole('button',{name:'Encrypt',exact:true}).click();
 await page.evaluate(()=>{
  const original=Worker.prototype.postMessage;
  const replacement=function(this:Worker,message:unknown):void{
   if(typeof message==='object'&&message!==null&&(message as {name?:unknown}).name==='bgtamperstates')throw Error('synthetic final-state worker failure');
   original.call(this,message);
  };
  Worker.prototype.postMessage=replacement as typeof Worker.prototype.postMessage;
  try{(document.querySelector('#bg-tamper-invalid') as HTMLButtonElement).click();}
  finally{Worker.prototype.postMessage=original;}
 });
 await expect(page.locator('#bg-out .verdict')).toContainText('Operation failed');
 await expect(page.locator('#bg-out')).toContainText('synthetic final-state worker failure');
 await expect(page.locator('#bg-out .verdict')).not.toContainText('Input refused');
 await expect(page.locator('[data-key-N]')).toHaveCount(0);
 await page.getByRole('button',{name:'Generate session key',exact:true}).click();
 await expect(page.locator('[data-key-N]')).toHaveAttribute('data-key-N','437');
});

test('a late error from a retired worker cannot kill its replacement session',async({page})=>{
 await boot(page);
 await page.evaluate(()=>{
  const original=Worker.prototype.terminate,retired:Worker[]=[];
  (window as unknown as {__retiredWorkers:Worker[]}).__retiredWorkers=retired;
  Worker.prototype.terminate=function(this:Worker):void{retired.push(this);original.call(this);};
 });
 await page.locator('#key-size').selectOption('16');
 await page.getByRole('button',{name:'Generate session key',exact:true}).click();
 await expect(page.locator('[data-key-N]')).toHaveAttribute('data-key-N','437');
 await page.getByRole('button',{name:'Generate session key',exact:true}).click();
 await expect(page.locator('[data-key-N]')).toHaveAttribute('data-key-N','437');
 await page.getByRole('tab',{name:/Rewind the stream/}).click();
 await page.locator('#bg-seed-mode').selectOption('manual');
 await page.locator('#bg-bits').fill('1001110000010000');
 await page.locator('#bg-seed').fill('5');
 await page.getByRole('button',{name:'Encrypt',exact:true}).click();
 await page.evaluate(()=>{
  (document.querySelector('#bg-decrypt') as HTMLButtonElement).click();
  const retired=(window as unknown as {__retiredWorkers:Worker[]}).__retiredWorkers;
  if(retired.length!==1)throw Error('Expected exactly one retired worker.');
  retired[0].dispatchEvent(new ErrorEvent('error',{message:'late stale worker failure'}));
 });
 await expect(page.locator('[data-verdict=bg-decrypt]')).toContainText('DECRYPTED — the rewind landed on x₀');
 await expect(page.locator('[data-key-N]')).toHaveAttribute('data-key-N','437');
 await expect(page.locator('#key-state')).not.toContainText('Session failed');
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
 await expect(panel).toContainText('HAC Algorithm 8.55 requires two distinct primes');
 await expect(panel).toContainText('p,q ≡ 3 (mod 4)');
 await expect(panel).toContainText('p,q ≡ 7 (mod 8)');
 await expect(panel).toContainText('40 Miller–Rabin rounds');
 await expect(panel).toContainText('assume the accepted candidates really are prime');
 await expect(panel).toContainText('fresh uniform');
 await expect(panel).toContainText('does not transmit r');
 await expect(panel).toContainText('not every hand-picked seed');
 await expect(panel).toContainText('short final-block support is an explicit teaching adaptation');
 await expect(panel).toContainText('not a verbatim HAC case');
 await expect(panel).toContainText('Goldwasser–Micali semantic security is based on quadratic residuosity');
 await expect(panel).toContainText('HAC Note 8.58(i) states Blum–Goldwasser semantic security assuming integer factorization is intractable');
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
 const c1=await row.getAttribute('data-bg-reuse-c1'),c2=await row.getAttribute('data-bg-reuse-c2');
 const c=await row.getAttribute('data-bg-reuse-cxor'),m=await row.getAttribute('data-bg-reuse-pxor');
 expect(c1).not.toBeNull();expect(c2).not.toBeNull();
 expect(refXor(c1!,c2!)).toBe(c);
 expect(c).toBe(m);expect(c).toBe(refXor('1001110000010000','0110001111101111'));
 const final1=await row.getAttribute('data-bg-reuse-final1'),final2=await row.getAttribute('data-bg-reuse-final2');
 expect(final1).toBe(final2);
 await page.getByText('Inspect both same-seed ciphertexts',{exact:true}).click();
 const evidence=await page.getByRole('region',{name:'Same-seed ciphertext evidence'}).locator('tbody tr').allTextContents();
 expect(evidence).toEqual(['First message'+c1+final1,'Second message'+c2+final2]);
 await expect(page.locator('[data-verdict=bg-reuse]')).toContainText('Fresh randomness is part of probabilistic encryption');
});

test('empty messages do not claim a visible two-time-pad XOR leak',async({page})=>{
 await stream(page,'','1');
 const wire=page.getByRole('region',{name:'Transmitted ciphertext blocks'}),sender=page.getByRole('region',{name:'Sender original state-chain calculation'});
 await expect(wire.locator('tbody tr')).toHaveCount(1);await expect(wire).toContainText('No ciphertext blocks (empty message)');
 await expect(sender.locator('tbody tr')).toHaveCount(1);await expect(sender).toContainText('No emitting state (empty message)');
 await page.getByRole('button',{name:'Show same-seed leak'}).click();
 const out=page.locator('#bg-out');
 await expect(out).toContainText('there are no ciphertext bits to XOR');
 await expect(out).toContainText('only repeated final-state linkability remains visible');
 await expect(page.locator('[data-verdict=bg-reuse]')).toHaveCount(0);
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
 const out=page.locator('#bg-out');
 await page.getByRole('button',{name:'Generate session key',exact:true}).click();
 await expect(out).toHaveAttribute('data-bg-secrets-cleared','session');
 await expect(page.locator('[data-key-N]')).toBeVisible();
 await page.getByRole('button',{name:'Decrypt with the factors'}).click();
 await expect(page.locator('[data-bg-final]')).toHaveCount(0);
 await expect(page.locator('#bg-out')).toContainText(/session key changed|Encrypt a message first/);
 await stream(page,'1001110000010000','5');
 const cancelled=page.locator('#bg-out');
 await page.getByRole('button',{name:'Discard key \/ cancel',exact:true}).click();
 await expect(cancelled).toHaveAttribute('data-bg-secrets-cleared','session');
 await expect(page.locator('#key-state')).toContainText('JavaScript does not prove memory zeroization');
 await page.getByRole('button',{name:'Show same-seed leak'}).click();
 await expect(page.locator('[data-bg-final]')).toHaveCount(0);
 await expect(cancelled).toContainText('Generate a session key');
 await stream(page,'1001110000010000','5');
 const detached=await page.locator('#bg-out').elementHandle();expect(detached).not.toBeNull();
 await page.getByRole('tab',{name:/Encrypt bits/}).click();
 expect(await detached!.getAttribute('data-bg-secrets-cleared')).toBe('panel');
 expect((await detached!.textContent())?.trim()).toBe('');
 await page.getByRole('button',{name:'Discard key \/ cancel',exact:true}).click();
 expect(await detached!.getAttribute('data-bg-secrets-cleared')).toBe('session');
 expect((await detached!.textContent())?.trim()).toBe('');
});
