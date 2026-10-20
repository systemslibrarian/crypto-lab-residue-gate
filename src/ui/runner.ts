export type Progress = (data:unknown)=>void;
export type Task = (name:string,args:Record<string,unknown>,progress:Progress)=>Promise<unknown>;
// A fresh worker per task makes cancellation immediate, even inside a long BigInt loop.
// Terminated workers cannot publish stale results. The generation check also covers fallback.
export class Runner {
 private worker:Worker|null=null;private generation=0;private reject:((reason:Error)=>void)|null=null;
 constructor(private createWorker:()=>Worker,private fallback:Task,private notice:HTMLElement){window.addEventListener('lab-retire',()=>this.cancel(),{once:true});}
 cancel():void{this.generation++;this.worker?.terminate();this.worker=null;this.reject?.(new Error('Cancelled'));this.reject=null;}
 async run<T>(name:string,args:Record<string,unknown>,progress:Progress=()=>{}):Promise<T>{
  this.cancel();const id=this.generation;
  try{this.worker=this.createWorker();}catch{this.notice.textContent='Degraded mode: workers unavailable. The bounded experiment runs on the main thread.';await new Promise(r=>setTimeout(r,0));const value=await this.fallback(name,args,progress);if(id!==this.generation)throw Error('Cancelled');return value as T;}
  return new Promise<T>((resolve,reject)=>{this.reject=reject;this.worker!.onerror=e=>{if(id!==this.generation)return;this.worker?.terminate();this.worker=null;this.reject=null;reject(new Error('Worker failed: '+e.message));};this.worker!.onmessage=({data})=>{if(id!==this.generation)return;if(data.progress!==undefined){progress(data.progress);return;}this.worker?.terminate();this.worker=null;this.reject=null;if(data.error)reject(new Error(data.error));else resolve(data.result as T);};this.worker!.postMessage({name,args});});
 }
}
