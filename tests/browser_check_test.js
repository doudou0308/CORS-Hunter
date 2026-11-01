// Runs the exported browser-check JavaScript with local stubs; not a CORS browser test.
const fs = require('fs'), vm = require('vm'), assert = require('assert');
const html=fs.readFileSync('build/browser-check-test.html','utf8');
const script=html.match(/<script>([\s\S]*)<\/script>/)[1];
(async()=>{
  const fields={};for(const id of ['origin','url','method','headers','body','credentials','opaque','run','out'])fields[id]={value:'',checked:false,textContent:'',disabled:false};
  fields.credentials.checked=true;
  let fetches=[],listener,frame;
  const fakeFetch=async(url,options)=>{fetches.push({url,options});return{status:200,body:new ReadableStream({start(controller){controller.enqueue(new TextEncoder().encode('fixture response'));controller.close();}})};};
  const parent={postMessage(data){listener({source:frame.contentWindow,data});}};
  const doc={getElementById:id=>fields[id],createElement(){frame={contentWindow:{},setAttribute(){},remove(){},hidden:false,srcdoc:''};return frame;},body:{appendChild(f){
    const embedded=f.srcdoc.match(/<script>([\s\S]*)<\/script>/)[1];
    new vm.Script(embedded);vm.runInNewContext(embedded,{fetch:fakeFetch,parent,Uint8Array,atob,TextDecoder});
  }}};
  const context={document:doc,location:{origin:'http://127.0.0.1:8001'},fetch:fakeFetch,confirm:()=>true,
    URL,Uint8Array,TextDecoder,atob,crypto:{randomUUID:()=> 'fixture-token'},
    addEventListener(name,cb){listener=cb;},removeEventListener(){},setTimeout,clearTimeout};
  vm.runInNewContext(script,context);
  fields.method.value='GET';await fields.run.onclick();
  assert(fields.out.textContent.includes('浏览器已读取响应'));assert.equal(fetches.length,1);assert.equal(fetches[0].options.credentials,'include');
  fields.opaque.checked=true;fields.headers.value=JSON.stringify({'X-Test':'a<b'});
  await fields.run.onclick();await new Promise(resolve=>setTimeout(resolve,20));
  assert(fields.out.textContent.includes('浏览器已读取响应'));assert.equal(fetches.length,2);
  assert.equal(fetches[1].options.headers['X-Test'],'a<b');
  console.log('PASS: exported page ordinary fetch + sandbox script + message result; no real browser CORS validation.');
})().catch(e=>{console.error(e);process.exitCode=1;});
