package hunter;
import burp.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
/** Generates a user-triggered browser check; contains no exfiltration endpoint. */
public final class Poc {
    private Poc(){}
    public static String build(Finding f,IExtensionHelpers helpers) {
        Message template=f.probe!=null?f.probe:f.original;
        byte[] raw=template.getRequest();IRequestInfo info=helpers.analyzeRequest(template);
        byte[] body=Policy.body(raw,info.getBodyOffset());
        StringBuilder headerPairs=new StringBuilder();
        for(String line:info.getHeaders().subList(1,info.getHeaders().size())) {
            int c=line.indexOf(':');if(c<1)continue;
            String name=line.substring(0,c).trim(),lower=name.toLowerCase(Locale.ROOT);
            // Never embed Cookie, Authorization, API keys or arbitrary original headers in the HTML.
            if(!Arrays.asList("accept","accept-language","content-language","content-type").contains(lower))continue;
            if(headerPairs.length()>0)headerPairs.append(',');
            headerPairs.append('[').append(Policy.js(name)).append(',').append(Policy.js(line.substring(c+1).trim())).append(']');
        }
        return "<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><title>CORS Hunter 浏览器复核</title>"+
            "<style>body{font:16px system-ui;max-width:960px;margin:40px auto;padding:20px;background:#f7f8fc;color:#182033}label{display:block;margin:16px 0}input,textarea{width:100%;box-sizing:border-box;padding:10px}button{padding:10px 18px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:white;padding:20px}code{background:#e7eaf2}</style>"+
            "<h1>CORS 浏览器复核</h1><p>仅在本页本地显示结果，不向第三方上传。点击按钮才发送请求；写操作可能产生业务副作用。</p>"+
            "<p>本页 Origin：<code id=origin></code>。记录中的探测 Origin：<code>"+Policy.html(f.origin)+"</code>。普通复核应将页面托管在你控制的、与目标不同的 Origin；本页结果不自动代表那个探测 Origin。</p>"+
            "<p><code>null</code> 规则可用下方 sandbox 模式；不要手工设置 Origin，浏览器会生成它。Cookie 由浏览器决定，SameSite、第三方 Cookie、混合内容及其他策略都可能阻止请求。</p>"+
            "<label>目标 URL<input id=url></label><label>方法<input id=method></label>"+
            "<label>脚本请求头 JSON（已移除认证信息；自定义头需自行填写）<textarea id=headers rows=4></textarea></label>"+
            "<label>正文 Base64（原始正文未写入文件；如需重放写请求，请自行填写）<textarea id=body rows=2></textarea></label>"+
            "<label><input id=credentials type=checkbox checked style=\"width:auto\"> credentials: include</label>"+
            "<label><input id=opaque type=checkbox style=\"width:auto\"> 在 sandbox iframe 内以 null Origin 请求</label>"+
            "<button id=run>确认并发送一次</button><pre id=out>尚未发送</pre><script>\n"+
            "const $=id=>document.getElementById(id);$('origin').textContent=location.origin;"+
            "$('url').value="+Policy.js(f.url.toExternalForm())+";$('method').value="+Policy.js(f.method)+";"+
            "$('headers').value=JSON.stringify(Object.fromEntries(["+headerPairs+"]),null,2);"+
            "const originalBodyBytes="+body.length+";"+
            "async function execute(c){const o={method:c.method,headers:c.headers,credentials:c.credentials,mode:'cors',redirect:'error'};"+
            "if(c.method!=='GET'&&c.method!=='HEAD')o.body=Uint8Array.from(atob(c.body),x=>x.charCodeAt(0));"+
            "try{const r=await fetch(c.url,o);let t='',size=0;const reader=r.body?r.body.getReader():null;const decoder=new TextDecoder();"+
            "if(reader)while(true){const chunk=await reader.read();if(chunk.done)break;const keep=Math.min(chunk.value.length,65536-size);t+=decoder.decode(chunk.value.slice(0,keep),{stream:true});size+=keep;if(size>=65536){await reader.cancel();t+='\\n[显示上限 64 KiB]';break;}}"+
            "return '浏览器已读取响应。HTTP '+r.status+'；是否敏感请人工判断。\\n'+t;}catch(e){return '未能读取：'+e+'\\n失败不证明服务端安全；检查 DevTools 的 CORS、Cookie、TLS、混合内容及预检信息。';}}\n"+
            "$('run').onclick=async()=>{let c;try{c={url:$('url').value,method:$('method').value.toUpperCase(),headers:JSON.parse($('headers').value),body:$('body').value,credentials:$('credentials').checked?'include':'omit'};"+
            "const u=new URL(c.url);if(!['http:','https:'].includes(u.protocol))throw Error('仅允许 HTTP/HTTPS');"+
            "if(!['GET','HEAD','POST','PUT','PATCH','DELETE'].includes(c.method))throw Error('不支持的方法');"+
            "if(!['GET','HEAD'].includes(c.method)&&originalBodyBytes>0&&!c.body)throw Error('原请求有正文，请手动填入 Base64 后再验证');"+
            "if(!confirm('向 '+u.origin+' 发送一次 '+c.method+'？'))return;}catch(e){$('out').textContent=e;return;}"+
            "$('run').disabled=true;$('out').textContent='请求中…';"+
            "if(!$('opaque').checked){$('out').textContent=await execute(c);$('run').disabled=false;return;}"+
            "const frame=document.createElement('iframe');frame.hidden=true;frame.setAttribute('sandbox','allow-scripts');"+
            "const token=crypto.randomUUID?crypto.randomUUID():String(Math.random());"+
            "const done=e=>{if(e.source===frame.contentWindow&&e.data&&e.data.token===token){$('out').textContent=e.data.result;$('run').disabled=false;removeEventListener('message',done);frame.remove();clearTimeout(timer);}};"+
            "addEventListener('message',done);const timer=setTimeout(()=>{removeEventListener('message',done);frame.remove();$('run').disabled=false;$('out').textContent='等待超过 30 秒；请求可能已发送，请勿盲目重试。';},30000);"+
            "const code='('+execute.toString()+')('+JSON.stringify(c).replace(/</g,'\\\\u003c')+').then(result=>parent.postMessage({token:'+JSON.stringify(token)+',result}, \"*\"));';"+
            "frame.srcdoc='<'+ 'script>'+code+'<'+ '/script>';document.body.appendChild(frame);};\n"+
            "</script></html>";
    }
}
