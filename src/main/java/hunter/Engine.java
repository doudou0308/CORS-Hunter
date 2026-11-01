package hunter;

import burp.*;
import java.net.URL;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.Consumer;

public final class Engine {
    public static final String MARKER="X-CORS-Hunter-Probe";
    public static final int MAX_REQUEST=65536, MAX_RESPONSE=524288, MAX_SEEN=3000;
    public volatile boolean automatic=true, scopeOnly=true, extended=false, reportIssues=true, navigationFetch=true;
    public volatile long intervalMillis=500;
    public volatile String customOrigin="";
    public final AtomicBoolean unloaded=new AtomicBoolean(false), paused=new AtomicBoolean(false);
    public final AtomicInteger sent=new AtomicInteger(), dropped=new AtomicInteger(), completed=new AtomicInteger();
    private final AtomicInteger generation=new AtomicInteger();
    private final IBurpExtenderCallbacks cb;
    private final IExtensionHelpers helpers;
    private final Consumer<Finding> sink;
    private final ThreadPoolExecutor executor;
    private final Object lock=new Object();
    private final Set<String> seen=new HashSet<String>(),pending=new HashSet<String>(),issues=new HashSet<String>();
    private final Map<String,Long> cooldown=new HashMap<String,Long>();
    private final Map<String,Integer> failures=new HashMap<String,Integer>();
    private long nextSendNanos;
    private final String tag=UUID.randomUUID().toString();
    public Engine(IBurpExtenderCallbacks cb,Consumer<Finding> sink) {
        this.cb=cb;this.helpers=cb.getHelpers();this.sink=sink;
        executor=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<Runnable>(64),r->{
            Thread t=new Thread(r,"CORS-Hunter-worker");t.setDaemon(true);return t;
        },new ThreadPoolExecutor.AbortPolicy());
    }
    public int queued(){return executor.getQueue().size();}
    public int active(){return executor.getActiveCount();}
    public int tracked(){synchronized(lock){return seen.size();}}
    public void log(String text){cb.printOutput("[CORS Hunter] "+text);}
    public void error(Throwable e){java.io.StringWriter s=new java.io.StringWriter();e.printStackTrace(new java.io.PrintWriter(s));cb.printError(s.toString());}
    public boolean own(byte[] request,IHttpService service) {
        for(String h:helpers.analyzeRequest(service,request).getHeaders()) {
            int c=h.indexOf(':'); if(c>0&&h.substring(0,c).trim().equalsIgnoreCase(MARKER)) return true;
        }
        return false;
    }
    public String offer(IHttpRequestResponse source,boolean manual,boolean allowWrite) {
        if(unloaded.get()||paused.get()) return "任务已暂停；先点击 Resume";
        try {
            byte[] req=source.getRequest(),res=source.getResponse();
            if(req==null||req.length>MAX_REQUEST) return "请求为空或超过 64 KiB";
            if(res!=null&&res.length>MAX_RESPONSE) return "原始响应超过 512 KiB；跳过以限制结果内存";
            IHttpService service=source.getHttpService();
            if(service==null) return "HTTP service 为空";
            if(own(req,service)) return "跳过插件探测请求";
            IRequestInfo info=helpers.analyzeRequest(service,req);
            if(Policy.headers(info.getHeaders()).containsKey("transfer-encoding")) return "Transfer-Encoding 请求请人工处理，避免改变正文 framing";
            URL url=info.getUrl(); String method=info.getMethod().toUpperCase(Locale.ROOT);
            if(!Arrays.asList("GET","HEAD","POST","PUT","PATCH","DELETE").contains(method)) return "不支持此请求方法";
            if(!method.equals("GET")&&!method.equals("HEAD")&&(!manual||!allowWrite)) return "自动模式仅 GET/HEAD；其他方法需要手动确认";
            byte[] body=Policy.body(req,info.getBodyOffset());
            if((method.equals("GET")||method.equals("HEAD"))&&body.length>0) return "带正文 GET/HEAD 无法等价用于 fetch，跳过";
            if(!destinationMatches(url,service)) return "URL 与 HTTP service 不一致，跳过";
            if(scopeOnly&&!cb.isInScope(url)) return "不在 Burp Target scope 内";
            String key=fingerprint(service,url,req);
            synchronized(lock) {
                if(pending.contains(key)||(!manual&&seen.contains(key))) return "已排队或已检测";
                if(!seen.contains(key)&&seen.size()>=MAX_SEEN) return "已达到 3000 个请求上下文预算；可在空闲时重置";
                if(unloaded.get()||paused.get()) return "任务已暂停";
                seen.add(key);pending.add(key);
                try {executor.execute(new Job(new Message(service,req,res),url,method,key,generation.get()));}
                catch(RejectedExecutionException e){pending.remove(key);seen.remove(key);dropped.incrementAndGet();return "队列已满，任务未入队";}
            }
            return "已排队："+method+" "+url.getPath();
        } catch(Exception e){error(e);return "入队失败，查看 Extensions > Errors";}
    }
    private boolean destinationMatches(URL u,IHttpService s) {
        if(s==null||!(u.getProtocol().equals("http")||u.getProtocol().equals("https"))||u.getUserInfo()!=null) return false;
        int port=u.getPort()==-1?u.getDefaultPort():u.getPort();
        return port==s.getPort()&&u.getProtocol().equalsIgnoreCase(s.getProtocol())&&u.getHost().equalsIgnoreCase(s.getHost());
    }
    private static String fingerprint(IHttpService s,URL u,byte[] req)throws Exception {
        MessageDigest md=MessageDigest.getInstance("SHA-256");
        md.update((s.getProtocol()+"|"+s.getHost()+"|"+s.getPort()+"|"+u.toExternalForm()).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte[] hash=md.digest(req);return Base64.getEncoder().encodeToString(hash);
    }
    private final class Job implements Runnable {
        final Message base;final URL url;final String method,key;final int gen;
        Job(Message b,URL u,String m,String k,int g){base=b;url=u;method=m;key=k;gen=g;}
        public void run(){
            boolean success=false;
            try{check(this);scan(this);success=true;completed.incrementAndGet();}
            catch(Cancelled e){/* cooperative cancellation, no new traffic */}
            catch(Exception e){error(e);}
            finally{synchronized(lock){pending.remove(key);if(!success)seen.remove(key);}}
        }
    }
    private static final class Cancelled extends RuntimeException {private static final long serialVersionUID=1;}
    private void check(Job job) {
        if(unloaded.get()||paused.get()||job.gen!=generation.get()) throw new Cancelled();
        if(scopeOnly&&!cb.isInScope(job.url)) throw new Cancelled();
    }
    public void pause() {
        synchronized(lock) {
            paused.set(true);generation.incrementAndGet();
            List<Runnable> jobs=new ArrayList<Runnable>();executor.getQueue().drainTo(jobs);
            for(Runnable r:jobs)if(r instanceof Job){seen.remove(((Job)r).key);pending.remove(((Job)r).key);}
        }
    }
    public void resume(){if(!unloaded.get())paused.set(false);}
    public boolean reset(){synchronized(lock){if(!pending.isEmpty()||active()>0)return false;seen.clear();issues.clear();cooldown.clear();failures.clear();sent.set(0);completed.set(0);dropped.set(0);return true;}}
    public void close(){unloaded.set(true);pause();executor.shutdown();}
    private Message send(Job job,byte[] request) throws Exception {
        check(job);
        String hostKey=Policy.origin(job.url);
        synchronized(lock) {
            Long until=cooldown.get(hostKey);
            if(until!=null&&until>System.currentTimeMillis()) throw new IllegalStateException("目标处于故障/慢请求冷却期");
            if(!cooldown.containsKey(hostKey)&&cooldown.size()>=512)throw new IllegalStateException("目标数量预算已满");
            if(!cooldown.containsKey(hostKey))cooldown.put(hostKey,0L);
        }
        while(System.nanoTime()<nextSendNanos){check(job);Thread.sleep(50);}
        check(job);
        if(sent.get()>=12000)throw new IllegalStateException("已达到 12000 次请求预算；在空闲时重置");
        sent.incrementAndGet(); nextSendNanos=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(intervalMillis);
        long begin=System.nanoTime();
        try {
            IHttpRequestResponse result=cb.makeHttpRequest(job.base.getHttpService(),request);
            check(job);
            if(result==null||result.getResponse()==null)throw new IllegalStateException("没有收到 HTTP 响应");
            if(result.getResponse().length>MAX_RESPONSE)throw new IllegalStateException("响应超过 512 KiB，未保存或分析");
            failures.remove(hostKey);
            return new Message(job.base.getHttpService(),request,result.getResponse());
        } catch(Cancelled e){throw e;}
        catch(Exception e){synchronized(lock){int n=failures.containsKey(hostKey)?failures.get(hostKey)+1:1;failures.put(hostKey,n);if(n>=3)cooldown.put(hostKey,System.currentTimeMillis()+30000);}throw e;}
        finally {if(System.nanoTime()-begin>TimeUnit.SECONDS.toNanos(10)){synchronized(lock){cooldown.put(hostKey,System.currentTimeMillis()+30000);}log("慢请求返回，目标冷却 30 秒；legacy API 无法取消在途请求");}}
    }
    public byte[] request(Message base,URL url,String method,String origin) {
        boolean profile=navigationFetch&&(method.equals("GET")||method.equals("HEAD"))&&Policy.navigation(helpers.analyzeRequest(base).getHeaders());
        return request(base,url,method,origin,profile);
    }
    private byte[] request(Message base,URL url,String method,String origin,boolean profile) {
        byte[] raw=base.getRequest();IRequestInfo info=helpers.analyzeRequest(base.getHttpService(),raw);
        List<String> old=info.getHeaders();Set<String> remove=new HashSet<String>(Arrays.asList(
            "origin","referer","host","content-length","transfer-encoding","connection","keep-alive","expect",
            "upgrade","trailer","te","proxy-authorization","proxy-connection","accept-encoding","range",
            "if-none-match","if-modified-since","if-match","if-unmodified-since","if-range",MARKER.toLowerCase(Locale.ROOT)));
        if(profile) Collections.addAll(remove,"accept","upgrade-insecure-requests","cache-control","pragma");
        Map<String,List<String>> map=Policy.headers(old);
        if(map.containsKey("connection"))for(String value:map.get("connection"))for(String token:value.split(","))remove.add(token.trim().toLowerCase(Locale.ROOT));
        String target=url.getFile();if(target.isEmpty())target="/";
        if(target.indexOf('\r')>=0||target.indexOf('\n')>=0||target.indexOf(' ')>=0)throw new IllegalArgumentException("无效 request-target");
        List<String> headers=new ArrayList<String>();headers.add(method+" "+target+" HTTP/1.1");headers.add("Host: "+url.getAuthority());
        for(int i=1;i<old.size();i++) {
            String line=old.get(i);int colon=line.indexOf(':');
            if(colon<=0||line.indexOf('\r')>=0||line.indexOf('\n')>=0)throw new IllegalArgumentException("无效请求头");
            String name=line.substring(0,colon).trim().toLowerCase(Locale.ROOT);
            if(remove.contains(name)||name.startsWith("sec-fetch-")||name.startsWith("sec-ch-"))continue;
            if(name.equals("x-http-method-override")||name.equals("x-http-method")||name.equals("x-method-override"))
                throw new IllegalArgumentException("含方法覆盖头，请在 Repeater 中人工复核");
            headers.add(line);
        }
        if(profile)headers.add("Accept: */*");
        headers.add("Accept-Encoding: identity");headers.add("Origin: "+origin);headers.add(MARKER+": "+tag);
        return helpers.buildHttpMessage(headers,Policy.body(raw,info.getBodyOffset()));
    }
    private byte[] options(Job job,String origin,SortedSet<String> required) {
        String target=job.url.getFile();if(target.isEmpty())target="/";
        List<String> h=new ArrayList<String>(Arrays.asList("OPTIONS "+target+" HTTP/1.1","Host: "+job.url.getAuthority(),
            "Origin: "+origin,"Access-Control-Request-Method: "+job.method,MARKER+": "+tag));
        if(!required.isEmpty())h.add("Access-Control-Request-Headers: "+String.join(", ",required));
        return helpers.buildHttpMessage(h,null); // No Cookie or Authorization on preflight.
    }
    private void scan(Job job)throws Exception {
        String id=UUID.randomUUID().toString().replace("-","").substring(0,12),scheme=job.url.getProtocol()+"://";
        LinkedHashMap<String,String> origins=new LinkedHashMap<String,String>();
        origins.put(scheme+"cors-"+id+".invalid","random");origins.put("null","null");
        if(extended&&!job.url.getHost().contains(":")&&!job.url.getHost().matches("[0-9.]+")) {
            origins.put(scheme+job.url.getHost()+".cors-"+id+".invalid","suffix");
            origins.put(scheme+"cors-"+id+"-"+job.url.getHost(),"prefix");
        }
        if(!customOrigin.isEmpty())origins.put(Policy.validOrigin(customOrigin),"custom");
        origins.remove(Policy.origin(job.url));
        boolean profile=navigationFetch&&(job.method.equals("GET")||job.method.equals("HEAD"))&&Policy.navigation(helpers.analyzeRequest(job.base).getHeaders());
        String profileNote=profile?"[navigation -> fetch: Accept */*; 移除导航提示/缓存头，内容可能与原导航不同] ":"";
        for(Map.Entry<String,String> origin:origins.entrySet()) {
            check(job);Message pre=null,probe=null;String o=origin.getKey(),rule=origin.getValue();
            try {
                byte[] req=request(job.base,job.url,job.method,o,profile);
                SortedSet<String> required=Policy.requiredHeaders(helpers.analyzeRequest(job.base.getHttpService(),req).getHeaders());
                boolean need=!Policy.simpleMethod(job.method)||!required.isEmpty(),cred=true,anon=true;
                if(need) {
                    pre=send(job,options(job,o,required));IResponseInfo pi=helpers.analyzeResponse(pre.getResponse());
                    Map<String,List<String>> ph=Policy.headers(pi.getHeaders());
                    cred=Policy.preflight(ph,pi.getStatusCode(),o,job.method,required,true);
                    anon=Policy.preflight(ph,pi.getStatusCode(),o,job.method,required,false);
                    if(!cred&&!anon){emit(job,null,pre,o,rule,"PREFLIGHT_BLOCKED",profileNote+"预检未通过；未重放实际请求。请求头："+required,pi.getStatusCode(),ph);continue;}
                }
                probe=send(job,req);IResponseInfo ri=helpers.analyzeResponse(probe.getResponse());
                Map<String,List<String>> rh=Policy.headers(ri.getHeaders());
                String grade,reason;
                if(ri.getStatusCode()>=300&&ri.getStatusCode()<400){grade="REDIRECT";reason="未跟随重定向；无法据此确认最终响应策略";}
                else if(cred&&Policy.permits(rh,o,true)){grade="CREDENTIAL_POLICY";reason="响应允许携带凭证读取"+(need?"，预检也通过":"，无需预检")+"；浏览器凭证、数据敏感性及实际读取仍待验证";}
                else if(anon&&Policy.permits(rh,o,false)){grade="NONCREDENTIAL_POLICY";reason="非凭证模式的头部条件通过；本次重放可能仍携带原认证，不能据此证明匿名读取";}
                else if(rh.containsKey("access-control-allow-origin")){grade="HEADER_ONLY";reason="存在 CORS 响应头，但未满足所测 Origin/凭证/预检条件";}
                else {grade="MISS";reason="未发现所测 Origin 的 CORS 许可";}
                emit(job,probe,pre,o,rule,grade,profileNote+reason,ri.getStatusCode(),rh);
            } catch(Cancelled e){throw e;}
            catch(Exception e){error(e);emit(job,probe,pre,o,rule,"ERROR",e.getClass().getSimpleName()+": "+e.getMessage(),0,Collections.emptyMap());break;}
        }
    }
    private void emit(Job job,Message probe,Message pre,String origin,String rule,String grade,String reason,int status,Map<String,List<String>> h) {
        check(job);
        Finding f=new Finding(job.base,probe,pre,job.url,job.method,origin,rule,grade,reason,status,
            Policy.display(h,"access-control-allow-origin"),Policy.display(h,"access-control-allow-credentials"));
        sink.accept(f);
        if(reportIssues&&probe!=null&&grade.equals("CREDENTIAL_POLICY")&&status>=200&&status<300) {
            String key=job.method+" "+job.url.toExternalForm();boolean add;
            synchronized(lock){add=issues.size()<300&&issues.add(key);}
            if(add) try{cb.addScanIssue(new Issue(f));}catch(Exception e){synchronized(lock){issues.remove(key);}error(e);}
        }
    }
}
