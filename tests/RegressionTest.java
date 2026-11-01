import burp.*;
import hunter.*;
import com.sun.net.httpserver.*;
import javax.swing.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.lang.reflect.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.*;

public class RegressionTest {
    static int assertions;
    static void ok(boolean b,String msg){assertions++;if(!b)throw new AssertionError(msg);}
    @SuppressWarnings("unchecked") static <T>T proxy(Class<T> c,InvocationHandler h){return (T)java.lang.reflect.Proxy.newProxyInstance(c.getClassLoader(),new Class<?>[]{c},h);}
    static Object empty(Class<?> t){if(t==boolean.class)return false;if(t==int.class)return 0;if(t==short.class)return (short)0;if(t==byte.class)return (byte)0;return null;}
    static class Service implements IHttpService {
        final int port;Service(int port){this.port=port;}
        public String getHost(){return "127.0.0.1";}public int getPort(){return port;}public String getProtocol(){return "http";}
    }
    static int offset(byte[] b){for(int i=0;i<b.length-3;i++)if(b[i]==13&&b[i+1]==10&&b[i+2]==13&&b[i+3]==10)return i+4;throw new IllegalArgumentException("Missing CRLF");}
    static List<String> headers(byte[] b){return Arrays.asList(new String(b,0,offset(b)-4,StandardCharsets.ISO_8859_1).split("\r\n"));}
    static byte[] build(List<String> h,byte[] body){try{ByteArrayOutputStream b=new ByteArrayOutputStream();b.write(String.join("\r\n",h).getBytes(StandardCharsets.ISO_8859_1));if(body!=null&&body.length>0)b.write(("\r\nContent-Length: "+body.length).getBytes(StandardCharsets.ISO_8859_1));b.write("\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));if(body!=null)b.write(body);return b.toByteArray();}catch(IOException e){throw new RuntimeException(e);}}
    static byte[] response(int status,String...h){List<String> hs=new ArrayList<String>();hs.add("HTTP/1.1 "+status+" Test");hs.addAll(Arrays.asList(h));return build(hs,"{\"user\":\"fixture\"}".getBytes(StandardCharsets.UTF_8));}
    static final IExtensionHelpers HELPERS=proxy(IExtensionHelpers.class,(o,m,a)->{
        switch(m.getName()) {
            case "analyzeRequest": {
                IHttpService service;byte[] raw;
                if(a.length==1&&a[0] instanceof IHttpRequestResponse){IHttpRequestResponse msg=(IHttpRequestResponse)a[0];service=msg.getHttpService();raw=msg.getRequest();}
                else if(a.length==2){service=(IHttpService)a[0];raw=(byte[])a[1];}
                else{service=new Service(80);raw=(byte[])a[0];}
                String[] line=headers(raw).get(0).split(" ");
                URL url=new URL(service.getProtocol()+"://"+service.getHost()+":"+service.getPort()+line[1]);
                return proxy(IRequestInfo.class,(x,n,v)->{switch(n.getName()){case "getHeaders":return headers(raw);case "getBodyOffset":return offset(raw);case "getMethod":return line[0];case "getUrl":return url;default:return empty(n.getReturnType());}});
            }
            case "analyzeResponse": {byte[] raw=(byte[])a[0];return proxy(IResponseInfo.class,(x,n,v)->{switch(n.getName()){case "getHeaders":return headers(raw);case "getBodyOffset":return offset(raw);case "getStatusCode":return Short.valueOf(headers(raw).get(0).split(" ")[1]);default:return empty(n.getReturnType());}});}
            case "buildHttpMessage":return build((List<String>)a[0],(byte[])a[1]);
            default:return empty(m.getReturnType());
        }
    });
    static class Harness {
        final List<byte[]> sent=new CopyOnWriteArrayList<byte[]>();
        final List<IScanIssue> issues=new CopyOnWriteArrayList<IScanIssue>();
        final List<Finding> rows=new CopyOnWriteArrayList<Finding>();
        final List<IMessageEditorController> controllers=new CopyOnWriteArrayList<IMessageEditorController>();
        final List<String> errors=new CopyOnWriteArrayList<String>();
        final List<Object[]> repeaters=new CopyOnWriteArrayList<Object[]>();
        boolean scope=true;volatile BiFunction<IHttpService,byte[],byte[]> backend;
        volatile IHttpListener listener;Engine engine;Consumer<IHttpListener> onRegister;
        Harness(){backend=(s,r)->{String origin=Policy.one(Policy.headers(headers(r)),"origin");return response(200,"Access-Control-Allow-Origin: "+origin,"Access-Control-Allow-Credentials: true","Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE","Access-Control-Allow-Headers: authorization, content-type, x-test");};}
        final IBurpExtenderCallbacks callbacks=proxy(IBurpExtenderCallbacks.class,(o,m,a)->{
            switch(m.getName()) {
                case "getHelpers":return HELPERS;
                case "isInScope":return scope;
                case "getStdout":case "getStderr":return new ByteArrayOutputStream();
                case "printError":errors.add(String.valueOf(a[0]));return null;
                case "makeHttpRequest":{IHttpService s=(IHttpService)a[0];byte[] req=(byte[])a[1];sent.add(req);byte[] res=backend.apply(s,req);Message result=new Message(s,req,res);if(listener!=null)listener.processHttpMessage(1024,false,result);return result;}
                case "addScanIssue":issues.add((IScanIssue)a[0]);return null;
                case "registerHttpListener":listener=(IHttpListener)a[0];if(onRegister!=null)onRegister.accept(listener);return null;
                case "removeHttpListener":listener=null;return null;
                case "sendToRepeater":repeaters.add(a);return null;
                case "createMessageEditor":{
                    controllers.add((IMessageEditorController)a[0]);JPanel component=new JPanel();
                    return proxy(IMessageEditor.class,(x,n,v)->{if(n.getName().equals("getComponent"))return component;if(n.getName().equals("setMessage"))ok(SwingUtilities.isEventDispatchThread(),"editor set on EDT");return empty(n.getReturnType());});
                }
                default:return empty(m.getReturnType());
            }
        });
        Engine start(){engine=new Engine(callbacks,rows::add);engine.intervalMillis=1;return engine;}
        Message base(String method,String extra,byte[] body,int port){return new Message(new Service(port),build(Arrays.asList(method+" /api?a=1 HTTP/1.1","Host: 127.0.0.1:"+port,"Cookie: session=fixture",extra),body),response(200));}
        void await()throws Exception{long until=System.currentTimeMillis()+5000;while(System.currentTimeMillis()<until){if(engine.active()==0&&engine.queued()==0&&!rows.isEmpty())return;Thread.sleep(10);}throw new AssertionError("worker timeout");}
    }
    static Map<String,List<String>> hs(String...s){return Policy.headers(Arrays.asList(s));}
    static void policyTests()throws Exception {
        String o="https://attacker.invalid";
        ok(Policy.permits(hs("Access-Control-Allow-Origin: "+o,"Access-Control-Allow-Credentials: true"),o,true),"exact credential policy");
        for(String acao:new String[]{o+".example.org",o+"/",o+", https://other.invalid","*"})ok(!Policy.permits(hs("Access-Control-Allow-Origin: "+acao,"Access-Control-Allow-Credentials: true"),o,true),"reject substring/list/wildcard credentials");
        for(String acac:new String[]{"True","nottrue","true, true","TRUE"})ok(!Policy.permits(hs("Access-Control-Allow-Origin: "+o,"Access-Control-Allow-Credentials: "+acac),o,true),"strict ACAC");
        ok(!Policy.permits(hs("Access-Control-Allow-Origin-Extra: "+o,"Access-Control-Allow-Credentials: true"),o,true),"header exact name");
        ok(!Policy.permits(hs("Access-Control-Allow-Origin: "+o,"Access-Control-Allow-Origin: "+o,"Access-Control-Allow-Credentials: true"),o,true),"duplicate ACAO");
        ok(Policy.permits(hs("Access-Control-Allow-Origin: *"),o,false),"anonymous wildcard");
        ok(Policy.permits(hs("Access-Control-Allow-Origin: null","Access-Control-Allow-Credentials: true"),"null",true),"opaque origin");
        Map<String,List<String>> p=hs("Access-Control-Allow-Origin: "+o,"Access-Control-Allow-Credentials: true","Access-Control-Allow-Methods: PUT","Access-Control-Allow-Headers: authorization, content-type");
        ok(Policy.preflight(p,204,o,"PUT",new TreeSet<String>(Arrays.asList("authorization","content-type")),true),"PUT preflight");
        ok(!Policy.preflight(p,403,o,"PUT",Collections.emptySet(),true),"preflight HTTP failure");
        ok(!Policy.preflight(p,204,o,"DELETE",Collections.emptySet(),true),"method not allowed");
        ok(!Policy.preflight(p,204,o,"PUT",Collections.singleton("x-secret"),true),"header not allowed");
        Map<String,List<String>> wildcard=hs("Access-Control-Allow-Origin: *","Access-Control-Allow-Headers: *","Access-Control-Allow-Methods: *");
        ok(!Policy.preflight(wildcard,204,o,"PUT",Collections.singleton("authorization"),false),"Authorization never wildcard");
        ok(Policy.preflight(wildcard,204,o,"PUT",Collections.singleton("x-test"),false),"anonymous wildcard preflight");
        ok(Policy.requiredHeaders(Arrays.asList("GET / HTTP/1.1","Host: x","Cookie: a=1","Sec-Fetch-Mode: cors","Accept: application/json")).isEmpty(),"browser headers excluded");
        ok(Policy.requiredHeaders(Arrays.asList("Content-Type: application/json","Authorization: Bearer fixture")).equals(new TreeSet<String>(Arrays.asList("authorization","content-type"))),"unsafe script headers");
        ok(Policy.requiredHeaders(Arrays.asList("Content-Type: text/plain;charset=UTF-8","Accept-Language: en-US")).isEmpty(),"simple values");
        ok(Policy.requiredHeaders(Arrays.asList("Range: bytes=0-10")).isEmpty(),"single range safelist");
        ok(!Policy.requiredHeaders(Arrays.asList("Range: bytes=0-10,20-30")).isEmpty(),"multiple range unsafe");
        byte[] binary={0,13,10,(byte)0xff,(byte)0xe4,(byte)0xb8,(byte)0xad};byte[] request=build(Arrays.asList("POST / HTTP/1.1","Host: test"),binary);
        ok(Arrays.equals(Policy.body(request,offset(request)),binary),"binary byte offsets");
        ok(Policy.csv("=1+1").startsWith("\"'"),"CSV formula neutralized");
        ok(Policy.csv("=1+1\nnext").startsWith("\"'"),"multiline CSV formula neutralized");
        ok(Policy.csv("\t=1").startsWith("\"'"),"CSV leading control");
        ok(!Policy.js("</script>").contains("<"),"JS injection escape");
        for(String invalid:new String[]{"https://a.invalid/","https://a.invalid:443","https://u:p@a.invalid","javascript:alert(1)","https://a.invalid?x=1"}){boolean rejected=false;try{Policy.validOrigin(invalid);}catch(IllegalArgumentException e){rejected=true;}ok(rejected,"invalid serialized origin rejected");}
    }
    static void engineTests()throws Exception {
        Harness h=new Harness();Engine e=h.start();Message base=h.base("GET","Accept: application/json",null,8080);
        ok(e.offer(base,false,false).startsWith("已排队"),"enqueue");h.await();ok(h.sent.size()==2,"two default origins");
        ok(h.rows.stream().allMatch(f->f.grade.equals("CREDENTIAL_POLICY")),"strict result");ok(h.issues.size()==1,"issue consolidation");
        ok(e.offer(h.base("POST","Transfer-Encoding: chunked",new byte[]{0},8080),true,true).contains("Transfer-Encoding"),"chunk framing is not silently rewritten");
        int before=h.sent.size();e.offer(base,false,false);Thread.sleep(20);ok(h.sent.size()==before,"dedup");
        h.scope=false;ok(e.offer(base,true,false).contains("scope"),"manual scope");h.scope=true;
        ok(e.offer(h.base("POST","Content-Type: application/json",new byte[]{1},8080),false,false).contains("自动模式"),"no automatic write replay");
        ok(e.offer(h.base("GET",Engine.MARKER+": old-instance",null,8080),true,false).contains("跳过"),"marker recursion prevention");
        e.close();
        h=new Harness();e=h.start();h.backend=(s,r)->response(403,"Access-Control-Allow-Origin: nope");
        e.offer(h.base("POST","Content-Type: application/json",new byte[]{1,2},8080),true,true);h.await();
        ok(h.sent.size()==2&&h.sent.stream().allMatch(r->headers(r).get(0).startsWith("OPTIONS ")),"preflight block prevents actual write");
        ok(h.sent.stream().noneMatch(r->Policy.headers(headers(r)).containsKey("cookie")),"preflight no cookies");e.close();
        h=new Harness();e=h.start();byte[] binary={0,(byte)0xff,13,10,(byte)0xe4,(byte)0xb8,(byte)0xad};
        e.offer(h.base("POST","Content-Type: application/json",binary,8080),true,true);h.await();
        ok(h.sent.size()==4,"OPTIONS then POST each origin");
        for(byte[] r:h.sent)if(headers(r).get(0).startsWith("POST"))ok(Arrays.equals(binary,Policy.body(r,offset(r))),"binary POST preserved");
        ok(h.rows.get(0).preflight!=null,"preflight evidence");
        String html=Poc.build(h.rows.get(0),HELPERS);ok(!html.contains("session=fixture"),"no cookies in PoC");ok(!html.contains(Base64.getEncoder().encodeToString(binary)),"no raw body in PoC");
        java.nio.file.Files.write(java.nio.file.Paths.get("build/browser-check-test.html"),html.getBytes(StandardCharsets.UTF_8));e.close();
        h=new Harness();e=h.start();CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
        h.backend=(s,r)->{entered.countDown();try{release.await(2,TimeUnit.SECONDS);}catch(Exception ex){throw new RuntimeException(ex);}return response(200);};
        e.offer(base,false,false);ok(entered.await(2,TimeUnit.SECONDS),"request in flight");e.pause();release.countDown();Thread.sleep(100);
        ok(h.sent.size()==1&&h.rows.isEmpty(),"pause does not continue origins after in-flight returns");e.close();
        Harness burst=new Harness();Engine be=burst.start();CountDownLatch started=new CountDownLatch(1),finish=new CountDownLatch(1);
        burst.backend=(service,r)->{started.countDown();try{finish.await(3,TimeUnit.SECONDS);}catch(Exception ex){throw new RuntimeException(ex);}return response(200);};
        be.offer(base,false,false);ok(started.await(2,TimeUnit.SECONDS),"burst first active");
        for(int i=0;i<70;i++)be.offer(burst.base("GET","X-Test: "+i,null,8080),false,false);
        ok(be.queued()==64&&be.dropped.get()==6,"bounded queue rejects overflow");be.close();finish.countDown();Thread.sleep(100);
        ok(burst.sent.size()==1&&be.queued()==0,"unload drains queue without more traffic");
    }
    static final String NAV_ACCEPT="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
    static Message navigation(Harness h,String extra) {
        return new Message(new Service(8080),build(Arrays.asList("GET /api?a=1 HTTP/1.1","Host: 127.0.0.1:8080", "Cookie: session=fixture",
            "Sec-Fetch-Mode: navigate","Sec-Fetch-Dest: document","Upgrade-Insecure-Requests: 1","Cache-Control: max-age=0","Pragma: no-cache","Accept: "+NAV_ACCEPT,extra),null),response(200));
    }
    static void navigationTests()throws Exception {
        Harness h=new Harness();Engine e=h.start();e.offer(navigation(h,"Accept-Language: zh-CN,zh;q=0.9"),false,false);h.await();
        ok(h.sent.size()==2&&h.sent.stream().allMatch(r->headers(r).get(0).startsWith("GET ")),"navigation must become a minimal fetch probe rather than blocked OPTIONS");
        ok(h.rows.stream().allMatch(f->f.grade.equals("CREDENTIAL_POLICY")),"navigation reflect positive");
        ok(h.rows.stream().allMatch(f->f.reason.contains("fetch")),"changed profile must be disclosed");
        for(byte[] req:h.sent){Map<String,List<String>> headers=Policy.headers(headers(req));ok("*/*".equals(Policy.one(headers,"accept")),"fetch Accept");ok(!headers.containsKey("upgrade-insecure-requests")&&!headers.containsKey("cache-control")&&!headers.containsKey("pragma"),"navigation hints removed");ok(headers.containsKey("cookie"),"credentials retained for evidence");}
        String poc=Poc.build(h.rows.get(0),HELPERS);ok(!poc.contains("application/xhtml+xml"),"PoC uses actual fetch headers");e.close();
        h=new Harness();e=h.start();e.navigationFetch=false;e.offer(navigation(h,"Accept-Language: en"),false,false);h.await();
        ok(h.sent.size()==2&&h.sent.stream().allMatch(r->headers(r).get(0).startsWith("OPTIONS ")),"strict profile can be restored");
        ok(h.rows.stream().allMatch(f->f.grade.equals("PREFLIGHT_BLOCKED")),"strict profile remains subject to original headers");e.close();
        h=new Harness();e=h.start();e.offer(h.base("GET","Accept: "+NAV_ACCEPT,null,8080),false,false);h.await();
        ok(h.rows.stream().allMatch(f->f.grade.equals("PREFLIGHT_BLOCKED")),"non-navigation long Accept retains genuine preflight requirement");e.close();
        h=new Harness();e=h.start();e.offer(navigation(h,"X-Private-Token: fixture"),false,false);h.await();
        ok(h.rows.stream().allMatch(f->f.grade.equals("PREFLIGHT_BLOCKED")),"navigation business header still blocked");
        for(byte[] req:h.sent)ok("x-private-token".equals(Policy.one(Policy.headers(headers(req)),"access-control-request-headers")),"only true business header appears in preflight");e.close();
        h=new Harness();e=h.start();e.offer(navigation(h,"Authorization: Bearer fixture-secret"),false,false);h.await();
        ok(h.sent.size()==4,"Authorization still requires preflight");
        for(byte[] req:h.sent)if(headers(req).get(0).startsWith("GET "))ok("Bearer fixture-secret".equals(Policy.one(Policy.headers(headers(req)),"authorization")),"Authorization retained in actual request");
        ok(!Poc.build(h.rows.get(0),HELPERS).contains("fixture-secret"),"PoC never exports authorization");e.close();
    }
    static void localHttpTests()throws Exception {
        AtomicInteger received=new AtomicInteger();HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/api",x->{received.incrementAndGet();String origin=x.getRequestHeaders().getFirst("Origin");x.getResponseHeaders().add("Access-Control-Allow-Origin",origin==null?"none":origin);x.getResponseHeaders().add("Access-Control-Allow-Credentials","true");byte[] body="{\"fixture\":true}".getBytes(StandardCharsets.UTF_8);x.sendResponseHeaders(200,body.length);x.getResponseBody().write(body);x.close();});server.start();
        try{Harness h=new Harness();Engine e=h.start();h.backend=(s,r)->{try{
            List<String> lines=headers(r);String[] first=lines.get(0).split(" ");HttpURLConnection c=(HttpURLConnection)new URL("http://127.0.0.1:"+s.getPort()+first[1]).openConnection();
            c.setInstanceFollowRedirects(false);c.setConnectTimeout(2000);c.setReadTimeout(2000);c.setRequestMethod(first[0]);
            for(String line:lines.subList(1,lines.size())){int colon=line.indexOf(':');String name=line.substring(0,colon);if(!name.equalsIgnoreCase("Host"))c.setRequestProperty(name,line.substring(colon+1).trim());}
            int code=c.getResponseCode();List<String> out=new ArrayList<String>();out.add("HTTP/1.1 "+code+" Test");
            c.getHeaderFields().forEach((k,v)->{if(k!=null)for(String value:v)out.add(k+": "+value);});
            ByteArrayOutputStream bytes=new ByteArrayOutputStream();try(InputStream in=c.getInputStream()){byte[] buf=new byte[1024];int n;while((n=in.read(buf))!=-1)bytes.write(buf,0,n);}c.disconnect();return build(out,bytes.toByteArray());
        }catch(Exception ex){throw new RuntimeException(ex);}};
        e.offer(h.base("GET","Accept: application/json",null,server.getAddress().getPort()),false,false);h.await();
        ok(received.get()==2,"actual localhost HTTP probes");ok(h.rows.stream().allMatch(f->f.grade.equals("CREDENTIAL_POLICY")),"local HTTP policy classification");e.close();
        }finally{server.stop(0);}
    }
    static void uiTests()throws Exception {
        Harness h=new Harness();BurpExtender ext=new BurpExtender();ext.registerExtenderCallbacks(h.callbacks);SwingUtilities.invokeAndWait(()->{});
        Field engineField=BurpExtender.class.getDeclaredField("engine");engineField.setAccessible(true);
        h.engine=(Engine)engineField.get(ext);h.engine.intervalMillis=1;
        h.listener.processHttpMessage(IBurpExtenderCallbacks.TOOL_PROXY,false,h.base("GET","Accept: application/json",null,8080));
        waitForIdle(h);SwingUtilities.invokeAndWait(()->{});
        ok(h.engine.intakeCount(Engine.IntakeCode.QUEUED)==1&&h.sent.size()==2,"first response after UI readiness scans without refreshing");
        Message original=h.base("GET","Accept: application/json",null,8080),probe=new Message(original.getHttpService(),original.getRequest(),response(200));
        Finding f=new Finding(original,probe,null,new URL("http://127.0.0.1:8080/api?a=1"),"GET","http://fixture.invalid","random","CREDENTIAL_POLICY","fixture",200,"","");
        Field selected=BurpExtender.class.getDeclaredField("selected");selected.setAccessible(true);selected.set(ext,f);
        ok(h.controllers.size()==6,"six message editors");ok(h.controllers.get(2).getHttpService()!=null,"probe editor service");ok(h.controllers.get(2).getRequest().length>0,"probe editor request context");
        Method send=BurpExtender.class.getDeclaredMethod("send",Finding.class);send.setAccessible(true);
        SwingUtilities.invokeAndWait(()->{try{send.invoke(ext,f);}catch(Exception ex){throw new RuntimeException(ex);}});SwingUtilities.invokeAndWait(()->{});SwingUtilities.invokeAndWait(()->{});
        ok(h.repeaters.size()==1&&h.repeaters.get(0)[4].equals("CORS-1"),"Repeater caption and call");
        ext.extensionUnloaded();SwingUtilities.invokeAndWait(()->{});ok(h.errors.isEmpty(),"UI no initialization errors");
    }
    static void waitForIdle(Harness h)throws Exception {
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);
        while(System.nanoTime()<deadline){if(h.sent.size()==2&&h.engine.active()==0&&h.engine.queued()==0)return;Thread.sleep(5);}
        throw new AssertionError("first response scan did not complete");
    }
    static void firstResponseTests()throws Exception {
        CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
        SwingUtilities.invokeLater(()->{entered.countDown();try{release.await(5,TimeUnit.SECONDS);}catch(InterruptedException ex){Thread.currentThread().interrupt();}});
        ok(entered.await(2,TimeUnit.SECONDS),"EDT held to reproduce startup window");
        Harness h=new Harness();BurpExtender ext=new BurpExtender();
        Field engineField=BurpExtender.class.getDeclaredField("engine");engineField.setAccessible(true);
        // Deliver a response during listener registration, before UI initialization is even queued.
        h.onRegister=listener->{try {
            h.engine=(Engine)engineField.get(ext);h.engine.intervalMillis=1;
            listener.processHttpMessage(IBurpExtenderCallbacks.TOOL_PROXY,false,h.base("GET","Accept: application/json",null,8080));
            waitForIdle(h);
        }catch(Exception ex){throw new RuntimeException(ex);}};
        boolean registered;
        try {ext.registerExtenderCallbacks(h.callbacks);registered=h.listener!=null;}
        finally {release.countDown();}
        SwingUtilities.invokeAndWait(()->{});
        try {
            ok(registered,"HTTP listener must register before EDT initialization finishes");
            ok(h.sent.size()==2&&h.issues.size()==1,"one first response produces two probes without refreshing");
            Field modelField=BurpExtender.class.getDeclaredField("model");modelField.setAccessible(true);
            SwingUtilities.invokeAndWait(()->{try{ok(((javax.swing.table.DefaultTableModel)modelField.get(ext)).getRowCount()==2,"results completed before UI are displayed after initialization");}catch(IllegalAccessException ex){throw new RuntimeException(ex);}});
            ok(h.engine.intakeCount(Engine.IntakeCode.SELF)==2,"startup probes re-enter listener but do not recurse");
            ok(h.engine.intakeCount(Engine.IntakeCode.QUEUED)==1,"first external response was queued exactly once");
            ok(h.errors.isEmpty(),"first response and buffered results have no initialization error");
        } finally {ext.extensionUnloaded();SwingUtilities.invokeAndWait(()->{});}
        ok(h.listener==null,"HTTP listener removed on unload");
    }
    static void intakeTests()throws Exception {
        Harness h=new Harness();Engine e=h.start();h.listener=e::observe;
        Message base=h.base("GET","Accept: application/json",null,8080);
        e.observe(IBurpExtenderCallbacks.TOOL_PROXY,true,base);
        ok(e.received.get()==0,"request-side callbacks are not counted as responses");
        h.scope=false;e.observe(IBurpExtenderCallbacks.TOOL_PROXY,false,base);
        ok(h.sent.isEmpty()&&e.tracked()==0&&e.intakeCount(Engine.IntakeCode.SCOPE)==1,"out-of-scope is visible and never marks dedup");
        h.scope=true;e.observe(IBurpExtenderCallbacks.TOOL_PROXY,false,base);h.await();
        ok(h.sent.size()==2&&h.rows.size()==2,"same first response can be queued after scope becomes eligible");
        ok(e.received.get()==4&&e.intakeCount(Engine.IntakeCode.SELF)==2,"external and recursive callbacks counted separately");
        e.observe(IBurpExtenderCallbacks.TOOL_PROXY,false,base);
        ok(e.intakeCount(Engine.IntakeCode.DUPLICATE)==1&&h.sent.size()==2,"diagnostics do not bypass dedup");
        e.automatic=false;e.observe(IBurpExtenderCallbacks.TOOL_PROXY,false,base);
        ok(e.intakeCount(Engine.IntakeCode.AUTO_OFF)==1,"automatic-off reason visible");e.automatic=true;
        e.pause();e.observe(IBurpExtenderCallbacks.TOOL_PROXY,false,base);
        ok(e.intakeCount(Engine.IntakeCode.PAUSED)==1,"paused reason visible");e.resume();
        e.observe(IBurpExtenderCallbacks.TOOL_PROXY,false,h.base("POST","Content-Type: application/json",new byte[]{1},8080));
        ok(e.intakeCount(Engine.IntakeCode.WRITE_BLOCKED)==1&&h.sent.size()==2,"diagnostics do not introduce automatic writes");
        ok(e.intakeStatus().contains("scopeSkipped=1")&&e.intakeDetails().contains("WRITE_BLOCKED"),"intake counters available to UI");
        ok(!e.intakeStatus().contains("session=fixture")&&!e.intakeDetails().contains("session=fixture"),"diagnostics exclude request authentication");
        int observed=e.received.get();e.close();e.observe(IBurpExtenderCallbacks.TOOL_PROXY,false,base);
        ok(e.received.get()==observed&&h.sent.size()==2,"unloaded listener cannot schedule more work");
    }
    public static void main(String[] args)throws Exception{firstResponseTests();intakeTests();policyTests();engineTests();navigationTests();localHttpTests();uiTests();System.out.println("PASS: "+assertions+" assertions; strict policy, binary requests, preflight, dedup, pause, local HTTP, EDT/controller/Repeater. Burp runtime not tested.");}
}
