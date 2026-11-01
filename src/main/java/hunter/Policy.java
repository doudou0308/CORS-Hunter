package hunter;

import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Pure CORS checks; intentionally makes no claim about data sensitivity. */
public final class Policy {
    private Policy() {}
    public static Map<String,List<String>> headers(List<String> lines) {
        Map<String,List<String>> out = new LinkedHashMap<String,List<String>>();
        for (String line : lines) {
            int colon = line.indexOf(':');
            if (colon <= 0) continue;
            String name = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
            String value = line.substring(colon + 1).trim();
            if (!out.containsKey(name)) out.put(name, new ArrayList<String>());
            out.get(name).add(value);
        }
        return out;
    }
    public static String one(Map<String,List<String>> h, String key) {
        List<String> v = h.get(key);
        return v == null || v.size() != 1 ? null : v.get(0);
    }
    public static String display(Map<String,List<String>> h, String key) {
        List<String> v = h.get(key);
        return v == null ? "" : v.toString();
    }
    public static boolean permits(Map<String,List<String>> h, String origin, boolean credentials) {
        String a = one(h, "access-control-allow-origin");
        if (a == null || !(a.equals(origin) || (!credentials && a.equals("*")))) return false;
        return !credentials || "true".equals(one(h, "access-control-allow-credentials"));
    }
    public static boolean navigation(List<String> lines) {
        return "navigate".equals(one(headers(lines),"sec-fetch-mode"));
    }
    public static boolean simpleMethod(String m) {
        return m.equals("GET") || m.equals("HEAD") || m.equals("POST");
    }
    private static boolean unsafeByte(String s) {
        for (int i=0; i<s.length(); i++) {
            char c=s.charAt(i);
            if ((c<32 && c!=9) || c==127 || "\"():<>?@[\\]{}".indexOf(c)>=0) return true;
        }
        return false;
    }
    static boolean safeValue(String name, String value) {
        if (value.getBytes(StandardCharsets.UTF_8).length>128) return false;
        if (name.equals("accept")) return !unsafeByte(value);
        if (name.equals("accept-language") || name.equals("content-language"))
            return value.matches("[0-9A-Za-z *,\\-.;=]*");
        if (name.equals("content-type")) {
            if (unsafeByte(value)) return false;
            String type=value.split(";",2)[0].trim().toLowerCase(Locale.ROOT);
            return type.equals("application/x-www-form-urlencoded") || type.equals("multipart/form-data") || type.equals("text/plain");
        }
        return name.equals("range") && value.matches("bytes=[0-9]+-[0-9]*");
    }
    public static boolean browserHeader(String name) {
        return name.startsWith("sec-") || name.startsWith("proxy-") || Arrays.asList(
            "accept-charset","accept-encoding","access-control-request-headers","access-control-request-method",
            "connection","content-length","cookie","cookie2","date","dnt","expect","host","keep-alive",
            "origin","referer","te","trailer","transfer-encoding","upgrade","user-agent","via","priority"
        ).contains(name) || name.equals("x-cors-hunter-probe");
    }
    /** A conservative reconstruction of script-controlled request headers from wire traffic. */
    public static SortedSet<String> requiredHeaders(List<String> lines) {
        Map<String,List<String>> h=headers(lines);
        SortedSet<String> required=new TreeSet<String>();
        List<String> safeNames=new ArrayList<String>();
        int safeSize=0;
        for (Map.Entry<String,List<String>> e:h.entrySet()) {
            String name=e.getKey();
            if (browserHeader(name)) continue;
            String value=String.join(", ",e.getValue());
            if (!safeValue(name,value)) required.add(name);
            else { safeNames.add(name); safeSize+=value.getBytes(StandardCharsets.UTF_8).length; }
        }
        if (safeSize>1024) required.addAll(safeNames);
        return required;
    }
    private static Set<String> tokens(Map<String,List<String>> h,String name,boolean lower) {
        Set<String> out=new HashSet<String>();
        List<String> values=h.get(name);
        if(values!=null) for(String value:values) for(String token:value.split(",")) {
            String s=token.trim(); out.add(lower?s.toLowerCase(Locale.ROOT):s);
        }
        return out;
    }
    public static boolean preflight(Map<String,List<String>> h,int status,String origin,
                                    String method,Set<String> required,boolean credentials) {
        if(status<200 || status>=300 || !permits(h,origin,credentials)) return false;
        Set<String> methods=tokens(h,"access-control-allow-methods",false);
        if(!simpleMethod(method) && !methods.contains(method) && !(methods.contains("*")&&!credentials)) return false;
        Set<String> allowed=tokens(h,"access-control-allow-headers",true);
        for(String name:required) {
            if(allowed.contains(name)) continue;
            if(allowed.contains("*")&&!credentials&&!name.equals("authorization")) continue;
            return false;
        }
        return true;
    }
    public static byte[] body(byte[] request,int offset) {
        if(offset<0 || offset>request.length) throw new IllegalArgumentException("Invalid body offset");
        return Arrays.copyOfRange(request,offset,request.length);
    }
    public static String origin(URL u) {
        int p=u.getPort()==-1?u.getDefaultPort():u.getPort();
        String host=u.getHost().toLowerCase(Locale.ROOT);
        return u.getProtocol().toLowerCase(Locale.ROOT)+"://"+host+(p==u.getDefaultPort()?"":":"+p);
    }
    public static String validOrigin(String value) {
        if(value.equals("null")) return value;
        try {
            URI u=new URI(value);
            if(!("http".equals(u.getScheme())||"https".equals(u.getScheme())) || u.getHost()==null ||
                u.getRawUserInfo()!=null || u.getRawQuery()!=null || u.getRawFragment()!=null ||
                (u.getRawPath()!=null&&!u.getRawPath().isEmpty()) || u.getPort()>65535 || u.getPort()==0)
                throw new IllegalArgumentException("Origin must be scheme://host[:port], without path");
            String normalized=origin(u.toURL());
            if(!normalized.equals(value)) throw new IllegalArgumentException("Use serialized Origin: "+normalized);
            return value;
        } catch (URISyntaxException|MalformedURLException e) {throw new IllegalArgumentException("Invalid Origin",e);}
    }
    public static String html(String s) {
        return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;").replace("'","&#39;");
    }
    public static String csv(String s) {
        String check=s.replaceFirst("^[\\s\\uFEFF]+","");
        if((!check.isEmpty() && "=+@-＝＋＠－".indexOf(check.charAt(0))>=0) || s.startsWith("\t") || s.startsWith("\r") || s.startsWith("\n")) s="'"+s;
        return "\""+s.replace("\"","\"\"")+"\"";
    }
    public static String js(String s) {
        StringBuilder b=new StringBuilder("\"");
        for(char c:s.toCharArray()) {
            if(c=='"'||c=='\\') b.append('\\').append(c);
            else if(c<32 || c=='<' || c=='>' || c=='&' || c==0x2028 || c==0x2029)
                b.append(String.format(Locale.ROOT,"\\u%04x",(int)c));
            else b.append(c);
        }
        return b.append('"').toString();
    }
}
