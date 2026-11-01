package hunter;
import java.net.URL;
public final class Finding {
    public final Message original,probe,preflight;
    public final URL url;
    public final String method,origin,rule,grade,reason,acao,acac;
    public final int status;
    public Finding(Message original,Message probe,Message preflight,URL url,String method,
                   String origin,String rule,String grade,String reason,int status,String acao,String acac) {
        this.original=original;this.probe=probe;this.preflight=preflight;this.url=url;this.method=method;
        this.origin=origin;this.rule=rule;this.grade=grade;this.reason=reason;this.status=status;this.acao=acao;this.acac=acac;
    }
    public String[] cells(){return new String[]{method,url.toExternalForm(),rule,origin,String.valueOf(status),grade,acao,acac,reason};}
}
