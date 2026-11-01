package hunter;
import burp.*;
import java.net.URL;
import java.util.*;
public final class Issue implements IScanIssue {
    private final Finding f;
    public Issue(Finding f){this.f=f;}
    public URL getUrl(){return f.url;}
    public String getIssueName(){return "CORS credential policy accepted an untrusted Origin (review required)";}
    public int getIssueType(){return 0;}
    public String getSeverity(){return "Information";}
    public String getConfidence(){return "Tentative";}
    public String getIssueBackground(){return "CORS response headers can permit a different origin to read responses. Header acceptance alone does not establish browser credential delivery, sensitive data exposure, or exploitability.";}
    public String getRemediationBackground(){return "Use exact trusted origins. Avoid enabling credentialed cross-origin reads of sensitive data for untrusted origins.";}
    public String getIssueDetail(){return "<p>Origin: <b>"+Policy.html(f.origin)+"</b></p><p>Rule: "+Policy.html(f.rule)+"; HTTP status: "+f.status+"</p><p>"+Policy.html(f.reason)+"</p><p>ACAO: "+Policy.html(f.acao)+"<br>ACAC: "+Policy.html(f.acac)+"</p><p>Review the original, preflight (if needed), and probe messages. Confirm browser behavior separately. Public response data is not automatically a vulnerability.</p>";}
    public String getRemediationDetail(){return null;}
    public IHttpRequestResponse[] getHttpMessages(){
        List<IHttpRequestResponse> msgs=new ArrayList<IHttpRequestResponse>();msgs.add(f.original);
        if(f.preflight!=null)msgs.add(f.preflight);msgs.add(f.probe);return msgs.toArray(new IHttpRequestResponse[0]);
    }
    public IHttpService getHttpService(){return f.original.getHttpService();}
}
