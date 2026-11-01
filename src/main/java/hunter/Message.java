package hunter;
import burp.*;
/** A bounded, detached snapshot; no dependency on mutable history messages. */
public final class Message implements IHttpRequestResponse {
    private byte[] request,response;
    private IHttpService service;
    private String comment,highlight;
    public Message(IHttpService service, byte[] request, byte[] response) {
        this.service=service; setRequest(request); setResponse(response);
    }
    public static Message copy(IHttpRequestResponse m) {return new Message(m.getHttpService(),m.getRequest(),m.getResponse());}
    public byte[] getRequest(){return request==null?null:request.clone();}
    public byte[] getResponse(){return response==null?null:response.clone();}
    public void setRequest(byte[] v){request=v==null?null:v.clone();}
    public void setResponse(byte[] v){response=v==null?null:v.clone();}
    public IHttpService getHttpService(){return service;}
    public void setHttpService(IHttpService v){service=v;}
    public String getComment(){return comment;}
    public void setComment(String v){comment=v;}
    public String getHighlight(){return highlight;}
    public void setHighlight(String v){highlight=v;}
}
