package burp;

import hunter.*;
import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.function.Supplier;

public final class BurpExtender implements IBurpExtender,IHttpListener,IContextMenuFactory,IExtensionStateListener,ITab {
    private IBurpExtenderCallbacks cb;
    private Engine engine;
    private JPanel panel;
    private JTable table;
    private DefaultTableModel model;
    private final List<Finding> rows=new ArrayList<Finding>();
    private volatile Finding selected;
    private final Semaphore uiSlots=new Semaphore(128);
    private final java.util.concurrent.atomic.AtomicInteger displayDropped=new java.util.concurrent.atomic.AtomicInteger();
    private final ThreadPoolExecutor files=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<Runnable>(4),r->{Thread t=new Thread(r,"CORS-Hunter-file");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
    private JLabel status,action;
    private JTextField filter,originField;
    private JCheckBox onlySignals;
    private TableRowSorter<DefaultTableModel> sorter;
    private final List<IMessageEditor> editors=new ArrayList<IMessageEditor>();
    private javax.swing.Timer timer;
    private int repeaterSequence;
    private JMenuItem manualMenu;
    private volatile IHttpRequestResponse[] contextMessages;
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        cb=callbacks;cb.setExtensionName("CORS Hunter 1.0.1");
        engine=new Engine(cb,this::append);
        cb.registerExtensionStateListener(this);
        SwingUtilities.invokeLater(()->{
            if(engine.unloaded.get())return;
            try{init();cb.addSuiteTab(this);cb.registerHttpListener(this);cb.registerContextMenuFactory(this);
                cb.printOutput("CORS Hunter 1.0.1 loaded. Auto: in-scope GET/HEAD. Add targets to Target scope. Java legacy API; no Jython required.");}
            catch(Exception e){engine.error(e);engine.close();}
        });
    }
    private void init() {
        panel=new JPanel(new BorderLayout(6,6));
        manualMenu=new JMenuItem("CORS Hunter: scan selected (manual)");
        manualMenu.addActionListener(e->{IHttpRequestResponse[] msgs=contextMessages;if(msgs!=null)manual(msgs);});
        JPanel controls=new JPanel(new FlowLayout(FlowLayout.LEFT));
        JCheckBox auto=new JCheckBox("Auto GET/HEAD",true),scope=new JCheckBox("Scope only",true),extended=new JCheckBox("Extra origin rules",false),issues=new JCheckBox("Add info issues",true);
        auto.addActionListener(e->engine.automatic=auto.isSelected());
        scope.addActionListener(e->{engine.scopeOnly=scope.isSelected();note(scope.isSelected()?"范围限制已开启":"范围限制已关闭：仅在明确授权目标上测试",false);});
        extended.addActionListener(e->engine.extended=extended.isSelected());issues.addActionListener(e->engine.reportIssues=issues.isSelected());
        JSpinner interval=new JSpinner(new SpinnerNumberModel(500,200,5000,100));
        interval.addChangeListener(e->engine.intervalMillis=((Number)interval.getValue()).longValue());
        for(JComponent c:Arrays.asList(auto,scope,extended,issues))controls.add(c);
        controls.add(new JLabel("Interval ms:"));controls.add(interval);
        JButton pause=new JButton("Pause + cancel queued"),resume=new JButton("Resume"),reset=new JButton("Reset dedup/budget");
        pause.addActionListener(e->{engine.pause();note("已暂停并取消排队；在途请求可能仍执行，返回后不继续发包",false);});
        resume.addActionListener(e->{engine.resume();note("已恢复；取消的任务需要重新触发",false);});
        reset.addActionListener(e->note(engine.reset()?"去重、故障冷却和请求预算已重置":"仍有在途或排队任务，暂不能重置",false));
        controls.add(pause);controls.add(resume);controls.add(reset);
        JPanel tools=new JPanel(new FlowLayout(FlowLayout.LEFT));
        filter=new JTextField(14);onlySignals=new JCheckBox("Signals only");
        filter.addActionListener(e->applyFilter());onlySignals.addActionListener(e->applyFilter());
        tools.add(new JLabel("Filter:"));tools.add(filter);tools.add(onlySignals);
        JCheckBox fetchProfile=new JCheckBox("Navigation -> fetch",true);
        fetchProfile.setToolTipText("仅导航 GET/HEAD：Accept 改为 */*，去除导航提示和缓存头；业务头仍保留并检查预检");
        fetchProfile.addActionListener(e->engine.navigationFetch=fetchProfile.isSelected());tools.add(fetchProfile);
        originField=new JTextField(22);JButton apply=new JButton("Set custom Origin");
        apply.addActionListener(e->{try{String v=originField.getText().trim();engine.customOrigin=v.isEmpty()?"":Policy.validOrigin(v);note("自定义 Origin 已更新；空值表示不追加",false);}catch(Exception ex){note(ex.getMessage(),true);}});
        tools.add(originField);tools.add(apply);
        JButton repeater=new JButton("Send probe to Repeater"),rescan=new JButton("Rescan selected"),poc=new JButton("Export browser check"),csv=new JButton("Export CSV"),clear=new JButton("Clear results");
        repeater.addActionListener(e->toRepeater());rescan.addActionListener(e->{Finding f=selection();if(f!=null)manual(new IHttpRequestResponse[]{f.original});});
        poc.addActionListener(e->exportPoc());csv.addActionListener(e->exportCsv());
        clear.addActionListener(e->SwingUtilities.invokeLater(()->{rows.clear();model.setRowCount(0);selected=null;show(null);note("已清显示；去重及任务保持，可另用 Reset",false);}));
        JPanel actions=new JPanel(new FlowLayout(FlowLayout.LEFT));for(JButton b:Arrays.asList(repeater,rescan,poc,csv,clear))actions.add(b);
        JPanel top=new JPanel(new GridLayout(0,1));top.add(controls);top.add(tools);top.add(actions);panel.add(top,BorderLayout.NORTH);
        String[] columns={"Method","URL","Rule","Origin","HTTP","Result","ACAO","ACAC","Reason"};
        model=new DefaultTableModel(columns,0){private static final long serialVersionUID=1;public boolean isCellEditable(int r,int c){return false;}};
        table=new JTable(model);table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        DefaultTableCellRenderer textRenderer=new DefaultTableCellRenderer();textRenderer.putClientProperty("html.disable",Boolean.TRUE);table.setDefaultRenderer(Object.class,textRenderer);
        sorter=new TableRowSorter<DefaultTableModel>(model);table.setRowSorter(sorter);table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        int[] widths={70,320,80,260,60,190,240,100,600};for(int i=0;i<widths.length;i++)table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        table.getSelectionModel().addListSelectionListener(e->{if(!e.getValueIsAdjusting()){Finding f=selection();selected=f;if(f!=null)note(f.reason,false);SwingUtilities.invokeLater(()->{if(selected==f)show(f);});}});
        table.addMouseListener(new MouseAdapter(){public void mouseClicked(MouseEvent e){if(e.getClickCount()==2&&SwingUtilities.isLeftMouseButton(e)){int row=table.rowAtPoint(e.getPoint());if(row>=0){Finding f=rows.get(table.convertRowIndexToModel(row));send(f);}}}});
        JTabbedPane details=new JTabbedPane();
        for(int kind=0;kind<3;kind++)for(int type=0;type<2;type++) {
            final int which=kind;final boolean request=type==0;
            Supplier<Message> message=()->message(selected,which);
            IMessageEditor editor=cb.createMessageEditor(new IMessageEditorController(){
                public IHttpService getHttpService(){Message m=message.get();return m==null?null:m.getHttpService();}
                public byte[] getRequest(){Message m=message.get();return m==null?new byte[0]:m.getRequest();}
                public byte[] getResponse(){Message m=message.get();return m==null?new byte[0]:m.getResponse();}
            },false);
            editors.add(editor);details.addTab(new String[]{"Original","Probe","Preflight"}[kind]+(request?" Request":" Response"),editor.getComponent());
        }
        JSplitPane split=new JSplitPane(JSplitPane.VERTICAL_SPLIT,new JScrollPane(table),details);split.setResizeWeight(.50);panel.add(split,BorderLayout.CENTER);
        status=new JLabel("Ready");action=new JLabel("请先在 Burp Target 中添加 scope；双击结果可送入 Repeater");
        JPanel footer=new JPanel(new GridLayout(0,1));footer.add(status);footer.add(action);panel.add(footer,BorderLayout.SOUTH);
        cb.customizeUiComponent(panel);
        timer=new javax.swing.Timer(1000,e->status.setText((engine.paused.get()?"PAUSED":"RUNNING")+" | sent="+engine.sent.get()+" queued="+engine.queued()+" active="+engine.active()+" contexts="+engine.tracked()+" rows="+rows.size()+" dropped="+(engine.dropped.get()+displayDropped.get())));timer.start();
    }
    private static Message message(Finding f,int kind){return f==null?null:kind==0?f.original:kind==1?f.probe:f.preflight;}
    private Finding selection(){int view=table.getSelectedRow();if(view<0)return null;int row=table.convertRowIndexToModel(view);return row>=0&&row<rows.size()?rows.get(row):null;}
    private void show(Finding f){for(int i=0;i<editors.size();i++){Message m=message(f,i/2);boolean req=i%2==0;byte[] b=m==null?null:req?m.getRequest():m.getResponse();editors.get(i).setMessage(b==null?new byte[0]:b,req);}}
    private void applyFilter(){SwingUtilities.invokeLater(()->{final String q=filter.getText().toLowerCase(Locale.ROOT);final boolean signals=onlySignals.isSelected();sorter.setRowFilter(new RowFilter<DefaultTableModel,Integer>(){
        public boolean include(Entry<? extends DefaultTableModel,? extends Integer> entry){Finding f=rows.get(entry.getIdentifier());if(signals&&(f.grade.equals("MISS")||f.grade.equals("HEADER_ONLY")))return false;return String.join(" ",f.cells()).toLowerCase(Locale.ROOT).contains(q);}
    });});}
    private void append(Finding f) {
        if(!uiSlots.tryAcquire()){displayDropped.incrementAndGet();return;}
        SwingUtilities.invokeLater(()->{try{if(engine.unloaded.get())return;if(rows.size()>=200){displayDropped.incrementAndGet();return;}rows.add(f);model.addRow(f.cells());}finally{uiSlots.release();}});
    }
    private void note(String text,boolean alert){SwingUtilities.invokeLater(()->{if(engine.unloaded.get())return;action.setText(text);if(alert)JOptionPane.showMessageDialog(panel,text,"CORS Hunter",JOptionPane.WARNING_MESSAGE);});}
    public void processHttpMessage(int tool,boolean request,IHttpRequestResponse message) {
        if(request||!engine.automatic||engine.unloaded.get()||engine.paused.get())return;
        String result=engine.offer(message,false,false);
        if(result.contains("失败"))engine.log(result);
    }
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        if(engine.unloaded.get()||manualMenu==null)return null;
        IHttpRequestResponse[] msgs=invocation.getSelectedMessages();if(msgs==null||msgs.length==0)return null;
        contextMessages=msgs.clone();
        return Collections.singletonList(manualMenu);
    }
    private void manual(IHttpRequestResponse[] messages) {
        if(messages.length>20){note("一次最多手动选择 20 条消息",true);return;}
        boolean writes=false;
        for(IHttpRequestResponse m:messages){String method=cb.getHelpers().analyzeRequest(m).getMethod();if(!method.equals("GET")&&!method.equals("HEAD"))writes=true;}
        if(writes&&JOptionPane.showConfirmDialog(panel,"包含写操作：可能重放原始正文及认证信息，每个 Origin 都可能重复业务操作。\n默认测试 random/null 两类；开启扩展规则还会增加请求。继续？","确认手动重放",JOptionPane.YES_NO_OPTION,JOptionPane.WARNING_MESSAGE)!=JOptionPane.YES_OPTION)return;
        for(IHttpRequestResponse m:messages)note(engine.offer(m,true,writes),false);
    }
    private void toRepeater(){Finding f=selection();if(f==null){note("请先选中结果行",true);return;}send(f);}
    private void send(Finding f){
        final Message m=f.probe!=null?f.probe:f.preflight;
        if(m==null){note("此行没有可发送的探测请求；请查看 Reason",true);return;}
        final String caption="CORS-"+(++repeaterSequence);
        SwingUtilities.invokeLater(()->{try{IHttpService s=m.getHttpService();cb.sendToRepeater(s.getHost(),s.getPort(),s.getProtocol().equalsIgnoreCase("https"),m.getRequest(),caption);note("API 已接受请求；打开 Repeater > "+caption+"，点击 Send 才发包",false);engine.log("Repeater: "+caption);}catch(Exception e){engine.error(e);note("发送失败，查看 Extensions > Errors",true);}});
    }
    private Path choose(String suffix){JFileChooser chooser=new JFileChooser();if(chooser.showSaveDialog(panel)!=JFileChooser.APPROVE_OPTION)return null;Path path=chooser.getSelectedFile().toPath();if(!path.toString().toLowerCase(Locale.ROOT).endsWith(suffix))path=Paths.get(path+suffix);if(Files.exists(path)&&JOptionPane.showConfirmDialog(panel,"文件已存在，覆盖？","CORS Hunter",JOptionPane.YES_NO_OPTION)!=JOptionPane.YES_OPTION)return null;return path;}
    private void write(Path path,String text){try{files.execute(()->{try{Files.write(path,text.getBytes(StandardCharsets.UTF_8));note("已保存："+path.getFileName(),false);}catch(Exception e){engine.error(e);note("保存失败，查看 Errors",true);}});}catch(RejectedExecutionException e){note("文件任务繁忙或扩展已卸载",true);}}
    private void exportCsv(){Path path=choose(".csv");if(path==null)return;StringBuilder b=new StringBuilder("\ufeff");for(int i=-1;i<rows.size();i++){String[] values=i==-1?new String[]{"Method","URL","Rule","Origin","HTTP","Result","ACAO","ACAC","Reason"}:rows.get(i).cells();for(int j=0;j<values.length;j++){if(j>0)b.append(',');b.append(Policy.csv(values[j]));}b.append("\r\n");}write(path,b.toString());}
    private void exportPoc(){Finding f=selection();if(f==null){note("请先选中结果行",true);return;}Path path=choose(".html");if(path!=null)write(path,Poc.build(f,cb.getHelpers()));}
    public void extensionUnloaded(){engine.close();files.shutdown();cb.removeHttpListener(this);cb.removeContextMenuFactory(this);SwingUtilities.invokeLater(()->{if(timer!=null)timer.stop();});}
    public String getTabCaption(){return "CORS Hunter";}
    public Component getUiComponent(){return panel;}
}
