# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IContextMenuFactory, IContextMenuInvocation
from burp import IHttpListener, IMessageEditorController
from javax.swing import (JPanel, JButton, JTextArea, JScrollPane, JLabel, 
                         JComboBox, JCheckBox, JTable, JTabbedPane, JSplitPane,
                         JTextField, JMenu, JMenuItem, SwingUtilities, JOptionPane,
                         BorderFactory, BoxLayout, Box, ListSelectionModel,
                         JFileChooser)
from javax.swing.border import TitledBorder
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, FlowLayout, Font, Dimension, Color, GridLayout
from java.awt.event import ActionListener, MouseAdapter
from java.lang import Runnable, Thread
from java.io import PrintWriter
from java.util import ArrayList
import sys
import codecs

EXTENSION_NAME = "WAF Bypass Encoder"
VERSION = "1.0"

ENCODINGS = [
    ("IBM037", "EBCDIC"),
    ("IBM500", "EBCDIC"),
    ("IBM1026", "EBCDIC"),
    ("UTF-16", "Unicode"),
    ("UTF-16BE", "Unicode"),
    ("UTF-16LE", "Unicode"),
    ("UTF-32", "Unicode"),
    ("UTF-32BE", "Unicode"),
    ("UTF-32LE", "Unicode"),
    ("ISO-8859-1", "ISO"),
    ("ISO-8859-15", "ISO"),
    ("Windows-1252", "Windows"),
]

CONTENT_TYPES = [
    "text/xml; charset={encoding}",
    "application/xml; charset={encoding}",
    "application/json; charset={encoding}",
    "application/x-www-form-urlencoded; charset={encoding}",
    "text/plain; charset={encoding}",
    "application/octet-stream",
]


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.registerContextMenuFactory(self)
        SwingUtilities.invokeLater(self._createUI)
        self._stdout.println("=" * 50)
        self._stdout.println("%s v%s loaded!" % (EXTENSION_NAME, VERSION))
        self._stdout.println("=" * 50)
    
    def _createUI(self):
        self._panel = WAFBypassPanel(self._callbacks, self._helpers, self._stdout)
        self._callbacks.addSuiteTab(self)
    
    def getTabCaption(self):
        return EXTENSION_NAME
    
    def getUiComponent(self):
        return self._panel
    
    def createMenuItems(self, invocation):
        return self._panel.createContextMenu(invocation)


class EncodingEngine:
    
    @staticmethod
    def encode(data, encoding):
        encoding_upper = encoding.upper().replace("-", "").replace("_", "")
        try:
            if encoding_upper in ["IBM037", "CP037"]:
                return data.encode("cp037")
            elif encoding_upper in ["IBM500", "CP500"]:
                return data.encode("cp500")
            elif encoding_upper in ["IBM1026", "CP1026"]:
                return data.encode("cp1026")
            elif encoding_upper == "UTF16":
                return data.encode("utf-16")
            elif encoding_upper == "UTF16BE":
                return data.encode("utf-16-be")
            elif encoding_upper == "UTF16LE":
                return data.encode("utf-16-le")
            elif encoding_upper == "UTF32":
                return data.encode("utf-32")
            elif encoding_upper == "UTF32BE":
                return data.encode("utf-32-be")
            elif encoding_upper == "UTF32LE":
                return data.encode("utf-32-le")
            elif encoding_upper in ["ISO88591", "LATIN1"]:
                return data.encode("iso-8859-1")
            elif encoding_upper == "ISO885915":
                return data.encode("iso-8859-15")
            elif encoding_upper in ["WINDOWS1252", "CP1252"]:
                return data.encode("windows-1252")
            else:
                return data.encode(encoding)
        except Exception as e:
            raise Exception("Encoding error: %s" % str(e))
    
    @staticmethod
    def get_charset_name(encoding):
        encoding_map = {
            "IBM037": "ibm037",
            "IBM500": "ibm500",
            "IBM1026": "ibm1026",
            "UTF-16": "utf-16",
            "UTF-16BE": "utf-16be",
            "UTF-16LE": "utf-16le",
            "UTF-32": "utf-32",
            "UTF-32BE": "utf-32be",
            "UTF-32LE": "utf-32le",
            "ISO-8859-1": "iso-8859-1",
            "ISO-8859-15": "iso-8859-15",
            "Windows-1252": "windows-1252",
        }
        return encoding_map.get(encoding, encoding.lower())


class FuzzResult:
    def __init__(self, encoding, encoding_type, content_type, encoded_request):
        self.encoding = encoding
        self.encoding_type = encoding_type
        self.content_type = content_type
        self.encoded_request = encoded_request
        self.response = None
        self.status_code = -1
        self.response_length = 0
        self.response_time = 0
        self.note = "Ready"


class WAFBypassPanel(JPanel):
    
    def __init__(self, callbacks, helpers, stdout):
        JPanel.__init__(self)
        self._callbacks = callbacks
        self._helpers = helpers
        self._stdout = stdout
        self._engine = EncodingEngine()
        self._fuzz_results = {}
        self._current_request = None
        self._current_http_service = None
        self._initUI()
    
    def _initUI(self):
        self.setLayout(BorderLayout(5, 5))
        self.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        control_panel = self._createControlPanel()
        self.add(control_panel, BorderLayout.NORTH)
        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        main_split.setResizeWeight(0.6)
        request_tabs = JTabbedPane()
        request_tabs.addTab("Full Request", self._createRequestPanel())
        request_tabs.addTab("Request Body", self._createBodyPanel())
        request_tabs.addTab("Encoded Output", self._createOutputPanel())
        main_split.setTopComponent(request_tabs)
        bottom_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        bottom_split.setResizeWeight(0.5)
        bottom_split.setLeftComponent(self._createFuzzResultPanel())
        detail_tabs = JTabbedPane()
        detail_tabs.addTab("Request Detail", self._createDetailPanel())
        detail_tabs.addTab("Log", self._createLogPanel())
        bottom_split.setRightComponent(detail_tabs)
        main_split.setBottomComponent(bottom_split)
        self.add(main_split, BorderLayout.CENTER)
    
    def _createControlPanel(self):
        panel = JPanel(BorderLayout())
        panel.setBorder(TitledBorder("Encoding Settings"))
        rows = JPanel()
        rows.setLayout(BoxLayout(rows, BoxLayout.Y_AXIS))
        row1 = JPanel(FlowLayout(FlowLayout.LEFT, 10, 5))
        row1.add(JLabel("Target Host:"))
        self._host_field = JTextField(20)
        row1.add(self._host_field)
        row1.add(JLabel("Port:"))
        self._port_field = JTextField("80", 5)
        row1.add(self._port_field)
        self._https_check = JCheckBox("HTTPS", False)
        row1.add(self._https_check)
        row1.add(Box.createHorizontalStrut(20))
        row1.add(JLabel("Encoding:"))
        encoding_names = [e[0] for e in ENCODINGS]
        self._encoding_combo = JComboBox(encoding_names)
        row1.add(self._encoding_combo)
        rows.add(row1)
        row2 = JPanel(FlowLayout(FlowLayout.LEFT, 10, 5))
        row2.add(JLabel("Content-Type:"))
        self._content_type_combo = JComboBox(CONTENT_TYPES)
        self._content_type_combo.setEditable(True)
        self._content_type_combo.setPreferredSize(Dimension(300, 25))
        row2.add(self._content_type_combo)
        self._update_ct_check = JCheckBox("Update Content-Type", True)
        self._update_cl_check = JCheckBox("Update Content-Length", True)
        row2.add(self._update_ct_check)
        row2.add(self._update_cl_check)
        rows.add(row2)
        row3 = JPanel(FlowLayout(FlowLayout.LEFT, 10, 5))
        encode_btn = JButton("Encode Request")
        encode_btn.addActionListener(lambda e: self._doEncode())
        row3.add(encode_btn)
        fuzz_btn = JButton("Fuzz All")
        fuzz_btn.setBackground(Color(255, 200, 100))
        fuzz_btn.addActionListener(lambda e: self._doFuzzAll())
        row3.add(fuzz_btn)
        send_btn = JButton("Send Selected")
        send_btn.setBackground(Color(100, 200, 255))
        send_btn.addActionListener(lambda e: self._doSendSelected())
        row3.add(send_btn)
        send_all_btn = JButton("Send All Fuzz")
        send_all_btn.setBackground(Color(100, 255, 100))
        send_all_btn.addActionListener(lambda e: self._doSendAllFuzz())
        row3.add(send_all_btn)
        clear_btn = JButton("Clear")
        clear_btn.addActionListener(lambda e: self._doClear())
        row3.add(clear_btn)
        rows.add(row3)
        panel.add(rows, BorderLayout.CENTER)
        return panel
    
    def _createRequestPanel(self):
        panel = JPanel(BorderLayout())
        panel.setBorder(TitledBorder("Full HTTP Request (Editable)"))
        self._request_area = JTextArea()
        self._request_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._request_area.setText(
            "POST /api/test HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 35\r\n"
            "\r\n"
            '{"username":"admin","pwd":"test"}'
        )
        scroll = JScrollPane(self._request_area)
        panel.add(scroll, BorderLayout.CENTER)
        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        paste_btn = JButton("Paste")
        paste_btn.addActionListener(lambda e: self._request_area.paste())
        btn_panel.add(paste_btn)
        parse_btn = JButton("Parse & Extract")
        parse_btn.addActionListener(lambda e: self._parseRequest())
        btn_panel.add(parse_btn)
        sync_btn = JButton("Sync Body to Editor")
        sync_btn.addActionListener(lambda e: self._syncBody())
        btn_panel.add(sync_btn)
        panel.add(btn_panel, BorderLayout.SOUTH)
        return panel
    
    def _createBodyPanel(self):
        panel = JPanel(BorderLayout())
        panel.setBorder(TitledBorder("Request Body (Only this part will be encoded)"))
        self._body_area = JTextArea()
        self._body_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._body_area.setLineWrap(True)
        scroll = JScrollPane(self._body_area)
        panel.add(scroll, BorderLayout.CENTER)
        return panel
    
    def _createOutputPanel(self):
        panel = JPanel(BorderLayout())
        panel.setBorder(TitledBorder("Encoded Request"))
        self._output_area = JTextArea()
        self._output_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._output_area.setEditable(False)
        scroll = JScrollPane(self._output_area)
        panel.add(scroll, BorderLayout.CENTER)
        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        copy_btn = JButton("Copy All")
        copy_btn.addActionListener(lambda e: self._copyOutput())
        btn_panel.add(copy_btn)
        panel.add(btn_panel, BorderLayout.SOUTH)
        return panel
    
    def _createFuzzResultPanel(self):
        panel = JPanel(BorderLayout())
        panel.setBorder(TitledBorder("Fuzz Results (Click to view details)"))
        columns = ["#", "Encoding", "Content-Type", "Status", "Length", "Time(ms)", "Note"]
        self._table_model = DefaultTableModel(columns, 0)
        self._result_table = JTable(self._table_model)
        self._result_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._result_table.getSelectionModel().addListSelectionListener(
            lambda e: self._onResultSelected(e)
        )
        class DoubleClickListener(MouseAdapter):
            def __init__(self, panel):
                self._panel = panel
            def mouseClicked(self, e):
                if e.getClickCount() == 2:
                    self._panel._doSendSelected()
        self._result_table.addMouseListener(DoubleClickListener(self))
        scroll = JScrollPane(self._result_table)
        panel.add(scroll, BorderLayout.CENTER)
        toolbar = JPanel(FlowLayout(FlowLayout.LEFT))
        clear_btn = JButton("Clear Results")
        clear_btn.addActionListener(lambda e: self._clearResults())
        toolbar.add(clear_btn)
        panel.add(toolbar, BorderLayout.SOUTH)
        return panel
    
    def _createDetailPanel(self):
        panel = JPanel(BorderLayout())
        panel.setBorder(TitledBorder("Selected Fuzz Request Detail"))
        self._detail_area = JTextArea()
        self._detail_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._detail_area.setEditable(False)
        self._detail_area.setText("# Click on a row in the Fuzz Results table to view details\n# Double-click to send the request")
        scroll = JScrollPane(self._detail_area)
        panel.add(scroll, BorderLayout.CENTER)
        return panel
    
    def _createLogPanel(self):
        panel = JPanel(BorderLayout())
        self._log_area = JTextArea()
        self._log_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._log_area.setEditable(False)
        scroll = JScrollPane(self._log_area)
        panel.add(scroll, BorderLayout.CENTER)
        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        clear_btn = JButton("Clear Log")
        clear_btn.addActionListener(lambda e: self._log_area.setText(""))
        btn_panel.add(clear_btn)
        panel.add(btn_panel, BorderLayout.SOUTH)
        return panel
    
    def _log(self, message):
        import java.time.LocalTime as LocalTime
        time_str = str(LocalTime.now())[:8]
        self._log_area.append("[%s] %s\n" % (time_str, message))
        self._log_area.setCaretPosition(self._log_area.getDocument().getLength())
        self._stdout.println(message)
    
    def _parseRequest(self):
        raw_request = self._request_area.getText()
        if not raw_request:
            JOptionPane.showMessageDialog(self, "Please enter a valid HTTP request")
            return
        raw_request = raw_request.replace("\r\n", "\n").replace("\n", "\r\n")
        for line in raw_request.split("\r\n"):
            if line.lower().startswith("host:"):
                host_value = line[5:].strip()
                if ":" in host_value:
                    parts = host_value.split(":")
                    self._host_field.setText(parts[0])
                    self._port_field.setText(parts[1])
                else:
                    self._host_field.setText(host_value)
                break
        if "\r\n\r\n" in raw_request:
            body = raw_request.split("\r\n\r\n", 1)[1]
            self._body_area.setText(body)
            self._log("[+] Request parsed, body length: %d chars" % len(body))
        else:
            self._log("[*] No request body found")
    
    def _syncBody(self):
        raw_request = self._request_area.getText()
        if "\r\n\r\n" in raw_request:
            body = raw_request.split("\r\n\r\n", 1)[1]
            self._body_area.setText(body)
        elif "\n\n" in raw_request:
            body = raw_request.split("\n\n", 1)[1]
            self._body_area.setText(body)
    
    def _extractBody(self, raw_request):
        raw_request = raw_request.replace("\r\n", "\n").replace("\n", "\r\n")
        if "\r\n\r\n" in raw_request:
            return raw_request.split("\r\n\r\n", 1)[1]
        return ""
    
    def _buildRequest(self, template_request, encoded_body, content_type):
        template_request = template_request.replace("\r\n", "\n").replace("\n", "\r\n")
        if "\r\n\r\n" in template_request:
            headers = template_request.split("\r\n\r\n")[0]
        else:
            headers = template_request
        while headers.endswith("\r\n"):
            headers = headers[:-2]
        lines = headers.split("\r\n")
        new_headers = []
        found_ct = False
        found_cl = False
        for line in lines:
            if not line:
                continue
            line_lower = line.lower()
            if line_lower.startswith("content-type:") and self._update_ct_check.isSelected():
                new_headers.append("Content-Type: %s" % content_type)
                found_ct = True
                continue
            if line_lower.startswith("content-length:") and self._update_cl_check.isSelected():
                new_headers.append("Content-Length: %d" % len(encoded_body))
                found_cl = True
                continue
            new_headers.append(line)
        if not found_ct and self._update_ct_check.isSelected():
            new_headers.append("Content-Type: %s" % content_type)
        if not found_cl and self._update_cl_check.isSelected():
            new_headers.append("Content-Length: %d" % len(encoded_body))
        header_str = "\r\n".join(new_headers) + "\r\n\r\n"
        if isinstance(encoded_body, str):
            encoded_body = encoded_body.encode("iso-8859-1")
        return header_str.encode("iso-8859-1") + encoded_body
    
    def _getContentType(self, encoding):
        template = str(self._content_type_combo.getSelectedItem())
        charset = self._engine.get_charset_name(encoding)
        return template.replace("{encoding}", charset)
    
    def _doEncode(self):
        encoding = str(self._encoding_combo.getSelectedItem())
        body = self._body_area.getText()
        if not body:
            self._syncBody()
            body = self._body_area.getText()
            if not body:
                JOptionPane.showMessageDialog(self, "Request body is empty")
                return
        try:
            encoded_body = self._engine.encode(body, encoding)
            content_type = self._getContentType(encoding)
            raw_request = self._request_area.getText()
            full_request = self._buildRequest(raw_request, encoded_body, content_type)
            output = "=== Encoded Request (%s) ===\n\n" % encoding
            try:
                output += full_request.decode("iso-8859-1")
            except:
                output += "Hex: " + full_request.encode("hex")
            output += "\n\n=== Body Hex ===\n"
            if isinstance(encoded_body, str):
                output += encoded_body.encode("hex")
            else:
                output += str(encoded_body).encode("hex")
            self._output_area.setText(output)
            self._log("[+] Encoded with %s, length: %d bytes" % (encoding, len(full_request)))
        except Exception as e:
            self._log("[-] Encoding failed: %s" % str(e))
            JOptionPane.showMessageDialog(self, "Encoding failed: %s" % str(e))
    
    def _doFuzzAll(self):
        raw_request = self._request_area.getText()
        if not raw_request:
            JOptionPane.showMessageDialog(self, "Please enter a valid HTTP request")
            return
        body = self._extractBody(raw_request)
        if not body:
            JOptionPane.showMessageDialog(self, "Request body is empty")
            return
        self._body_area.setText(body)
        self._parseRequest()
        self._log("[*] Starting Fuzz All...")
        self._table_model.setRowCount(0)
        self._fuzz_results = {}
        class FuzzRunner(Runnable):
            def __init__(self, panel, raw_request, body):
                self._panel = panel
                self._raw_request = raw_request
                self._body = body
            def run(self):
                for i, (encoding, enc_type) in enumerate(ENCODINGS, 1):
                    try:
                        encoded_body = self._panel._engine.encode(self._body, encoding)
                        content_type = self._panel._getContentType(encoding)
                        full_request = self._panel._buildRequest(
                            self._raw_request, encoded_body, content_type
                        )
                        result = FuzzResult(encoding, enc_type, content_type, full_request)
                        self._panel._fuzz_results[i] = result
                        def createTableUpdater(idx, enc, ct, reqlen):
                            def updateTable():
                                self._panel._table_model.addRow([
                                    idx, enc, ct, "-", reqlen, "-", "Ready"
                                ])
                            return updateTable
                        SwingUtilities.invokeLater(createTableUpdater(i, encoding, content_type, len(full_request)))
                        self._panel._log("[+] #%d %s - %d bytes" % (i, encoding, len(full_request)))
                    except Exception as e:
                        self._panel._log("[-] %s failed: %s" % (encoding, str(e)))
                self._panel._log("[*] Fuzz requests generated: %d" % len(self._panel._fuzz_results))
        Thread(FuzzRunner(self, raw_request, body)).start()
    
    def _doSendSelected(self):
        row = self._result_table.getSelectedRow()
        if row < 0:
            JOptionPane.showMessageDialog(self, "Please select a row first")
            return
        host = self._host_field.getText().strip()
        if not host:
            JOptionPane.showMessageDialog(self, "Please enter target host")
            return
        index = int(self._table_model.getValueAt(row, 0))
        result = self._fuzz_results.get(index)
        if result:
            class SendRunner(Runnable):
                def __init__(self, panel, index, result, row):
                    self._panel = panel
                    self._index = index
                    self._result = result
                    self._row = row
                def run(self):
                    self._panel._sendFuzzRequest(self._index, self._result, self._row)
            Thread(SendRunner(self, index, result, row)).start()
    
    def _doSendAllFuzz(self):
        if not self._fuzz_results:
            JOptionPane.showMessageDialog(self, "Please click 'Fuzz All' first")
            return
        host = self._host_field.getText().strip()
        if not host:
            JOptionPane.showMessageDialog(self, "Please enter target host")
            return
        self._log("[*] Sending all Fuzz requests...")
        class SendAllRunner(Runnable):
            def __init__(self, panel):
                self._panel = panel
            def run(self):
                for i in range(self._panel._table_model.getRowCount()):
                    index = int(self._panel._table_model.getValueAt(i, 0))
                    result = self._panel._fuzz_results.get(index)
                    if result:
                        self._panel._sendFuzzRequest(index, result, i)
                        try:
                            Thread.sleep(100)
                        except:
                            pass
                self._panel._log("[*] All Fuzz requests sent")
        Thread(SendAllRunner(self)).start()
    
    def _sendFuzzRequest(self, index, result, row):
        try:
            host = self._host_field.getText().strip()
            port = int(self._port_field.getText().strip())
            use_https = self._https_check.isSelected()
            self._log("[*] Sending Fuzz #%d (%s)..." % (index, result.encoding))
            import java.lang.System as System
            start_time = System.currentTimeMillis()
            response = self._callbacks.makeHttpRequest(host, port, use_https, result.encoded_request)
            end_time = System.currentTimeMillis()
            result.response_time = end_time - start_time
            result.response = response
            if response and len(response) > 0:
                response_info = self._helpers.analyzeResponse(response)
                result.status_code = response_info.getStatusCode()
                result.response_length = len(response)
                result.note = "Done"
                self._log("[+] Fuzz #%d - Status: %d, Length: %d, Time: %dms" % (
                    index, result.status_code, result.response_length, result.response_time
                ))
            else:
                result.note = "No Response"
                self._log("[-] Fuzz #%d - No response" % index)
            def createRowUpdater(r, sc, rl, rt, note):
                def updateRow():
                    status = sc if sc > 0 else "-"
                    self._table_model.setValueAt(status, r, 3)
                    self._table_model.setValueAt(rl, r, 4)
                    self._table_model.setValueAt(rt, r, 5)
                    self._table_model.setValueAt(note, r, 6)
                return updateRow
            SwingUtilities.invokeLater(createRowUpdater(
                row, result.status_code, result.response_length, result.response_time, result.note
            ))
        except Exception as e:
            result.note = "Error: %s" % str(e)
            self._log("[-] Fuzz #%d failed: %s" % (index, str(e)))
            def updateError():
                self._table_model.setValueAt("Error", row, 6)
            SwingUtilities.invokeLater(updateError)
    
    def _onResultSelected(self, event):
        if event.getValueIsAdjusting():
            return
        row = self._result_table.getSelectedRow()
        if row < 0:
            return
        index = int(self._table_model.getValueAt(row, 0))
        result = self._fuzz_results.get(index)
        if result:
            detail = "=== Fuzz #%d - %s ===\n\n" % (index, result.encoding)
            detail += "Content-Type: %s\n" % result.content_type
            detail += "Request Length: %d bytes\n" % len(result.encoded_request)
            if result.status_code > 0:
                detail += "Status Code: %d\n" % result.status_code
                detail += "Response Length: %d bytes\n" % result.response_length
                detail += "Response Time: %d ms\n" % result.response_time
            detail += "\n=== Request Content ===\n\n"
            try:
                request_str = "".join([chr(b & 0xff) for b in result.encoded_request])
                detail += request_str
            except:
                detail += "Hex: " + str(result.encoded_request).encode("hex")
            if result.response and len(result.response) > 0:
                detail += "\n\n=== Response Content (%d bytes) ===\n\n" % len(result.response)
                try:
                    response_str = "".join([chr(b & 0xff) for b in result.response])
                    detail += response_str
                except:
                    detail += "Unable to display response"
            self._detail_area.setText(detail)
            self._detail_area.setCaretPosition(0)
    
    def _doClear(self):
        self._request_area.setText("")
        self._body_area.setText("")
        self._output_area.setText("")
        self._detail_area.setText("")
        self._table_model.setRowCount(0)
        self._fuzz_results = {}
        self._log_area.setText("")
    
    def _clearResults(self):
        self._table_model.setRowCount(0)
        self._fuzz_results = {}
        self._detail_area.setText("")
    
    def _copyOutput(self):
        self._output_area.selectAll()
        self._output_area.copy()
    
    def createContextMenu(self, invocation):
        menu_items = ArrayList()
        messages = invocation.getSelectedMessages()
        if not messages or len(messages) == 0:
            return menu_items
        main_menu = JMenu("WAF Bypass Encoder")
        send_item = JMenuItem("Send Full Request to Panel")
        class SendToPanel(ActionListener):
            def __init__(self, panel, messages):
                self._panel = panel
                self._messages = messages
            def actionPerformed(self, event):
                request = self._messages[0].getRequest()
                http_service = self._messages[0].getHttpService()
                if request:
                    self._panel._current_request = request
                    self._panel._current_http_service = http_service
                    if http_service:
                        self._panel._host_field.setText(http_service.getHost())
                        self._panel._port_field.setText(str(http_service.getPort()))
                        self._panel._https_check.setSelected(
                            http_service.getProtocol().lower() == "https"
                        )
                    request_str = "".join([chr(b & 0xff) for b in request])
                    self._panel._request_area.setText(request_str)
                    self._panel._body_area.setText("")
                    self._panel._output_area.setText("")
                    self._panel._log("[+] Received full request, length: %d bytes" % len(request))
        send_item.addActionListener(SendToPanel(self, messages))
        main_menu.add(send_item)
        menu_items.add(main_menu)
        return menu_items
