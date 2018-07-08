#!/user/bin python3
# -*- coding:utf-8 -*-
import threading
import socket
import queue
import re
import ipaddress

from prettytable import PrettyTable
from tkinter import *
import tkinter.messagebox as messagebox

lock = threading.Lock()


def GetQueue(host, port_start, port_end):
    PortQueue = queue.Queue()
    for port in range(int(port_start), int(port_end)+1):
        PortQueue.put((host, port))
    return PortQueue


class ScanThread(threading.Thread):
    def __init__(self, SingleQueue, outip):
        threading.Thread.__init__(self)
        self.setDaemon(True)  # 设置后台运行，让join结束
        self.SingleQueue = SingleQueue
        self.outip = outip

    def get_port_service(self, text):
        service_path = "nmap-services"
        # https://svn.nmap.org/nmap/nmap-services
        # 删掉了前面的注释部分
        port_server = str(text)+"/tcp"
        with open(service_path, "r") as server:
            for finger in server.readlines():
                port = finger.strip().split()[1]
                # 查表，获取信息
                if port == port_server:
                    fingers = str(finger.strip().split()[0]).strip()
                    try:
                        info = str(finger.strip().split('#')[1])
                    except:
                        info = ""
                    return (port_server, fingers, info)
            return (port_server, "unknown", "")

    def Ping(self, scanIP, Port):
        global OpenPort, lock
        # 创建socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        address = (scanIP, Port)
        # TCP连接检测
        try:
            sock.connect(address)
        except:
            sock.close()
            return False
        sock.close()
        if lock.acquire():
            # 获取端口信息
            self.outip.put(self.get_port_service(Port))
            lock.release()
        return True

    def run(self):
        while not self.SingleQueue.empty():
            # 获取扫描队列，并扫描
            host, port = self.SingleQueue.get()
            self.Ping(host, port)


class Work(object):
    def __init__(self, scan_target="", scan_port_start="", scan_port_end="", back_fn=None):
        self.target = scan_target
        self.port_start = scan_port_start
        self.port_end = scan_port_end
        self.back_fn = back_fn
        self.result = []

    def run(self):
        ThreadList = []
        # 扫描队列
        SingleQueue = GetQueue(self.target, self.port_start, self.port_end)
        # 存储结果队列
        resultQueue = queue.Queue()
        # 启动200线程并发
        for i in range(0, 200):
            t = ScanThread(SingleQueue, resultQueue)
            ThreadList.append(t)
        for t in ThreadList:
            t.start()
        for t in ThreadList:
            # join等待结束后台线程
            t.join(0.1)
        data = []
        while not resultQueue.empty():
            line = resultQueue.get()
            data.append(
                {"Port": str(line[0]), "Services": str(line[1]), "Info": str(line[2])})
        self.back_fn(data)


class Application(Frame):
    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.pack()
        self.createWidgets()


    def createWidgets(self):
        # 目标填写
        self.IpLabel = Label(self, text='Target')
        self.IpLabel.pack(side=LEFT)

        self.IpInput = Entry(self)
        self.IpInput.pack(side=LEFT)
        # 端口填写
        self.PortLabel = Label(self, text='Port')
        self.PortLabel.pack(side=LEFT)

        self.StartPortInput = Entry(self, width=5)
        self.StartPortInput.pack(side=LEFT)

        self.Label1 = Label(self, text='-')
        self.Label1.pack(side=LEFT)

        self.EndPortInput = Entry(self, width=5)
        self.EndPortInput.pack(side=LEFT)
        # 扫描按钮
        self.ScanButton = Button(self, text='Scan', command=self.scan)
        self.ScanButton.pack(side=LEFT)
        # 显示框及XY滚动条
        self.Result = Text(wrap = 'none')
        self.ResultScrollbarX = Scrollbar(orient = HORIZONTAL)
        self.ResultScrollbarY=Scrollbar()

        self.ResultScrollbarX.config(command=self.Result.xview)
        self.ResultScrollbarY.config(command=self.Result.yview)
        self.Result.config(xscrollcommand=self.ResultScrollbarX.set,yscrollcommand=self.ResultScrollbarY.set)
        self.ResultScrollbarY.pack(fill=Y,side=RIGHT)
        self.ResultScrollbarX.pack(fill=X,side=BOTTOM)
        self.Result.pack(fill=BOTH,expand="yes")

    def scan(self):
        ip = self.IpInput.get() or ""
        port_start = self.StartPortInput.get() or ""
        port_end = self.EndPortInput.get() or ""
        ipflag=False
        realip=[]
        try:
            # 域名正则
            if(re.match(r"\b([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\b",str(ip))):
                try:
                    # 域名解析
                    realip.append(socket.gethostbyname(ip))
                    ipflag=True
                except:
                    messagebox.showinfo('ERROR','域名解析失败')
                    return
            elif(ip):
                # IP(CIDR)解析
                try:
                    realip=ipaddress.ip_network(ip)
                    ipflag=True
                except:
                    pass
            # 判断目标是否正确
            if(ipflag):
                # 判断端口范围
                if(1 <= int(port_start) <= int(port_end) <= 65535):
                    # 创建扫描任务
                    for target in realip:
                        self.Result.insert(END, str(target)+"\n")
                        # 执行任务并调用show函数显示结果
                        t = Work(scan_target=str(target), scan_port_start=str(port_start),
                                scan_port_end=str(port_end), back_fn=self.show)
                        t.run()
                else:
                    messagebox.showinfo('ERROR','端口范围有误')
            else:
                messagebox.showinfo('ERROR','输入地址有误')
        except:
            messagebox.showinfo('ERROR','输入信息有误')

    def show(self, data):
        # 将结果美化输出
        if(data):
            # 表头
            result_table = PrettyTable(["Port", "Services", "Info"])
            # Info 列左对齐
            result_table.align["Info"]='l'
            # 插入数据
            for i in data:
                result_table.add_row([i["Port"], i["Services"], i["Info"]])
            self.Result.insert(END, str(result_table)+"\n")
        else:
            self.Result.insert(END, "No port open or offline.\n")


app = Application()
app.master.title('多线程端口扫描器-GUI')
app.mainloop()
